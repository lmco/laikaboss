#!/usr/bin/env python
# Copyright 2020 National Technology & Engineering Solutions of Sandia, LLC 
# (NTESS). Under the terms of Contract DE-NA0003525 with NTESS, the U.S. 
# Government retains certain rights in this software.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""
This module handles HTML. 
"""

# Python library imports
from future import standard_library
standard_library.install_aliases()
from builtins import str
from past.builtins import unicode
import logging
import struct
import re
import sys
import base64
import urllib.request, urllib.parse, urllib.error
import html.entities
from future.backports.html.entities import html5
from laikaboss.util import get_option
from laikaboss.extras.extra_util import str_to_bool

# 3rd-party Python libraries
try:
    from bs4 import BeautifulSoup, Comment, SoupStrainer
    has_beautifulsoup = True
except:
    has_beautifulsoup = False

# LaikaBoss imports
import laikaboss
from laikaboss.si_module import SI_MODULE

_module_requires = ['bs4'] 

class SCAN_HTML(SI_MODULE):

    # create a flag if Javascript is over this percentage of the document
    js_threshold = 0.80 # 80% 

    # a list of tags that could have URLs in the href field
    href_list = ['a', 'area', 'base', 'link']
    # a list of tags that could have URLs in the src fields
    src_list = ['iframe', 'script', 'input', 'frame', 'audio', 'source', 'video', 'v:rect', 'v:roundrect', 'v:fill', 'v:oval','v:image']
    # a list of tags that could have URLs in the action fields
    action_list = ['form']

    def __init__(self):
        self.module_name = "SCAN_HTML"
        #Add html5 entities from python 3 to list of supported entities
        if sys.version_info[0] < 3:
            for html5_entity in html5:
                ent = html5_entity[:-1]
                html.entities.entitydefs[ent] = html5[html5_entity]
                #Multi-character entities don't work with name2codepoint
                if len(html5[html5_entity]) <= 1:
                    cp = ord(html5[html5_entity])
                    html.entities.name2codepoint[ent] = cp
                    html.entities.codepoint2name[cp] = ent

    def _run(self, scanObject, result, depth, args):
        result = []
        minimal_scan = str_to_bool(get_option(args, 'minimalscan', 'htmlminimalscan', 'False'))

        # parse HTML
        try:
            if minimal_scan:
                head_tag_only = SoupStrainer("head")
                html_object = BeautifulSoup(scanObject.buffer, "html.parser", parse_only=head_tag_only)
            else:
                html_object = BeautifulSoup(scanObject.buffer, "html.parser")
            # extract comments separately - sometimes comments have content in them
            # ex. For IE compatibility
            # This content is not parsed unless it is first extracted
            comments = html_object.findAll(text=lambda text:isinstance(text, Comment))
            for comment in comments:
                chtml = BeautifulSoup(comment.extract(), "html.parser")
                for node in chtml.find_all():
                    html_object.insert(3, node)
        except Exception as e:
            logging.exception("Cannot parse HTML")
            return

        # Look for auto-redirects and meta tags
        self._scan_meta(html_object, scanObject)

        # We only look at meta tags if doing a minimal scan
        if not minimal_scan:
            # Extract Javscript
            percent, children = self._extract_js(html_object, len(scanObject.buffer))
            scanObject.addMetadata("SCAN_HTML", "percent_javascript", [percent])
            if percent > self.js_threshold:
                scanObject.addFlag('%s:%s:%d%%' % ('html', "EXCESSIVE_JAVASCRIPT", percent * 100))

            i = 0
            for child in children:
                if isinstance(child, str):
                    child = child.encode('utf-8', 'replace')
                # need to strip file extension, or our HTML dispatch rule will incorrectly match the child
                fname = scanObject.filename.strip('.htm').strip('.html') + "_js_script_%d" % i
                result.append(laikaboss.objectmodel.ModuleObject(buffer=child, 
                    externalVars=laikaboss.objectmodel.ExternalVars(filename=fname, contentType="javascript")))
                i += 1

            # Look for objects
            self._scan_objects(html_object, scanObject)

            # Look for img tags and data associated with img tags
            self._scan_img(html_object, scanObject)

            # extract all non-image links
            self._get_links(html_object, scanObject)

            # Look for data
            children = self._scan_data(html_object, scanObject)

            for child in children:
                result.append(child)

            #look for phishing forms and post actions
            self._scan_form(html_object, scanObject)

        return result

    
    """
    Extract all Javascript pieces so they can be sent to the Yara module for signature matching.
    :param html_object: BeautifulSoup HTML parsing of the page
    :param total_len: Total length (in bytes) of the document
    :return: A tuple with: % of the document that is Javascript, an array of Javascript strings
    """
    @staticmethod
    def _extract_js(html_object, total_len):
        children = []
        percent = 0

        scripts = html_object.findAll("script")
        if len(scripts) == 0:
            return percent, children

        # extract the scripts - note this will extract all kinds, not just Javascript
        js_content = ""
        for script in scripts:
            try:
                ss = script.text
            except Exception as e:
                logging.error("Unable to extract Javascript: %s" % e)
                ss = str(script)
            children.append(ss)
            js_content += ss + " "

        # calculate the percentage of the document that is javascript
        percent = float(len(js_content) / float(total_len))

        return percent, children


    """
    Looks for embed tags and object tags within the page. Adds a flag if they are found.
    :param html_object: BeautifulSoup HTML object 
    :param scanObject: LaikaBoss scanObject to add the flags to
    :return: None
    """
    @staticmethod
    def _scan_objects(html_object, scanObject):
        embeds = html_object.findAll("embed")
        objects = html_object.findAll("object")

        has_embed = False
        for embed in embeds:
            embed_src = embed.get("src", default= None)
            if embed_src is None: 
                continue
            has_embed = True
            scanObject.addMetadata("SCAN_HTML", "embed_tag_src", [embed_src])
        if has_embed:
            scanObject.addFlag('%s:%s' % ('html', "EMBED_TAG_PRESENT"))

        has_object = False
        for _object in objects:
            object_src = _object.get("src", default= None)
            if object_src is None: 
                continue
            has_object = True
            scanObject.addMetadata("SCAN_HTML", "object_tag_src", [object_src])
        if has_object:
            scanObject.addFlag('%s:%s' % ('html', "OBJECT_TAG_PRESENT"))

    """
    Looks for objects with a 'data' field and flags them.
    https://css-tricks.com/data-uris/
    :param html_object: BeautifulSoup HTML object 
    :param scanObject: LaikaBoss scanObject to add the flags to
    :return: a list of data objects to add as children
    """
    @staticmethod
    def _scan_data(html_object, scanObject):
        children  = []

        data_objects = []
        candidate_urls = scanObject.getMetadata("SCAN_HTML", "html_links")
        data_objects.extend([url for url in candidate_urls if re.match("^data\:", url)])
        candidate_urls = [tag["src"] for tag in scanObject.getMetadata("SCAN_HTML", "HTML_IMG_TAG") if "src" in tag]
        data_objects.extend([url for url in candidate_urls if re.match("^data\:", url)])

        data_num = 0
        for content in data_objects:
            is_base64 = False
            if isinstance(content, unicode):
                content = unicode(content).encode('utf-8', 'replace')
            data_num += 1
            middle_idx = content.find(b",")
            media_types = content[5:middle_idx].split(b';') #Cut off beginning "data:" tag
            for mt in media_types:
                if not mt == b'base64':
                    try:
                        major_type = mt.split(b'/')[0].decode('utf-8')
                        scanObject.addFlag('%s:%s:%s' % ('html', "DATA_URI_PRESENT", major_type.upper()))
                    except:
                        scanObject.addFlag('%s:%s' % ('html', "DATA_URI_PRESENT"))
                else:
                    is_base64 = True

            data = content[middle_idx+1:].replace(b"\n", b"").replace(b" ", b"")
            data = urllib.parse.unquote_to_bytes(data) #Can be url encoded
            if is_base64:
                data = base64.b64decode(data)
                media_types.remove(b'base64')

            # make a threshold for data object size?
            scanObject.addMetadata("SCAN_HTML", "child_data_object_size", [len(data)])
            obj = laikaboss.objectmodel.ModuleObject(buffer=data, externalVars=laikaboss.objectmodel.ExternalVars(
                    filename=scanObject.filename + "_data_object_" + str(data_num), contentType=media_types))

            children.append(obj)

        return children


    """
    Checks for suspicious meta tags in HTML, specifically auto redirects. Adds a flag for each one found.
    :param html_object: BeautifulSoup HTML object 
    :param scanObject: LaikaBoss scanObject to add the flags to
    :return: None
    """
    @staticmethod
    def _scan_meta(html_object, scanObject):
        metas = html_object.findAll("meta")
        titles = html_object.findAll("title")
        
        for title in titles:
            scanObject.addMetadata("SCAN_HTML", "title", title.text)

        for meta in metas:
            # "charset" is a special attribute that defines the page's character set
            if meta.has_attr("charset"):
                scanObject.addMetadata("SCAN_HTML", "charset", meta.get("charset"))
            # Metadata equivalent to http headers
            elif meta.has_attr("http-equiv"):
                if meta.get("http-equiv").lower() in ["content-language", "content-security-policy", "content-type"]:
                    scanObject.addMetadata("SCAN_HTML", meta.get("http-equiv"), meta.get("content"))
                if meta.get("http-equiv").lower() == "refresh":  
                    url_data = meta.get("content", "unknown")
                    # this would be better served by the matchall function available in Python 3
                    if len(re.match("\d+", url_data).group()) == len(url_data):
                        scanObject.addFlag('%s:%s' % ('html', "AUTO_REFRESH"))
                        scanObject.addMetadata("SCAN_HTML", "refresh_time", [url_data])
                    else:
                        scanObject.addFlag('%s:%s' % ('html', "AUTO_REDIRECT"))
                        if 'url' in url_data or 'URL' in url_data:
                            url_parsed = re.match("(\d+);(?:\s+)?(?:url|URL)=[\'\"]?([^\'\"\s]+)[\'\"]?", url_data)
                            scanObject.addMetadata("SCAN_HTML", "refresh_time", url_parsed.group(1))
                            scanObject.addMetadata("SCAN_HTML", "redirect_url", url_parsed.group(2))
                        else:
                            scanObject.addMetadata("SCAN_HTML", "redirect_url", [url_data])
            elif meta.has_attr("name") and meta.has_attr("content"):
                scanObject.addMetadata("SCAN_HTML", meta.get("name"), meta.get("content"))

    """
    Finds <img> tags in html and looks for the URL, height, width, and border properties.
    This is useful for discerning web bugs (used for privacy tracking)
    :param html_object: BeautifulSoup HTML object
    :param scanObject: LaikaBOSS scanObject to add flags/metadata to
    :return: None
    """
    @staticmethod
    def _scan_img(html_object, scanObject):
        imgs = html_object.findAll("img")
        small_width_and_height = False
        if len(imgs) == 0:
            return

        img_metadata = []
        for img in imgs:
            d = {}
            try:
                if img.has_attr('src'):
                    d['src'] = img.get("src")
                    if isinstance(d['src'], str):
                        d['src'] = d['src'].encode('utf-8')
                if img.has_attr("height"):
                    try:
                        d['height'] = int(img.get('height'))
                    except:
                        try:
                            d['height'] = img.get('height')
                            if isinstance(d['height'], str):
                                d['height'] = d['height'].encode('utf-8')
                        except:
                            pass
                if img.has_attr('width'):
                    try:
                        d['width'] = int(img.get('width'))
                    except:
                        try:
                            d['width'] = img.get('width')
                            if isinstance(type(d['width']), str):
                                d['width'] = d['width'].encode('utf-8')
                        except:
                            pass
                if img.has_attr('border'):
                    d['border'] = int(img.get('border'))
                img_metadata.append(d)
                if 'height' in d and 'width' in d:
                    if type(d['height']) is int and type(d['width']) is int:
                        if d['height'] <= 1 and d['width'] <= 1:
                            small_width_and_height = True
            except:
                # Error during parsing
                # Ignore this tag for now, fire flag.
                scanObject.addFlag('%s:%s' % ('html', 'ERROR_PARSING_IMG_TAG'))
        scanObject.addMetadata('SCAN_HTML', 'HTML_IMG_TAG_COUNT', len(imgs))
        scanObject.addMetadata('SCAN_HTML', 'HTML_IMG_TAG', img_metadata)
        if small_width_and_height:
            scanObject.addFlag('%s:%s' % ('html', 'WEB_BUG'))

    """
    Looks for form actions and anything with a user/password field
    :param html_object: BeautifulSoup HTML object
    :param scanObject: LaikaBOSS scanObject to add flags/metadata to
    :return: None
    """
    @staticmethod
    def _scan_form(html, scanObject):
        flag = False
        for obj in html.find_all('form'):
            inputs = 0
            has_password = False
            children = obj.findChildren()
            for child in children:
                if child.name == 'input':
                    inputs += 1
                    child_type = child.get('type')
                    if child_type == 'password':
                        has_password = True
            # does the form have a password-type field?
            # is it a short form?
            if (inputs > 0 and inputs < 4) and has_password:
                flag = True 

        if flag:
            scanObject.addFlag('%s:%s' % ('html', "HTML_WITH_PASSWORD_FORM"))

        for tag in SCAN_HTML.action_list:
            for obj in html.find_all(tag):
                if obj.has_attr('action'):
                    url = obj.get('action').encode('utf-8', 'ignore')
                    scanObject.addMetadata("SCAN_HTML", "form_action_urls", [url])

    """
    Looks for form actions and anything with a user/password field
    :param html_object: BeautifulSoup HTML object
    :param scanObject: LaikaBOSS scanObject to add flags/metadata to
    :return: None
    """
    @staticmethod
    def _get_links(html, scanObject):
        links = []
        # find all href attributes
        for tag in SCAN_HTML.href_list:
            for link in html.find_all(tag):
                if link.has_attr('href'):
                    url = link.get('href').encode('utf-8', 'ignore')
                    links.append(url)

        # find all src attributes
        for tag in SCAN_HTML.src_list:
            for obj in html.find_all(tag):
                if obj.has_attr('src'):
                    url = obj.get('src').encode('utf-8', 'ignore')
                    links.append(url)

        links = list(set(links))
        scanObject.addMetadata("SCAN_HTML", "html_links", links)
