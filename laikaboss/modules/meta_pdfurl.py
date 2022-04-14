# Copyright 2020 National Technology & Engineering Solutions of Sandia, LLC 
# (NTESS). Under the terms of Contract DE-NA0003525 with NTESS, the U.S. 
# Government retains certain rights in this software.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# Import the python libraries needed for your module
import re

# Import classes and helpers from the Laika framework
from laikaboss.util import get_option
from laikaboss.si_module import SI_MODULE

URI_REGEX = b'\/UR[IL]\s{0,20}\((([^\\\\)]|(\\\\[^)])|\\\\\)){0,1024})\)'
URI_REF_REGEX = b'\/UR[IL][ \\n]{1,20}([0-9]{1,6})[ \\n]{1,20}([0-9]{1,6})[ \\n]{1,20}R'
OBJ_REGEX = b'([0-9]{1,6})[ \\n]{1,20}([0-9]{1,6})[ \\n]{1,20}obj[ \\n]{1,20}\((([^\\\\)]|(\\\\[^)])|\\\\\)){0,1024})\)'
URI_VALIDATE_REGEX = b'^[a-zA-Z]{2,100}:.'
WEB_URI_REGEX = b'https?://'


class META_PDFURL(SI_MODULE):
    ''' 
    Extracts unique URLs from PDFs and PDF streams using regular expressions
    
    to analyze children objects, other modules, such as EXPLODE_PDF, must be run prior to execution
    
    arguments:
        limit: max number of unique URLs, default 100
        analyzechildren: process children streams also, default 1
            
    '''

    def __init__(self):
        self.module_name = "META_PDFURL"
        self.uri_regex = None
        self.uri_ref_regex = None
        self.obj_regex = None

    def _run(self, scanObject, result, depth, args):
        
        #lazily compile regexes
        if not self.uri_regex:
            self.uri_regex = re.compile(URI_REGEX)
            self.uri_ref_regex = re.compile(URI_REF_REGEX)
            self.obj_regex = re.compile(OBJ_REGEX)
            self.uri_validate_regex = re.compile(URI_VALIDATE_REGEX)
            self.web_uri_regex = re.compile(WEB_URI_REGEX)
        
        limit = int(get_option(args, 'limit', 'metapdfurllimit', 100))
        analyze_children = int(get_option(args, 'analyzechildren', 'metapdfurlanalyzechildren', 1))

        valid_urls = set()
        invalid_urls = set()
        web_urls = set()
        
        scanObjects = [scanObject]
                
        if analyze_children:
            #add children scanObjects:
            for id in result.files:
                if result.files[id].parent == scanObject.uuid:    
                    scanObjects.append(result.files[id])

        for so in scanObjects:
            #Copy other URIs from EXPLODE_PDF here
            explode_uris = so.getMetadata('EXPLODE_PDF', 'URIs')
            for uri in explode_uris:
                uri = uri.encode('utf-8')
                if self.uri_validate_regex.match(uri):
                    valid_urls.add(uri)
    
            for match in self.uri_regex.finditer(so.buffer, re.S):
                url = match.group(1)
                if self.uri_validate_regex.search(url):
                    valid_urls.add(url)
                else:
                    invalid_urls.add(url)
            
            url_objects = set()
            for match in self.uri_ref_regex.finditer(so.buffer, re.S):
                url_objects.add((match.group(1),match.group(2)))
            if url_objects:
                for match in self.obj_regex.finditer(so.buffer, re.S):
                    id = (match.group(1),match.group(2))
                    if id in url_objects:
                        url = match.group(3)
                        if self.uri_validate_regex.search(url):
                            valid_urls.add(url)
                        else:
                            invalid_urls.add(url)
        
        for url in valid_urls:
            if self.web_uri_regex.match(url):
                web_urls.add(url)
        
        if valid_urls:
            scanObject.addFlag('pdf:url')
            scanObject.addMetadata(self.module_name, "URLs", list(valid_urls)[:limit])
        scanObject.addMetadata(self.module_name, "URL_count", len(valid_urls))

        if web_urls:
            scanObject.addFlag('pdf:url_web')
            scanObject.addMetadata(self.module_name, "URLs_web", list(web_urls)[:limit])
            scanObject.addMetadata(self.module_name, "URL_count_web", len(web_urls))
            
        if invalid_urls:
            scanObject.addFlag('pdf:invalid_url')
            scanObject.addMetadata(self.module_name, "invalid_URL_count", len(invalid_urls))

        return []

