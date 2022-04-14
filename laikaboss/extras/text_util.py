# Copyright 2020 National Technology & Engineering Solutions of Sandia, LLC 
# (NTESS). Under the terms of Contract DE-NA0003525 with NTESS, the U.S. 
# Government retains certain rights in this software.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""
File for text manipulation utilities
"""

from builtins import str
import random
import string
import hashlib
import logging
import syslog
import time
import os
import re
from laikaboss.objectmodel import QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError
from laikaboss import config

# Third-party library imports
try:
    from bs4 import BeautifulSoup, Comment, UnicodeDammit
    has_beautifulsoup = True
except:
    has_beautifulsoup = False

"""
Uses BeautifulSoup to convert HTML to formatted plaintext.
:param html: UTF-8 HTML data
:return: UTF-8 plain text, empty string if not HTML or error
"""
def html_to_text(html):
    text = ""
    # Can't convert without the library
    if not has_beautifulsoup:
        logging.error("BeautifulSoup4 is not installed, unable to convert HTML to plain text")
        return ("", "")

    try:
        soup_object = BeautifulSoup(html, "html.parser")
    except:
        logging.error("BeautifulSoup4 could not parse HTML, no plain text will be extracted")
        return ("", "")

    #deleting all comments
    comments = soup_object.findAll(text=lambda text:isinstance(text, Comment))
    for comment in comments:
        comment.extract()
            
    text = soup_object.get_text('\n')
    original_encoding = str(soup_object.original_encoding)
    
    # remove non-ascii characters, otherwise hashing might give an error
    #text = re.sub(r'[^\x00-\x7F]+',' ', text)

    return (original_encoding, text)

def convert_to_unicode(unknown_text):

    # Check to see if it's already unicode
    if isinstance(unknown_text, str):
        return unknown_text

    # Odd but going to support it
    if not isinstance(unknown_text, bytes):
        try:
            unknown_text = str(unknown_text)
        except UnicodeEncodeError:
            logging.warning("Could not convert to str: %s" % (type(unknown_text)))
            raise

    # Empty text happens a lot
    if (len(unknown_text) == 0):
        return u''

    # Use BeautifulSoup to try to encode it
    unicode_text = UnicodeDammit(unknown_text).unicode_markup
    if (not unicode_text):
        logging.warning("Warning: Unicode encoding error, punting...")
        logging.warning("Warning: Unknown text:" + unknown_text)
        return str("Unicode_encoding_error")

    # Assuming success
    return unicode_text
