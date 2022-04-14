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

HYPERLINK_REGEX = b'<Relationship[^>]{0,1024}?Type="[^"]{0,1024}?hyperlink"[^>]{0,1024}Target="([^"]{0,4096}?)"'

class META_OOXML_URLS(SI_MODULE):
    ''' 
    Extracts external hyperlink references

    dispatch on the .rels XML files that contain <Relationship tags
    '''

    def __init__(self):
        self.module_name = "META_OOXML_URLS"
        self.hyperlink_regex = None

    def _run(self, scanObject, result, depth, args):
        
        #lazily compile regexes
        if not self.hyperlink_regex:
            self.hyperlink_regex = re.compile(HYPERLINK_REGEX)
       
        limit = int(get_option(args, 'limit', 'ooxmlurllimit', 100))
 
        hyperlinks = set()

        for match in self.hyperlink_regex.finditer(scanObject.buffer, re.S):
            hyperlinks.add(match.group(1))
 
        if hyperlinks:
            scanObject.addMetadata(self.module_name, "urls", list(hyperlinks)[:limit])
            scanObject.addFlag("ooxml:url")
    
        return []

