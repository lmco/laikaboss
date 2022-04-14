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
'''
Sandia National Labs
'''


# Import the python libraries needed for your module
import re

# Import classes and helpers from the Laika framework
from laikaboss.util import get_option
from laikaboss.si_module import SI_MODULE

RELS_REGEX = b'<Relationship[^>]{0,1024}?Type="[^"]{0,1024}?relationships\/?([^"]{0,100}?)"[^>]{0,1024}?Target="([^"]{0,4096}?)"'

class META_OOXML_RELS(SI_MODULE):
    ''' 
    Extracts relationship relationships

    dispatch on the .rels XML files that contain <Relationship
    '''

    def __init__(self):
        self.module_name = "META_OOXML_RELS"
        self.rels_regex = None

    def _run(self, scanObject, result, depth, args):
        
        #lazily compile regexes
        if not self.rels_regex:
            self.rels_regex = re.compile(RELS_REGEX)
       
        limit = int(get_option(args, 'limit', 'ooxmlrelslimit', 100))
 
        rels = []

        for match in self.rels_regex.finditer(scanObject.buffer, re.S):
            rels.append({ "type": match.group(1), "target": match.group(2)})
 
        if rels:
            scanObject.addMetadata(self.module_name, "relationships", rels[:limit])
#            scanObject.addFlag("ooxml:rels")
        return []

