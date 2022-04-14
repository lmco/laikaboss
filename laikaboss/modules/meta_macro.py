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

ATTRIBUTE_REGEX = b'Attribute\s(VB_Control|VB_Base|VB_Name)\s=\s"(.{0,1024})"'

class META_MACRO(SI_MODULE):
    ''' 
    Extracts a few attributes from Macros
    '''

    def __init__(self):
        self.module_name = "META_MACRO"
        self.attribute_regex = None

    def _run(self, scanObject, result, depth, args):
        
        #lazily compile regexes
        if not self.attribute_regex:
            self.attribute_regex= re.compile(ATTRIBUTE_REGEX)
       
        for match in self.attribute_regex.finditer(scanObject.buffer):
            scanObject.addMetadata(self.module_name, match.group(1), match.group(2).decode("utf-8", errors='replace').encode('utf-8', errors='replace').rstrip())

        return []

