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
import re
import binascii

from laikaboss.si_module import SI_MODULE
from laikaboss.objectmodel import ModuleObject, ExternalVars
import laikaboss.util

class EXPLODE_RE_SUB(SI_MODULE):
    '''
    module around re.sub
    '''
    def __init__(self,):
        self.module_name = "EXPLODE_RE_SUB"
        self.re_pattern = None

    def _run(self, scanObject, result, depth, args):
        moduleResult = [] 

        buffer = scanObject.buffer
                
        pattern = laikaboss.util.get_option(args, 'pattern', 'resub_pattern', "uhm").encode('utf-8')
        replacement = laikaboss.util.get_option(args, 'replacement', 'resub_resplacement', "").encode('utf-8')

        pattern_hex = laikaboss.util.get_option(args, 'pattern_hex', 'resub_pattern_hex', "")
        if pattern_hex:
            pattern = binascii.unhexlify(pattern_hex)
        replacement_hex = laikaboss.util.get_option(args, 'replacement_hex', 'resub_replacement_hex', "")
        if replacement_hex:
            replacement = binascii.unhexlify(replacement_hex)
        
        name = laikaboss.util.get_option(args, 'name', 'resub_name', "resub")

        if not self.re_pattern:
            self.re_pattern = re.compile(pattern)


        newdata = self.re_pattern.sub(replacement, buffer)


        moduleResult.append(ModuleObject(buffer=newdata,externalVars=ExternalVars(filename=scanObject.filename + "_" + name)))
                   
        return moduleResult

