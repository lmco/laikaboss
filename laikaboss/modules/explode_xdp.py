# Copyright 2015 Lockheed Martin Corporation
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
import logging
from xml.dom.minidom import parseString
from laikaboss.objectmodel import *
from laikaboss.si_module import SI_MODULE

class EXPLODE_XDP(SI_MODULE):
    def __init__(self,):
        self.module_name = "EXPLODE_XDP"
    def _run(self, scanObject, result, depth, args):
        moduleResult = [] 
        try:
            # See if any element names were passed in, if not use the default of "chunk"
            if 'element_names' in args:
                 element_names = args['element_names'].split(';')
            else:
                 element_names = ['chunk']
            # Parse the xml
            dom1 = parseString(scanObject.buffer)
            for element_name in element_names:
                logging.debug("EXPLODE_XDP: trying %s element name" % element_name)
                chunks = dom1.getElementsByTagName(element_name)
                # Just in case there happen to be more than 1 element with the name chunk..
                for chunk in chunks:
                    b64pdf = chunk.firstChild.nodeValue
                    # Get rid of newlines
                    b64pdf = b64pdf.rstrip()
                    moduleResult.append(ModuleObject(buffer=b64pdf, externalVars=ExternalVars(filename='e_xdp_%s' % element_name, contentType="base64")))
            return moduleResult
        except:
            raise
