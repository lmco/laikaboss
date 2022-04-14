# Copyright 2015 Lockheed Martin Corporation
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
import base64
from laikaboss.objectmodel import ModuleObject, ExternalVars
from laikaboss.si_module import SI_MODULE

class DECODE_BASE64(SI_MODULE):
    def __init__(self,):
        self.module_name = "DECODE_BASE64"
    def _run(self, scanObject, result, depth, args):
        moduleResult = [] 
        try:
            decoded = base64.b64decode(scanObject.buffer)
            contentType = scanObject.contentType if "base64" not in scanObject.contentType else ""
            moduleResult.append(ModuleObject(buffer=decoded, 
                    externalVars=ExternalVars(filename="d_base64_%s" % len(decoded),
                    contentType=contentType, charset=scanObject.charset)))
            return moduleResult
        except:
            raise
