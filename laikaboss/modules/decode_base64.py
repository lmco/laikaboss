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
            moduleResult.append(ModuleObject(buffer=decoded, externalVars=ExternalVars(filename="d_base64_%s" % len(decoded))))
            return moduleResult
        except:
            raise
