# Copyright 2015 Lockheed Martin Corporation
# Copyright 2020 National Technology & Engineering Solutions of Sandia, LLC 
# (NTESS). Under the terms of Contract DE-NA0003525 with NTESS, the U.S. 
# Government retains certain rights in this software.
# 
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
import olefile
from laikaboss.objectmodel import ModuleObject, ExternalVars, QuitScanException, \
                                GlobalScanTimeoutError, GlobalModuleTimeoutError
from laikaboss.util import log_module
from laikaboss.si_module import SI_MODULE

class EXTRACT_OLE(SI_MODULE):
    def __init__(self,):
        self.module_name = "EXTRACT_OLE" 

    def _run(self, scanObject, result, depth, args):
        moduleResult = []
        
        try:
            buf = scanObject.buffer
            
            loc = buf.find(b"\xD0\xCF\x11\xE0")
            if not loc:
                scanObject.addFlag("extract_ole:OLE_MAGIC_NOT_FOUND")
            else:
                scanObject.addMetadata(self.module_name, "ole_location", loc)
                ole_obj = buf[loc:]
                moduleResult.append(ModuleObject(buffer=ole_obj, externalVars=ExternalVars(filename='extracted_ole')))
                
        except:
            scanObject.addFlag("extract_ole:ERROR_THROWN")
            pass
                
        return moduleResult
