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
from laikaboss.si_module import SI_MODULE
import ssdeep
import hashlib

class META_HASH(SI_MODULE):
    def __init__(self,):
        self.module_name = "META_HASH"
    def _run(self, scanObject, result, depth, args):
        moduleResult = [] 
        metaDict = {}
        metaDict['md5']    = hashlib.md5(scanObject.buffer).hexdigest()
        metaDict['SHA1']   = hashlib.sha1(scanObject.buffer).hexdigest()
        #metaDict['SHA224'] = hashlib.sha224(scanObject.buffer).hexdigest()
        metaDict['SHA256'] = hashlib.sha256(scanObject.buffer).hexdigest()
        #metaDict['SHA384'] = hashlib.sha384(scanObject.buffer).hexdigest()
        metaDict['SHA512'] = hashlib.sha512(scanObject.buffer).hexdigest()
        metaDict['ssdeep'] = ssdeep.hash(scanObject.buffer)
        
        scanObject.addMetadata(self.module_name, "HASHES", metaDict)
        
        return moduleResult
