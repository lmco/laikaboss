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
import hashlib

class META_HASH(SI_MODULE):
    def __init__(self,):
        self.module_name = "META_HASH"
        self.sane_defaults = set(["md5", #md5.hexdigest
                                  "SHA256",#sha256.hexdigest
                                  #"ssdeep", #ssdeep is not a standard package
                                  #"SHA512",#sha512.hexdigest (not sane?)
                                  "32SHA512",#first 32 bytes of sha512.
                                ])

    def _run(self, scanObject, result, depth, args):
        '''
        Assumes:
            there is a string like object in scanObject.buffer
        Ensures:
            hash values added using scanObject.addMetadata
        :param scanObject:<laikaboss.objectmodel.ScanObject>
        :param result:<laikaboss.objectmodel.ScanResult>
        :param depth:<int>
        :param args:<dict> --execution flow controls--
        :return: Always returns a empty list (no child objects)
        '''
        moduleResult = [] 
        metaDict = {}
        if not len(args):
            args = self.sane_defaults #overwriting a dict with set, bad idea?

        if "md5" in args:
            metaDict['md5'] = hashlib.md5(scanObject.buffer).hexdigest()
        if "SHA1" in args:
            metaDict['SHA1'] = hashlib.sha1(scanObject.buffer).hexdigest()
        if "SHA256" in args:
            metaDict['SHA256'] = hashlib.sha256(scanObject.buffer).hexdigest()
        if "SHA512" in args or "32SHA512" in args:
            #computing this once is worth the extra if + string storage??
            sha512_value = hashlib.sha512(scanObject.buffer).hexdigest()
            if "SHA512" in args:
                metaDict['SHA512'] = sha512_value
            if "32SHA512" in args:
                metaDict['32SHA512'] = sha512_value[:32]
        if "ssdeep" in args:
            #only import ssdeep if dispatched.
            #Prevents import error if you don't have/want the package
            import ssdeep
            metaDict['ssdeep'] = ssdeep.hash(scanObject.buffer)


        scanObject.addMetadata(self.module_name, "HASHES", metaDict)
        
        return moduleResult
