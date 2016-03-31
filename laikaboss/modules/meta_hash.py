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
from laikaboss.util import get_option
import hashlib

class META_HASH(SI_MODULE):
    def __init__(self,):
        self.module_name = "META_HASH"
        #defaults are a set.
        # Existance in this set means run the function
        # Absense from the set means skip the function
        # prevents need to update default with all possible hash functions.
        # could set and forget this value while adding additional functions in _run
        self.module_defaults = set(["md5", #md5.hexdigest
                                    "SHA1", #sha1.hexdigest
                                    "SHA256",#sha256.hexdigest
                                    "ssdeep", #ssdeep is not a standard package
                                    "SHA512",#sha512.hexdigest
                                   ])

    def _run(self, scanObject, result, depth, args):
        '''
        Assumes:
            there is a string like object in scanObject.buffer
        Ensures:
            hash values added using scanObject.addMetadata

        Laika Config File Options:
            hashmd5:    "1" = md5.hexdigest,    "0" = omit
            hashSHA1:   "1" = sha1.hexdigest,   "0" = omit
            hashSHA256: "1" = sha256.hexdigest, "0" = omit
            hashSHA512: "1" = sha256.hexdigest, "0" = omit
            hashSHA1:   "1" = sha1.hexdigest,   "0" = omit
            ssdeep:     "1" = ssdeep.hash,      "0" = omit

        Function Arguments:
        :param scanObject:<laikaboss.objectmodel.ScanObject>
        :param result:<laikaboss.objectmodel.ScanResult>
        :param depth:<int>
        :param args:<dict> --execution flow controls--
                    Valid args names <str> (value must be 1, 0, "1", or "0")
                        1/"1": Generate the hash of named type
                        0/"0": Omit the hash of named type
                        default args:
                        {"md5":1,
                         "SHA1":0,
                         "SHA256":1,
                         "SHA512":1,
                         "ssdeep":0}

        :return: Always returns a empty list (no child objects)
        '''
        moduleResult = []
        metaDict = {}
        if int(get_option(args, 'md5', 'hashmd5', "md5" in self.module_defaults)):
            metaDict['md5'] = hashlib.md5(scanObject.buffer).hexdigest()
        if int(get_option(args, 'SHA1', 'hashSHA1', "SHA1" in self.module_defaults)):
            metaDict['SHA1'] = hashlib.sha1(scanObject.buffer).hexdigest()
        if int(get_option(args, 'SHA256', 'hashSHA256', "SHA256" in self.module_defaults)):
            metaDict['SHA256'] = hashlib.sha256(scanObject.buffer).hexdigest()
        if int(get_option(args, 'SHA512', 'hashSHA512', "SHA512" in self.module_defaults)):
            metaDict['SHA512'] = hashlib.sha512(scanObject.buffer).hexdigest()
        if int(get_option(args, 'ssdeep', 'hashssdeep', "ssdeep" in self.module_defaults)):
            #only import ssdeep if dispatched.
            #Prevents import error if you don't have/want the package
            #python should keep handing you the original, minimal/no overhead
            try:
                import ssdeep
                metaDict['ssdeep'] = ssdeep.hash(scanObject.buffer)
            except ImportError:
                metaDict['ssdeep'] = "" #indicate ssdeep was configured but failed


        scanObject.addMetadata(self.module_name, "HASHES", metaDict)
        
        return moduleResult
