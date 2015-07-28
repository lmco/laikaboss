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
#This modules extracts metadata from x509 certificates
import sys, hashlib, traceback, logging
from M2Crypto import SMIME, X509, m2, BIO

from laikaboss.si_module import SI_MODULE
from laikaboss.util import get_scanObjectUID, getRootObject
from laikaboss.objectmodel import ModuleObject, ExternalVars, QuitScanException, \
                                GlobalScanTimeoutError, GlobalModuleTimeoutError

import os


class EXPLODE_PKCS7(SI_MODULE):
    
    def __init__(self,):
        self.module_name = "EXPLODE_PKCS7"

    def _run(self, scanObject, result, depth, args):
        moduleResult = [] 

        flags = []
        

        buffer = scanObject.buffer
        cert = None
        
        try:
            #scanObject.addMetadata(self.module_name, key, value)    

            input_bio = BIO.MemoryBuffer(buffer)

            #Check for PEM or DER
            if buffer[:1] == "0":
                #DER
                p7 = SMIME.PKCS7(m2.pkcs7_read_bio_der(input_bio._ptr()), 1)
            else:
                #PEM
                p7 = SMIME.load_pkcs7_bio(input_bio)    
            
            
            certs = p7.get0_signers(X509.X509_Stack())
            
            
            #some pkcs7's should have more than one certificate in them. openssl can extract them handily.
            #openssl pkcs7 -inform der -print_certs -in MYKEY.DSA
            i=0
            for cert in certs:
                cert_filename = "%x.der" % (cert.get_serial_number())
                moduleResult.append(ModuleObject(buffer=cert.as_der(),externalVars=ExternalVars(filename=cert_filename)))
                i = i + 1
            
        except (QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError):
            raise
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            logging.exception("Error parsing cert in "+str(get_scanObjectUID(getRootObject(result))))
            
            ugly_error_string = str(exc_value)
            #nicer_error_string = string.split(string.split(ugly_error_string,":")[4])[0]
            nicer_error_string = ugly_error_string.split(":")[4].split()[0]
                        
            scanObject.addFlag("pkcs7:err:"+nicer_error_string)
            
            
       
        return moduleResult

