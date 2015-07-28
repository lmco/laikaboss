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
import sys
import M2Crypto
import datetime

from laikaboss.si_module import SI_MODULE
from laikaboss.util import getRootObject, get_scanObjectUID
import logging
from laikaboss.objectmodel import QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError

import string

class META_X509(SI_MODULE):
    
    def __init__(self,):
        self.module_name = "META_X509"

    def _run(self, scanObject, result, depth, args):
        moduleResult = [] 

        flags = []
        
                                

        buffer = scanObject.buffer
        cert = None
        
        try:
            #scanObject.addMetadata(self.module_name, key, value)    

            #simple check for PEM or DER
            if buffer[:1] == "0":
                format =  M2Crypto.X509.FORMAT_DER
            else:
                format =  M2Crypto.X509.FORMAT_PEM
            
            
            
            cert = M2Crypto.X509.load_cert_string(buffer, format=format)

            #serial_number
            #print "serial_number: %x" % cert.get_serial_number()
            serial_number = "%x" % cert.get_serial_number()
            scanObject.addMetadata(self.module_name, "serial_number", serial_number)

            #fingerprint
            #print "fingerprint: "+str(cert.get_fingerprint())
            scanObject.addMetadata(self.module_name, "fingerprint", str(cert.get_fingerprint()))

            #version
            #print "version: "+str(cert.get_version())
            scanObject.addMetadata(self.module_name, "version", cert.get_version())
            
            #subject
            subject = self._parseDN(cert.get_subject())
            scanObject.addMetadata(self.module_name, "subject", subject)
            
            #issuer
            issuer = self._parseDN(cert.get_issuer())
            scanObject.addMetadata(self.module_name, "issuer", issuer)

            #validity dates
            scanObject.addMetadata(self.module_name, "not_before", str(cert.get_not_before()))
            scanObject.addMetadata(self.module_name, "not_after", str(cert.get_not_after()))
            
            
            #string complete subject and issuers
            scanObject.addMetadata(self.module_name, "subject_string", str(cert.get_subject()))
            scanObject.addMetadata(self.module_name, "issuer_string", str(cert.get_issuer()))
            
            
            if str(cert.get_issuer()) == str(cert.get_subject()):
                scanObject.addFlag("x509:nfo:self_signed_cert")
           
            start = datetime.datetime.strptime(str(cert.get_not_before()), "%b %d %H:%M:%S %Y %Z")
            end = datetime.datetime.strptime(str(cert.get_not_after()), "%b %d %H:%M:%S %Y %Z")
            dur = end - start
            scanObject.addMetadata(self.module_name, "duration", dur.days) 

            extensions = {}
            for i in range(cert.get_ext_count()):
                extensions[str(cert.get_ext_at(i).get_name())] = str(cert.get_ext_at(i).get_value()).strip();
            
            scanObject.addMetadata(self.module_name, "extensions", extensions)
            
        
        except (QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError):
            raise
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            logging.exception("Error parsing cert in "+str(get_scanObjectUID(getRootObject(result))))
            
            ugly_error_string = str(exc_value)
            nicer_error_string = string.split(string.split(ugly_error_string,":")[4])[0]
                        
            scanObject.addFlag("x509:err:"+nicer_error_string)
            
            
       
        return moduleResult 
    
    
        
#x{'C': 14,
#x 'CN': 13, 'commonName': 13,
#X 'Email': 48, 'emailAddress': 48,
# 'GN': 99, 'givenName': 99,
#x 'L': 15, 'localityName': 15,
#x 'O': 17, 'organizationName': 17,
#X 'OU': 18, 'organizationUnitName': 18,
# 'SN': 100, 'surname': 100}
#x 'ST': 16, 'SP': 16, 'stateOrProvinceName': 16, 
# 'serialNumber': 105,

    @staticmethod
    def _parseDN( dn ):
        return_value = {}
        if dn.CN:
            return_value['CN'] = dn.CN
        if dn.C:
            return_value['C'] = dn.C
        if dn.L:
            return_value['L'] = dn.L
        if dn.ST:
            return_value['ST'] = dn.ST
        if dn.O:
            return_value['O'] = dn.O
        if dn.OU:
            return_value['OU'] = dn.OU
        if dn.Email:
            return_value['emailAddress'] = dn.Email
        if dn.GN:
            return_value['GN'] = dn.GN
        if dn.SN:
            return_value['SN'] = dn.SN
        if dn.serialNumber:
            return_value['serialNumber'] = dn.serialNumber
             
        return return_value


