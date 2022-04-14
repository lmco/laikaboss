# Copyright 2020 National Technology & Engineering Solutions of Sandia, LLC 
# (NTESS). Under the terms of Contract DE-NA0003525 with NTESS, the U.S. 
# Government retains certain rights in this software.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Module to decrypt encrypted office files (word docs, excel spreadsheets, etc.)
#
# Sandia National Labs
from laikaboss.util import get_option
from laikaboss.objectmodel import ExternalVars, ModuleObject
from laikaboss.si_module import SI_MODULE
from laikaboss.extras import email_word_list_util

import io
import msoffcrypto
from msoffcrypto.format.ooxml import OOXMLFile

class EXPLODE_ENCRYPTEDOFFICE(SI_MODULE):
    ''' 
    Module that decrypts MS Office files (word docs, excel spreadsheets, etc.), explodes one decrypted file
    if the file was successfully decrypted
    '''
    def __init__(self):
        self.module_name = "EXPLODE_ENCRYPTEDOFFICE"

    def _run(self, scanObject, result, depth, args):
        moduleResult = [] 

        password = get_option(args, 'password', 'encryptedofficepassword', None)
        hardcoded_password_list_path = get_option(args, 'passwordlistpath', 'PasswordListLocation', '/etc/laikaboss/passwords_to_try')
        
        # Check to see if the file is actually encrypted
        encryptedFile = msoffcrypto.OfficeFile(io.BytesIO(scanObject.buffer))
        if encryptedFile.is_encrypted():
            # Add relevant flags
            scanObject.addFlag('encryptedoffice:encrypted')
            if isinstance(encryptedFile, OOXMLFile):
                scanObject.addFlag('encryptedoffice:officex')
            else:
                scanObject.addFlag('encryptedoffice:ole')
            # Populate password list
            # "VelvetSweatshop" is a default password for Excel
            # See e.g. https://blogs.vmware.com/networkvirtualization/2020/11/velvetsweatshop-when-default-passwords-can-still-make-a-difference.html/
            passwords_to_try = ['VelvetSweatshop']
            if password:
                passwords_to_try.append(password)
            # Try to get passwords from email (sibling objects)
            sibling_text = email_word_list_util.get_sibling_text(result, scanObject)
            word_list = email_word_list_util.create_word_list(sibling_text, hardcoded_password_list_path)
            passwords_to_try.extend(word_list)

            # Try all passwords
            passwd = None
            for candidate in passwords_to_try:
                try:
                    out = io.BytesIO()
                    encryptedFile.load_key(password=candidate)
                    encryptedFile.decrypt(out)
                    passwd = candidate
                    break
                except Exception:
                    pass
            # Successful decryption
            if passwd:
                out.seek(io.SEEK_SET) # Rewind stream
                scanObject.addMetadata(self.module_name, "Password", passwd)
                moduleResult.append(ModuleObject(buffer=out.read(), externalVars=ExternalVars(filename=scanObject.filename)))
                scanObject.addFlag('encryptedoffice:decrypt_success')
            # Unsuccessful decryption
            else:
                scanObject.addFlag('encryptedoffice:decrypt_failure')
        else:
            scanObject.addFlag('encryptedoffice:not_encrypted')

        return moduleResult


