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
"""
Explodes RAR files using rarfile library. 

Requires: rarfile 3.0 (https://pypi.python.org/pypi/rarfile/)

Sandia National Labs
"""

import logging
import tempfile
import rarfile
import os
import re
from distutils.util import strtobool
from builtins import str

from laikaboss import config
from laikaboss.objectmodel import ExternalVars, ModuleObject
from laikaboss.util import get_option, getParentObject, laika_temp_dir
from laikaboss.si_module import SI_MODULE
from laikaboss.extras import email_word_list_util

class EXPLODE_RAR2(SI_MODULE):

    def __init__(self):
        self.module_name = "EXPLODE_RAR2"

    def _run(self, scanObject, result, depth, args):
        moduleResult = [] 

        # Get params
        file_limit = int(get_option(args, 'filelimit', 'rarfilelimit', 0))
        byte_limit = int(get_option(args, 'bytelimit', 'rarbytelimit', 0))
        password = get_option(args, 'password', 'rarpassword')
        hardcoded_password_list_path = get_option(args, 'passwordlistpath', 'PasswordListLocation', '/etc/laikaboss/passwords_to_try')

        attempt_decrypt = strtobool(str(get_option(args, 'attemptdecrypt', 'rarattemptdecrypt', 'true')))

        with laika_temp_dir() as temp_dir:
            # Create temporary file to write the RAR file to
            fh, tempRarFile = tempfile.mkstemp(suffix='_rarfile', dir=temp_dir)
            os.write(fh, scanObject.buffer)
            os.close(fh)

            rarfile.UNRAR_TOOL = '/usr/bin/unrar'
            rf = None

            # Attempt to open the RAR file
            try:
                rf = rarfile.RarFile(tempRarFile)
            except (rarfile.NotRarFile, rarfile.BadRarFile) as e:
                logging.debug('%s: Not a RAR file (%s)' % (self.module_name, str(e)), exc_info=True)
                scanObject.addFlag('rar:CORRUPTED_RAR')
                raise
            except Exception as e:
                logging.exception('%s: Unknown error (%s)' % (self.module_name, str(e)))
                raise
 
            # Check for encryption
            if rf.needs_password():
                logging.debug('%s: Rar is encrypted' % self.module_name)
                scanObject.addFlag('rar:ENCRYPTED_RAR')

                # Attempt to decrypt RAR
                if attempt_decrypt:
                    logging.debug('%s: Attempting to decrypt RAR file.' % self.module_name)
                    self._attempt_decrypt(self, rf, scanObject, result, moduleResult, password, hardcoded_password_list_path)
            else:
                if not self._extract_files(self.module_name, rf, scanObject, moduleResult):
                    scanObject.addFlag('rar:CORRUPTED_RAR')

        return moduleResult

    @staticmethod
    def _attempt_decrypt(self, rar_file, scanObject, result, moduleResult, password, hardcoded_password_list_path):
        '''
        Attempts to decrypt a RAR file by using content in the parent object.
        '''

        decrypt_success = False

        possible_passwords = []

        sibling_text = email_word_list_util.get_sibling_text(result, scanObject)
        possible_passwords = email_word_list_util.create_word_list(sibling_text, hardcoded_password_list_path)
        if password:
            if isinstance(password, bytes):
                password = password.decode('utf-8')
            possible_passwords.insert(0, password)

        # Try possible passwords from parent object parsing
        for possible_password in possible_passwords:
            try:

                # Try this password on the RAR
                rar_file.setpassword(possible_password)

                # Extract files from decrypted archive
                if self._extract_files(self.module_name, rar_file, scanObject, moduleResult):
                    logging.debug("%s: Found password '%s'" % (self.module_name, possible_password))
                    scanObject.addFlag('rar:DECRYPT_SUCCESS')
                    scanObject.addMetadata(self.module_name, 'Password', possible_password)
                    decrypt_success = True
                    break

            except Exception as e:
                continue

        if not decrypt_success:
            logging.debug("%s: Unable to decrypt" % (self.module_name))
            scanObject.addFlag('rar:DECRYPT_FAILED')

    @staticmethod
    def _extract_files(module_name, rar_file, scanObject, moduleResult):
        '''
        Extracts files from a rar_file object
        '''

        rar_info = rar_file.infolist()
        found_child = False

        # Infolist empty means that there are no files in this archive
        # or archive was decrypted using incorrect password.
        if len(rar_info) == 0:
            return False

        for file_info in rar_info:
            if file_info.isdir():
                continue
            try:
                rar_data = rar_file.read(file_info.filename)
            except rarfile.BadRarFile as e:
                logging.debug('%s: Corrupted RAR file or incorrect password (%s)' % (module_name, str(e)))
                continue
            if len(rar_data) != file_info.file_size:
                continue

            # Get filename of extracted object
            object_filename = file_info.filename
            if isinstance(file_info.filename, str):
                try:
                    object_filename = object_filename.encode('utf-8')
                except Exception as e:
                    object_filename = "unicode_parsing_error"

            # Append extracted object as child
            moduleResult.append(ModuleObject(buffer=rar_data, externalVars=ExternalVars(filename=object_filename)))
            found_child = True

        return found_child
