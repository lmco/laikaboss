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
from distutils.util import strtobool
import logging
import os
import re
from shutil import rmtree as remove_dir
from laikaboss.si_module import SI_MODULE
from laikaboss.objectmodel import ExternalVars, ModuleObject
from laikaboss.util import get_option, getParentObject
import tempfile
import UnRAR2
from UnRAR2.rar_exceptions import IncorrectRARPassword, InvalidRARArchive

def _create_word_list(content):
    '''
    Get up to the first 200 words from the content. The content is expected to be an email, so all
    lines before the first blank line are skipped as they are assumed to be the header. Any lines
    after 'Content-Disposition: attachment' are also skipped as they are assumed to be the footer.
    '''
    words = list()
    header = 1
    footer = 0
    for line in re.split(r'\r\n|\n', content):
        if not line:
            header = 0
        if line.startswith('Content-Disposition: attachment'):
            footer = 1
        if header == 0 and footer == 0:
            for word in re.findall(re.compile('\S+'), line):
                if word not in words and len(word) > 2:
                    words.append(word)
            for word in re.findall(re.compile('\w+'), line):
                if word not in words and len(word) > 2:
                    words.append(word)
    return words[:200]

class EXPLODE_RAR(SI_MODULE):
    '''Laika module for exploding buffers out of RAR files.'''

    def __init__(self,):
        '''Main constructor'''
        self.module_name = "EXPLODE_RAR"

    def _run(self, scanObject, result, depth, args):
        '''Laika framework module logic execution'''
        moduleResult = []

        file_limit = int(get_option(args, 'filelimit', 'rarfilelimit', 0))
        byte_limit = int(get_option(args, 'bytelimit', 'rarbytelimit', 0))
        password = get_option(args, 'password', 'rarpassword')
        attempt_decrypt = strtobool(get_option(args, 'attemptdecrypt', 'rarattemptdecrypt', 'false'))
        temp_dir = get_option(args, 'tempdir', 'tempdir', '/tmp/laikaboss_tmp')
        if not os.path.isdir(temp_dir):
            os.mkdir(temp_dir)
            os.chmod(temp_dir, 0777)

        # A temp file must be created as UnRAR2 does not accept buffers
        with tempfile.NamedTemporaryFile(dir=temp_dir) as temp_file:
            temp_file.write(scanObject.buffer)
            temp_file.flush()

            # RAR can be password protected, which encrypts the headers
            headers_are_encrypted = False
            # RAR can encrypt the files while leaving the headers decrypted
            files_are_encrypted = False

            rar = None
            # list of the file info objects
            infos = []

            try:
                logging.debug('%s: Attempting to open rar file', self.module_name)
                # If headers are encrypted, the following will raise IncorrectRARPassword
                rar = UnRAR2.RarFile(temp_file.name)
                infos = rar.infolist()
                logging.debug('%s: Succeeded opening rar file', self.module_name)

                # If files are encrypted, the filename will be prefixed with a '*'
                for info in infos:
                    if info.filename.startswith('*'):
                        logging.debug('%s: Rar files are encrypted', self.module_name)
                        scanObject.addFlag('ENCRYPTED_RAR')
                        scanObject.addMetadata(self.module_name, "Encrypted", "Protected Files")
                        files_are_encrypted = True
                        break
            except IncorrectRARPassword:
                logging.debug('%s: Rar headers are encrypted', self.module_name)
                scanObject.addFlag('ENCRYPTED_RAR')
                scanObject.addMetadata(self.module_name, "Encrypted", "Protected Header")
                headers_are_encrypted = True
            except InvalidRARArchive:
                logging.debug('%s: Invalid Rar file')

            if (headers_are_encrypted or files_are_encrypted) and attempt_decrypt:
                logging.debug('%s: Attempting to decrypt', self.module_name)
                possible_passwords = []

                # Passwords are sometimes sent in the email content. Use the content of the parent
                # object as the list of possible passwords
                parent_object = getParentObject(result, scanObject)
                if parent_object:
                    possible_passwords = _create_word_list(parent_object.buffer)

                if password:
                    possible_passwords.insert(0, password)

                explode_temp_dir = os.path.join(temp_dir, 'exploderar')
                for possible_password in possible_passwords:
                    try:
                        logging.debug("EXPLODE_RAR: Attempting password '%s'", possible_password)
                        rar = UnRAR2.RarFile(temp_file.name, password=possible_password)
                        # Extraction is needed to force the exception on encrypted files
                        if files_are_encrypted:
                            rar.extract(path=explode_temp_dir)
                        infos = rar.infolist()
                        logging.debug("EXPLODE_RAR: Found password '%s'", possible_password)
                        scanObject.addFlag('rar:decrypted')
                        scanObject.addMetadata(self.module_name, 'Password', possible_password)
                        break
                    except IncorrectRARPassword:
                        continue
                if os.path.exists(explode_temp_dir):
                    remove_dir(explode_temp_dir)

            scanObject.addMetadata(self.module_name, "Total_Files", len(infos))
            file_count = 0
            exceeded_byte_limit = False
            for info in infos:
                if byte_limit and info.size > byte_limit:
                    logging.debug("EXPLODE_RAR: skipping file due to byte limit")
                    exceeded_byte_limit = True
                    continue
                try:
                    content = rar.read_files(info.filename)[0][1]
                    if byte_limit and len(content) > byte_limit:
                        logging.debug("EXPLODE_RAR: skipping file due to byte limit")
                        exceeded_byte_limit = True
                        continue
                    moduleResult.append(ModuleObject(buffer=content,
                        externalVars=ExternalVars(filename=info.filename)))
                except IndexError:
                    pass
                file_count += 1
                if file_limit and file_count >= file_limit:
                    scanObject.addFlag("rar:err:LIMIT_EXCEEDED")
                    logging.debug("EXPLODE_RAR: breaking due to file limit")
                    break
            if exceeded_byte_limit:
                scanObject.addFlag("rar:err:BYTE_LIMIT_EXCEEDED")

        scanObject.addMetadata(self.module_name, "Unzipped", len(moduleResult))
        return moduleResult

