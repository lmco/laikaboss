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
'''
This module decompresses 7-zip files
'''

import logging
import os
import shutil
import subprocess
import tempfile
from laikaboss import config
from laikaboss.objectmodel import ExternalVars, ModuleObject
from laikaboss.si_module import SI_MODULE
from laikaboss.util import get_option, getParentObject, laika_temp_dir
from laikaboss.extras import email_word_list_util

class EXPLODE_SEVENZIP(SI_MODULE):
    '''Laika module for exploding buffers out of 7-zipped files.'''

    def __init__(self,):
        '''Main constructor'''
        self.module_name = "EXPLODE_SEVENZIP"

    def _run(self, scanObject, result, depth, args):
        '''Laika framework module logic execution'''
        moduleResult = [] 

        # Determine file limit from arguments
        file_limit = int(get_option(args, 'filelimit', 'sevenzipfilelimit', 0))
        byte_limit = int(get_option(args, 'bytelimit', 'sevenzipbytelimit', 0))
        sevenzippw = get_option(args, 'password', 'sevenzippassword', '')
        hardcoded_password_list_path = get_option(args, 'passwordlistpath', 'PasswordListLocation', '/etc/laikaboss/passwords_to_try')
        self._unzip_file(self, moduleResult, scanObject, result, sevenzippw, file_limit, byte_limit, hardcoded_password_list_path)
        return moduleResult

    #  These private methods are set to static to ensure immutability since
    #  they may be called more than once in the lifetime of the class
    @staticmethod
    def _unzip_file(self, moduleResult, scanObject, result, password, file_limit, byte_limit, hardcoded_password_list_path):
        '''
        Attempts to unzip the file, looping through the namelist and adding each
        object to the ModuleResult. We add the filename from the archive to the
        external variables so it is available during recursive scanning.

        Arguments:
        moduleResult -- an instance of the ModuleResult class created above
        scanObject -- an instance of the ScanObject class, created by the dispatcher
        result -- an instance of the ScanResult class, created by the caller
        password -- the password for the sevenzipfile, if any
        file_limit -- the maximum number of files to explode, adds flag if exceeded
        byte_limit -- the maximum size in bytes for an exploded buffer, adds flag if exceeded

        Returns:
        Nothing, modification made directly moduleResult.
        '''

        word_list = None

        is_encrypted = False
        correct_password = None

        try:
            with laika_temp_dir() as temp_dir, tempfile.NamedTemporaryFile(delete=True, dir=temp_dir) as temp:
                extract_path = tempfile.mkdtemp(dir=temp_dir) 
                temp.write(scanObject.buffer)
                temp.flush()
                FNULL = open(os.devnull, 'w')
                sevenzip_size = 0
                try:
                    sevenzip_size = subprocess.check_output(["7z", "l", "-p", temp.name], stderr=subprocess.STDOUT)
                    sevenzip_size = sevenzip_size.split(b'\n')
                    try:
                        sevenzip_size = int(sevenzip_size[len(sevenzip_size)-2].split()[0])
                    except ValueError as e:
                        sevenzip_size = int(sevenzip_size[len(sevenzip_size)-2].split()[2])
                    scanObject.addMetadata(self.module_name, "Sevenzip_Byte_Size", sevenzip_size)
                except subprocess.CalledProcessError as e:
                    if b"encrypted" in e.output or b"Wrong password" in e.output:
                        is_encrypted = True
                except (ValueError, IndexError) as e:
                    sevenzip_size = 0 #Could not get size

                if byte_limit and sevenzip_size > byte_limit:
                    logging.debug("EXPLODE_SEVENZIP: skipping file due to byte limit")
                    scanObject.addFlag("sevenzip:BYTE_LIMIT_EXCEEDED")
                else:
                    # Attempt to extract with no password
                    output = ""
                    returnCode = 0
                    try:
                        output = subprocess.check_output(["7z", "-o%s" % extract_path, "-aou", "-p", "e", "%s" % temp.name], stderr=subprocess.STDOUT)
                    except subprocess.CalledProcessError as e:
                        output = e.output
                        returnCode = e.returncode
                    if returnCode == 2 and (b"encrypted" in output or b"Wrong password" in output):
                        is_encrypted = True

                    # Failed extraction due to wrong password?
                    if is_encrypted:
                        scanObject.addFlag("sevenzip:ENCRYPTED_7Z")

                        # 7z makes files even on unsuccessful decryption. Delete these temporary files.
                        shutil.rmtree(extract_path)
                        os.makedirs(extract_path)

                        # Get word list from sibling objects if they exists
                        sibling_text = email_word_list_util.get_sibling_text(result, scanObject)
                        word_list = email_word_list_util.create_word_list(sibling_text, hardcoded_password_list_path)
                        # Prepend password if given
                        if password:
                            if isinstance(password, bytes):
                                password = password.decode("utf-8")
                            word_list.insert(0, password)

                        # Try to extract with every word in our word list
                        for word in word_list:
                            returnCode = subprocess.call(["7z", "-o%s" % extract_path, "-aou", "-p%s" % (word), "e", temp.name], stdout=FNULL, stderr=FNULL)
                            if returnCode == 0:
                                correct_password = word
                                break

                            # 7z makes files even on unsuccessful decryption. Delete these temporary files.
                            shutil.rmtree(extract_path)
                            os.makedirs(extract_path)

                        if correct_password:
                            logging.debug("EXPLODE_SEVENZIP: Successfully decrypted with password (%s)" % (correct_password))
                            scanObject.addFlag("sevenzip:DECRYPT_SUCCESS")
                            scanObject.addMetadata(self.module_name, "Password", correct_password)
                        else:
                            logging.debug("EXPLODE_SEVENZIP: Decryption failed")
                            scanObject.addFlag("sevenzip:DECRYPT_FAILED")
                    # Other errors are raised as exceptions
                    elif returnCode > 1:
                        codeReasons = {
                            2: "Fatal extraction error",
                            7: "Command line error",
                            8: "Out of memory",
                            255: "Extraction cancelled"
                        }
                        if returnCode not in codeReasons:
                            raise Exception("Unknown error code: %s" % str(returnCode))
                        raise Exception(codeReasons[returnCode])
                    # Get extracted files

                    file_count = 0
                    exceeded_byte_limit = False
                    for directory, subdirs, files, in os.walk(extract_path):
                        for file_name in sorted(files):
                            file_count += 1
                            if file_limit and file_count >= file_limit:
                                scanObject.addFlag("sevenzip:FILE_LIMIT_EXCEEDED")
                                logging.debug("EXPLODE_SEVENZIP: breaking due to file limit")
                                break
                            else:
                                self._process_file(os.path.join(directory, file_name), file_name, moduleResult, scanObject)
                    scanObject.addMetadata(self.module_name, "Total_Files", len(files))
                FNULL.close()

        except Exception as e:
            scanObject.addFlag("sevenzip:UNKNOWN_ERROR")
            logging.exception("EXPLODE_SEVENZIP: unknown error: %s" % e)
            raise

    def _process_file(self, full_path_name, file_name, moduleResult, scanObject):
        '''
        Attempts to read the file and add each object to the ModuleResult. 
        We add the filename from the archive to the
        external variables so it is available during recursive scanning.

        Arguments:
        full_path_name -- full pathname and filename of the temp location of one of the files within the 7zip
        file_name -- the file name of one of the files within the 7zip
        moduleResult -- an instance of the ModuleResult class created above
        scanObject -- an instance of the ScanObject class, created by the dispatcher

        Returns:
        Nothing, modification made directly moduleResult.
        '''

        file_data = None
        try:
            with open(full_path_name, 'rb') as f:
                file_data = f.read()
            file_size = os.path.getsize(full_path_name)
            scanObject.addMetadata(self.module_name, "filename", file_name)
            scanObject.addMetadata(self.module_name, "size", file_size)
        except Exception as e:
            scanObject.addFlag("sevenzip:COULD_NOT_READ_FILE")
            logging.debug("EXPLODE_SEVENZIP: Could not read compressed file %s: %s" % (file_name, e))
            raise
        if full_path_name is not None:
            moduleResult.append(ModuleObject(buffer=file_data, externalVars=ExternalVars(filename='e_sevenzip_%s' % (file_name))))
        return
