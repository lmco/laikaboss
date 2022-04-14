# Copyright 2015 Lockheed Martin Corporation
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
from builtins import str
import os
import shutil
import subprocess
import tempfile
import logging
from laikaboss.objectmodel import ExternalVars, ModuleObject
from laikaboss.si_module import SI_MODULE
from laikaboss.util import get_option, getParentObject, laika_temp_dir
from laikaboss.extras import email_word_list_util

class EXPLODE_ZIP(SI_MODULE):
    '''Laika module for exploding buffers out of zipped files.'''

    def __init__(self,):
        '''Main constructor'''
        self.module_name = "EXPLODE_ZIP"

    def _run(self, scanObject, result, depth, args):
        '''Laika framework module logic execution'''
        moduleResult = [] 

        # Determine file limit from arguments
        file_limit = int(get_option(args, 'filelimit', 'zipfilelimit', 0))
        byte_limit = int(get_option(args, 'bytelimit', 'zipbytelimit', 0))
        hardcoded_password_list_path = get_option(args, 'passwordlistpath', 'PasswordListLocation', '/etc/laikaboss/passwords_to_try')
        zippw = get_option(args, 'password', 'zippassword', '')

        with laika_temp_dir() as tempdir:
            try:
                self._unzip_file(self, moduleResult, scanObject, result, zippw, file_limit, byte_limit, hardcoded_password_list_path, tempdir)
            except:
                # add a flag to the object to indicate it couldn't be extracted
                scanObject.addFlag("zip:CORRUPT_ZIP")
                # error logging handled by SI_MODULE wrapper
                raise
            finally:
                scanObject.addMetadata(self.module_name, "Unzipped", len(moduleResult))
        return moduleResult

    #  These private methods are set to static to ensure immutability since
    #  they may be called more than once in the lifetime of the class
    @staticmethod
    def _unzip_file(self, moduleResult, scanObject, result, password, file_limit, byte_limit, hardcoded_password_list_path, tempdir):
        '''
        Attempts to unzip the file, looping through the namelist and adding each
        object to the ModuleResult. We add the filename from the archive to the
        external variables so it is available during recursive scanning.

        Arguments:
        moduleResult -- an instance of the ModuleResult class created above
        scanObject -- an instance of the ScanObject class, created by the dispatcher
        result -- an instance of the ScanResult class, created by the caller
        password -- the password for the zipfile, if any
        file_limit -- the maximum number of files to explode, adds flag if exceeded
        byte_limit -- the maximum size in bytes for an exploded buffer, adds flag if exceeded

        Returns:
        Nothing, modification made directly moduleResult.
        '''

        word_list = None

        is_encrypted = False
        correct_password = None

        try:

            extract_path = tempfile.mkdtemp(dir=tempdir)

            with tempfile.NamedTemporaryFile(delete=True, dir=tempdir) as temp:
                temp.write(scanObject.buffer)
                temp.flush()

                FNULL = open(os.devnull, 'w')
                zip_size = 0
                try:
                    zip_size_out = subprocess.check_output(["7z", "l", "-p", '%s' % temp.name], stderr=subprocess.STDOUT)
                    zip_size_out = zip_size_out.split(b'\n')
                    try:
                       zip_size = int(zip_size_out[len(zip_size_out)-2].split()[0])
                    except ValueError as e:
                       zip_size = int(zip_size_out[len(zip_size_out)-2].split()[2])
                   
                    scanObject.addMetadata(self.module_name, "Zip_Byte_Size", zip_size)
                except subprocess.CalledProcessError as e:
                    if b"encrypted" in e.output or b"Wrong password" in e.output:
                        is_encrypted = True
                except (ValueError, IndexError) as e:
                    pass # Could not get zip size

                if byte_limit and zip_size > byte_limit:
                    logging.debug("EXPLODE_ZIP: skipping file due to byte limit")
                    scanObject.addFlag("zip:BYTE_LIMIT_EXCEEDED")
                else:
                    # Attempt to extract with no password
                    output = b""
                    returnCode = 0
                    try:
                        output = subprocess.check_output(["7z", "-o%s" % extract_path, "-aou", "-p", "e", "%s" % temp.name], stderr=subprocess.STDOUT)
                    except subprocess.CalledProcessError as e:
                        output = e.output
                        returnCode = e.returncode
                    if returnCode == 2 and (b"encrypted" in output or b"Wrong password" in output):
                        is_encrypted = True
                    # Failed extraction due to wrong password
                    if is_encrypted:
                        scanObject.addFlag("zip:ENCRYPTED_ZIP")

                        # 7z makes files even on unsuccessful decryption. Delete these temporary files.
                        shutil.rmtree(extract_path)
                        os.makedirs(extract_path)

                        # Get word list from sibling objects if they exists
                        sibling_text = email_word_list_util.get_sibling_text(result, scanObject)
                        word_list = email_word_list_util.create_word_list(sibling_text, hardcoded_password_list_path)

                        # Prepend password if given
                        if password:
                            if isinstance(password, bytes):
                                password = password.decode('utf-8')
                            word_list.insert(0, password)

                        # Try to extract with every word in our word list
                        for word in word_list:
                            # Only attempt decryption password if the password is printable otherwise execv() throws an error
                            if self._is_printable(word):
                                to_call = ["7z", "-o%s" % extract_path, "-aou", "-p%s" % (word), "e", "%s" % temp.name]
                                if all('\x00' not in item for item in to_call):
                                    returnCode = subprocess.call(to_call, stdout=FNULL, stderr=FNULL)
                                if returnCode == 0:
                                    correct_password = word
                                    break

                                # 7z makes files even on unsuccessful decryption. Delete these temporary files.
                                shutil.rmtree(extract_path)
                                os.makedirs(extract_path)

                        if correct_password:
                            logging.debug("EXPLODE_ZIP: Successfully decrypted with password (%s)" % (correct_password))
                            scanObject.addFlag("zip:DECRYPT_SUCCESS")
                            scanObject.addMetadata(self.module_name, "Password", correct_password)
                        else:
                            logging.debug("EXPLODE_ZIP: Decryption failed")
                            scanObject.addFlag("zip:DECRYPT_FAILED")
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
                    filenames = []
                    filesizes = []
                    for directory, subdirs, files, in os.walk(extract_path):
                        for file_name in sorted(files):
                            file_count += 1
                            if file_limit and file_count >= file_limit:
                                scanObject.addFlag("zip:FILE_LIMIT_EXCEEDED")
                                logging.debug("EXPLODE_ZIP: breaking due to file limit")
                                break
                            else:
                                (filename, filesize) = self._process_file(os.path.join(directory, file_name), file_name, moduleResult, scanObject)
                                filenames.append(filename)
                                filesizes.append(filesize)
                    scanObject.addMetadata(self.module_name, "Total_Files", len(files))

                    scanObject.addMetadata(self.module_name, "filename", filenames)
                    scanObject.addMetadata(self.module_name, "size", filesizes)

                FNULL.close()

            try:
                shutil.rmtree(extract_path)
            except Exception as e:
                scanObject.addFlag("zip:COULD_NOT_REMOVE_DIRECTORY_AFTER_EXTRACTING")
                logging.debug("EXPLODE_ZIP: Could not remove directory after extracting: %s" % extract_path)
                raise

        except Exception as e:
            scanObject.addFlag("zip:UNKNOWN_ERROR")
            logging.exception("EXPLODE_ZIP: unknown error: %s" % e)
            shutil.rmtree(extract_path)
            raise

    def _process_file(self, full_path_name, file_name, moduleResult, scanObject):
        '''
        Attempts to read the file and add each object to the ModuleResult. 
        We add the filename from the archive to the
        external variables so it is available during recursive scanning.

        Arguments:
        full_path_name -- full pathname and filename of the temp location of one of the files within the zip
        file_name -- the file name of one of the files within the zip
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
            filename_and_size = (file_name, file_size)
        except Exception as e:
            scanObject.addFlag("zip:COULD_NOT_READ_FILE")
            logging.debug("EXPLODE_ZIP: Could not read compressed file %s: %s" % (file_name, e))
            raise
        if full_path_name is not None:
            moduleResult.append(ModuleObject(buffer=file_data, externalVars=ExternalVars(filename='e_zip_%s' % (file_name))))
        return filename_and_size

    @staticmethod
    def _is_printable(s, codec='utf8'):
        '''
        Checks if a string is printable
        '''
        if not isinstance(s, bytes):
            return True
        try: 
            s.decode(codec)
        except UnicodeDecodeError:
            return False
        return True

    @staticmethod
    def _fix_bad_zip(file, buffer):
        '''
        Python's zipfile module does not tolerate extra data after the central directory
        signature in a zip archive. This function truncates the file so that the python
        zipfile module can properly extract the file.

        We're using 7z to extract zip files now, but this function is preserved for posterity
        in case it's ever needed again.

        Arguments:
        file -- a python file object containing the bad zip file
        buffer -- a raw buffer of the bad zip file

        Returns:
        Nothing, modification made directly to the file object.
        '''
        pos = buffer.find(b'\x50\x4b\x05\x06') # End of central directory signature
        if (pos > 0):
            logging.debug("EXPLODE_ZIP: Truncating file at location %s", str(pos + 22))
            file.seek(pos + 22)   # size of 'ZIP end of central directory record'
            file.truncate()

