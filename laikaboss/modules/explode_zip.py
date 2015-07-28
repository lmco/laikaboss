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
import cStringIO
import logging
from laikaboss.objectmodel import ExternalVars, ModuleObject#, QuitScanException
from laikaboss.si_module import SI_MODULE
from laikaboss.util import get_option
import zipfile

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
        zippw = get_option(args, 'password', 'zippassword', '')

        # write temporary file so we can open it with zipfile
        file = cStringIO.StringIO()
        file.write(scanObject.buffer)

        try:
            logging.debug("first attempt at unzipping..")
            self._unzip_file(self, moduleResult, file, scanObject, result, zippw, file_limit, byte_limit)
        except zipfile.BadZipfile:
            try:
                # try to repair the zip file (known python limitation)
                logging.debug("error extracting zip, trying to fix it")
                self._fix_bad_zip(file, scanObject.buffer)
                self._unzip_file(self, moduleResult, file, scanObject, result, zippw, file_limit, byte_limit)
            #except QuitScanException:
            #    raise
            except:
                # add a flag to the object to indicate it couldn't be extracted
                logging.debug("couldn't fix zip, marking it as corrupt")
                scanObject.addFlag("CORRUPT_ZIP")
                # error logging handled by SI_MODULE wrapper
                raise
        finally:
            scanObject.addMetadata(self.module_name, "Unzipped", len(moduleResult))
            file.close()
        return moduleResult

    #  These private methods are set to static to ensure immutability since
    #  they may be called more than once in the lifetime of the class
    @staticmethod
    def _unzip_file(self, moduleResult, file, scanObject, result, password, file_limit, byte_limit):
        '''
        Attempts to unzip the file, looping through the namelist and adding each
        object to the ModuleResult. We add the filename from the archive to the
        external variables so it is available during recursive scanning.

        If the file is encrypted (determined by an exception), add the flag and return

        Arguments:
        moduleResult -- an instance of the ModuleResult class created above
        file -- a file object created using the buffer passed into this module
        scanObject -- an instance of the ScanObject class, created by the dispatcher
        result -- an instance of the ScanResult class, created by the caller
        password -- the password for the zipfile, if any
        file_limit -- the maximum number of files to explode, adds flag if exceeded
        byte_limit -- the maximum size in bytes for an exploded buffer, adds flag if exceeded

        Returns:
        Nothing, modification made directly moduleResult.
        '''
        try:
            zf = zipfile.ZipFile(file)
            if password:
                zf.setpassword(password)
            file_count = 0
            #dir_depth_max = 0
            #dir_count = 0
            namelist = zf.namelist()
            scanObject.addMetadata(self.module_name, "Total_Files", len(namelist))
            exceeded_byte_limit = False
            for name in namelist:
                if byte_limit:
                    info = zf.getinfo(name)
                    if info.file_size > byte_limit:
                        logging.debug("EXPLODE_ZIP: skipping file due to byte limit")
                        exceeded_byte_limit = True
                        continue
                childBuffer = zf.read(name)
                if byte_limit and len(childBuffer) > byte_limit:
                    logging.debug("EXPLODE_ZIP: skipping file due to byte limit")
                    exceeded_byte_limit = True
                    continue
                moduleResult.append(ModuleObject(buffer=childBuffer,
                    externalVars=ExternalVars(filename='e_zip_%s' % name)))
                file_count += 1
                if file_limit and file_count >= file_limit:
                    scanObject.addFlag("zip:err:LIMIT_EXCEEDED")
                    logging.debug("EXPLODE_ZIP: breaking due to file limit")
                    break
            if exceeded_byte_limit:
                scanObject.addFlag("zip:err:BYTE_LIMIT_EXCEEDED")

        except RuntimeError as rte:
            if "encrypted" in rte.args[0]:
                scanObject.addFlag("ENCRYPTED_ZIP")
            else:
                raise

    @staticmethod
    def _fix_bad_zip(file, buffer):
        '''
        Python's zipfile module does not tolerate extra data after the central directory
        signature in a zip archive. This function truncates the file so that the python
        zipfile module can properly extract the file.

        Arguments:
        file -- a python file object containing the bad zip file
        buffer -- a raw buffer of the bad zip file

        Returns:
        Nothing, modification made directly to the file object.
        '''
        pos = buffer.find('\x50\x4b\x05\x06') # End of central directory signature
        if (pos > 0):
            logging.debug("Truncating file at location %s", str(pos + 22))
            file.seek(pos + 22)   # size of 'ZIP end of central directory record'
            file.truncate()

