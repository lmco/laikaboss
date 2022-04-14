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
# Module that uses pycdlib library to parse metadata from iso files.
# Library dependancies: pycdlib
from future import standard_library
standard_library.install_aliases()
from laikaboss.objectmodel import ExternalVars, ModuleObject
from laikaboss.si_module import SI_MODULE
from laikaboss.util import get_option
from laikaboss import config
from io import BytesIO
import pycdlib
import os

class EXPLODE_ISO(SI_MODULE):
    '''
    Input: An iso file to extract files from.
    Output: Files that are contained within this iso

    Purpose: Extract files from an iso image
    '''
    def __init__(self,):
        self.module_name = "EXPLODE_ISO"
        self.file_limit = 0
        self.byte_limit = 0
        self.file_cur = 0
        self.byte_cur = 0

    def _run(self, scanObject, result, depth, args):
        moduleResult = []
        # Find / Create a workaround to directly feed object (no temp file)?
        iso = pycdlib.PyCdlib()
        iso.open_fp(BytesIO(scanObject.buffer))

        # Set file / byte limits, pretty bad way...
        self.file_limit = int(get_option(args, 'filelimit', 'isofilelimit', -1))
        self.byte_limit = int(get_option(args, 'bytelimit', 'isobytelimit', -1))
        self.file_cur = 0
        self.byte_cur = 0

        # Recursively extract files starting at root dir
        self._extract_files_from_dir(self, iso, '/', moduleResult)
        scanObject.addMetadata(self.module_name, "files_extracted", self.file_cur)
        scanObject.addMetadata(self.module_name, "bytes_extracted", self.byte_cur)
        iso.close()
        return moduleResult

    # Helper method that format the data into available in volume descriptor into a string
    @staticmethod
    def _extract_files_from_dir(self, iso, path, moduleResult):
        # Check
        try:
            for child in iso.list_children(iso_path=path):
                # Check limits before proceeding
                if(self.file_limit != -1):
                    if(self.file_limit <= self.file_cur):
                        break
                if(self.byte_limit != -1):
                    if(self.byte_limit <= self.byte_cur):
                        break

                # Check that it is not . or ..
                if(child.is_dot() or child.is_dotdot()):
                    continue

                fpath = path+child.file_identifier()
                # Add this child if its a file
                if(child.is_file()):                    # Get the file from iso
                    buff = BytesIO()
                    iso.get_file_from_iso_fp(buff, iso_path=fpath)

                    # Update file count
                    self.file_cur += 1

                    # Update byte count
                    self.byte_cur += len(buff.getvalue())

                    # Append the extracted file                                                                 #.replace('/', '_')
                    moduleResult.append(ModuleObject(buffer=buff.getvalue(), externalVars=ExternalVars(filename='e_iso_' + fpath)))
                elif(child.isdir):
                    # Recursively search through directories
                    self._extract_files_from_dir(self, iso, fpath + '/', moduleResult)
        except:
            # For some reason sometimes files are marked as directories
            pass

    def _close(self):
        pass
