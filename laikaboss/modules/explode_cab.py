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
explode cab files 

Requires: Debian package 7z 

Sandia National Labs
"""

import logging
import subprocess
import tempfile
import os
import shutil

from laikaboss.objectmodel import ExternalVars, ModuleObject
from laikaboss.util import get_option, laika_temp_dir
from laikaboss.si_module import SI_MODULE

class EXPLODE_CAB(SI_MODULE):

    def __init__(self):
        self.module_name = "EXPLODE_CAB"

    def _run(self, scanObject, result, depth, args):

        moduleResult = [] 

        file_limit = int(get_option(args, 'filelimit', 'cabfilelimit', 0))
        byte_limit = int(get_option(args, 'bytelimit', 'cabbytelimit', 0))

        with laika_temp_dir() as tempdir:
            try:
                self._decompress_file(self, moduleResult, scanObject, file_limit, byte_limit, tempdir)
            except Exception as e:
                scanObject.addFlag("cab:DECOMPRESS_ERROR")
                logging.exception("Problem decompressing the file %s: (%s)" % (scanObject.filename, e))

        return moduleResult


    @staticmethod
    def _decompress_file(self, moduleResult, scanObject, file_limit, byte_limit, tempdir):
        '''
        Attempts to decompress the file.

        Arguments:
        moduleResult -- an instance of the ModuleResult class created above
        scanObject -- an instance of the ScanObject class created by dispatcher
        file_limit -- the maximum number of files for an exploded CAB archive, flagged if exceeded. file_limit == 0 means no file limit.
        byte_limit -- the maximum number of bytes for an exploded file from a CAB archive, flagged if exceeded. byte_limit == 0 means no byte limit.

        Returns:
        Nothing, modification made directly to moduleResult
        '''

        exceeded_byte_limit = False
        num_files = 0

        # Create temporary directory
        extract_path = tempfile.mkdtemp(dir=tempdir)
        logging.debug("Extract path: %s" % extract_path)
        remove_tree = True

        # Extract and decompress using subprocess
        with tempfile.NamedTemporaryFile(delete=True, suffix=".cab", dir=tempdir) as temp:
            temp.write(scanObject.buffer)
            temp.flush()

            FNULL = open(os.devnull, 'w')

            cmd = ['/usr/bin/7z', '-o%s' % extract_path, '-aou', 'e', temp.name]
            try:
                subprocess.check_call(cmd, stdout=FNULL, stderr=FNULL)
            except Exception as e:
                remove_tree = False
                shutil.rmtree(extract_path)
                logging.debug("EXPLODE_CAB: Problem calling 7z: %s" % str(e))
                scanObject.addFlag("cab:DECOMPRESS_ERROR")

        # Get children filenames and paths
        children = []
        for root, dirs, files in os.walk(extract_path):
            for file_name in files:
                children.append((os.path.join(root, file_name), file_name))

        # Handle children files
        for child_name in sorted(children, key=lambda x: x[1]):
            child_file_size = os.path.getsize(child_name[0])

            num_files += 1

            # Check for file limit
            if file_limit and num_files > file_limit:
                scanObject.addFlag("cab:FILE_LIMIT_EXCEEDED")
                logging.debug("EXPLODE_CAB: Breaking due to file limit")
                break

            # Check for byte limit
            if byte_limit and child_file_size > byte_limit:
                logging.debug("EXPLODE_CAB: Skipping child %s due to byte limit (File size: %d)" % (child_name[1], child_file_size))
                exceeded_byte_limit = True

            # Open and read child file
            with open(child_name[0], 'rb') as child_fh:
                child_data = child_fh.read()
                moduleResult.append(ModuleObject(buffer=child_data, externalVars=ExternalVars(filename="e_cab_%s" % child_name[1])))

        if exceeded_byte_limit:
            scanObject.addFlag("cab:BYTE_LIMIT_EXCEEDED")
