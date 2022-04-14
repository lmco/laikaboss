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
This module explodes ACE 1.x/2.x compressed/archived files by using the commandline utility "unace" from the package "unace-nonfree".

Requires: Debian package unace-nonfree

Sandia National Labs
"""

import logging
import subprocess
import shutil
import tempfile
import os
import laikaboss

from laikaboss.objectmodel import ExternalVars, ModuleObject
from laikaboss.util import get_option, laika_temp_dir
from laikaboss.si_module import SI_MODULE

class EXPLODE_ACE(SI_MODULE):

    def __init__(self):
        self.module_name = "EXPLODE_ACE"

    def _run(self, scanObject, result, depth, args):

        moduleResult = [] 

        file_limit = int(get_option(args, 'filelimit', 'acefilelimit', 0))
        byte_limit = int(get_option(args, 'bytelimit', 'acebytelimit', 0))

        with laika_temp_dir() as extract_tmp_dir:
            try:
                self._decompress_file(self, moduleResult, scanObject, file_limit, byte_limit, extract_tmp_dir)
            except Exception as e:
                logging.debug("Problem decompressing the file %s: (%s)" % (scanObject.filename, e), exc_info=True)
                scanObject.addFlag("ace:DECOMPRESS_ERROR")

        return moduleResult


    @staticmethod
    def _decompress_file(self, moduleResult, scanObject, file_limit, byte_limit, extract_tmp_dir):
        '''
        Attempts to decompress the file.

        Arguments:
        moduleResult -- an instance of the ModuleResult class created above
        scanObject -- an instance of the ScanObject class created by dispatcher
        file_limit -- the maximum number of files for an exploded ACE archive, flagged if exceeded. file_limit == 0 means no file limit.
        byte_limit -- the maximum number of bytes for an exploded file from an ACE archive, flagged if exceeded. byte_limit == 0 means no byte limit.

        Returns:
        Nothing, modification made directly to moduleResult
        '''

        exceeded_byte_limit = False
        num_files = 0

        # Write file to temporary directory
        extract_path = tempfile.mkdtemp(prefix="explodeace", dir=extract_tmp_dir)
        extract_path += os.sep
        logging.debug("Extract path: %s" % extract_path)

        # Extract and decompress using subprocess
        # Note that suffix MUST be ".ACE" or otherwise `unace` utility will not extract.
        with tempfile.NamedTemporaryFile(delete=True, suffix=".ACE") as temp:
            temp.write(scanObject.buffer)
            temp.flush()

            FNULL = open(os.devnull, 'w')

            cmd = ['/usr/bin/unace', 'x', '-o', '-y', temp.name, extract_path]
            try:
                subprocess.check_call(cmd, stdout=FNULL, stderr=FNULL)
            except Exception as e:
                logging.debug("EXPLODE_ACE: Problem calling unace: %s" % str(e))
                scanObject.addFlag('ace:DECOMPRESS_ERROR')

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
                scanObject.addFlag("ace:FILE_LIMIT_EXCEEDED")
                logging.debug("EXPLODE_ACE: Breaking due to file limit")
                break

            # Check for byte limit
            if byte_limit and child_file_size > byte_limit:
                exceeded_byte_limit = True

            # Open and read child file
            with open(child_name[0], 'rb') as child_fh:
                child_data = child_fh.read()
                moduleResult.append(ModuleObject(buffer=child_data, externalVars=ExternalVars(filename="e_ace_%s" % child_name[1])))

        if exceeded_byte_limit:
            scanObject.addFlag("ace:BYTE_LIMIT_EXCEEDED")

        # Remove temporary files
        try:
            shutil.rmtree(extract_path)
        except Exception as e:
            logging.debug("Problem cleaning up temporary files: %s")
            raise
