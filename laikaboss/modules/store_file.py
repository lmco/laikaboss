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
This module writes files to local disk at a specified location.


Params:

    storagedir - The root storage directory. This is the directory which will contain other directories (based on the parameter 'dirformat'), which in turn will contain the files.

    dirformat - A time formatted string following the C library's strftime() function specification on the directory which should contain the file this module runs on. Defaults to '%Y%m%d' which is a YearMonthDate format (with appropriate zero-padding). For example, if a user wanted to have more nested heirarchies, the user could set this parameter to '%Y/%m/%d' in order to get nested directories. Refer to https://docs.python.org/2/library/datetime.html#strftime-and-strptime-behavior for the full list of directives and their respective meanings for this parameter.

Files are stored with the naming convention <seconds since Epoch>_<ephemeral ID>_<uuid>. These three fields are all obtained from the ScanObject instance (defined in laikaboss/objectmodel.py). In order to guarantee atomicity of file scanning, files are first stored in a temporary directory (like "/tmp"), written, and then moved over to the final directory. This allows APIs like Python's watchdog to fire events like "onCreated" and not have to worry about whether or not the file is completely written or not.


Examples:

    Case:
        STORE_FILE(storagedir=/tmp/laikaboss_store_file,dirformat=%Y%m%d) run on file on March 17, 2017.
    Resulting path of directory in which file is stored:
        /tmp/laikaboss_store_file/20170317/

    Case:
        STORE_FILE(storagedir=/home/users/johnsmith/elephants_are_great,dirformat=%Y/%m/%d) run on file on December 7, 2004.
    Resulting path of directory in which file is stored:
        /home/users/johnsmith/elephants_are_great/2004/12/07/



Sandia National Labs

'STORE_FILE is the module that Laikaboss needs but not the one it deserves right now.'

"""

import logging
import os
import datetime
import shutil

from laikaboss.util import get_option
from laikaboss.si_module import SI_MODULE

def _make_dir(dir_path):
    try:
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)
        elif not os.path.isdir(dir_path):
            os.remove(dir_path)
            os.makedirs(dir_path)
    except OSError as e:
        logging.error('STORE_FILE: OSError (%s)', str(e))
        raise
    except Exception as e:
        logging.error('STORE_FILE: Error making directory (%s)', str(e))
        raise

class STORE_FILE(SI_MODULE):

    def __init__(self):

        self.module_name = "STORE_FILE"
        self.storage_dir = "/data/laikaboss_store_file"
        self.tmp_dir = "/tmp/laikaboss_store_file_tmp"

    def _run(self, scanObject, result, depth, args):

        # Get parameters
        storage_dir = get_option(args, 'storagedir', 'storagedir', self.storage_dir)
        tmp_dir = get_option(args, 'tmpdir', 'tmpdir', self.tmp_dir)
        dir_format = get_option(args, 'dirformat', 'dirformat', '%Y%m%d')

        # Create directories
        file_dir = self._check_dirs_exist(storage_dir, dir_format)
        tmp_dir = self._check_dirs_exist(tmp_dir, dir_format)

        if not file_dir:
            logging.error('%s: Error in creating directory hierarchy.', self.module_name)
            return []

        filename = '%d_%s_%s' % (scanObject.scanTime, scanObject.ephID, scanObject.uuid)

        # Get tmp dir path and full file path and then write to disk
        tmp_file_path = os.path.join(tmp_dir, filename)
        full_file_path = os.path.join(file_dir, filename)
        self._write_file(tmp_file_path, full_file_path, scanObject.buffer)

        logging.debug('%s: Stored file at (%s)', self.module_name, full_file_path)

        # This module should not have any children
        return []

    @staticmethod
    def _check_dirs_exist(storage_dir, dir_format):

        now = datetime.datetime.now()

        # Get our directory format based on custom formatted string
        str_custom_date_folder_format = now.strftime(dir_format)
        file_dir = os.path.join(storage_dir, str_custom_date_folder_format)

        # Make the directory if it does not yet exist
        if not os.path.exists(file_dir):
            try:
                _make_dir(file_dir)
            except Exception as e:
                return None

        return file_dir

    @staticmethod
    def _write_file(tmp_file_path, full_file_path, data):
        '''
        Writes file to disk. Assumes that full_file_path is unique.
        '''
        try:
            # First write to temporary directory
            fh = open(tmp_file_path, 'wb')
            fh.write(data)
            fh.close()

            # Move file to full directory
            shutil.move(tmp_file_path, full_file_path)
        except Exception as e:
            logging.error('STORE_FILE: Error writing file (%s)', str(e))
