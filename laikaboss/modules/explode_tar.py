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
# This module decompresses tar files
# Sandia National Labs

from future import standard_library
standard_library.install_aliases()
from laikaboss.objectmodel import ModuleObject, ExternalVars
from laikaboss.si_module import SI_MODULE
from laikaboss.util import get_option
import tarfile
import logging
import io


class EXPLODE_TAR(SI_MODULE):
    def __init__(self,):
        self.module_name = "EXPLODE_TAR"
    def _run(self, scanObject, result, depth, args):
        moduleResult = []

        file_limit = int(get_option(args, 'filelimit', 'tarfilelimit', 0))
        byte_limit = int(get_option(args, 'bytelimit', 'tarbytelimit', 0))

        try:
            self._decompress_file(self, moduleResult, scanObject, file_limit, byte_limit)
        except Exception as E:
            logging.exception("Problem decompressing the file %s: (%s)" %(scanObject.filename, E))
            scanObject.addFlag("tar:DECOMPRESS_ERROR")
            raise

        return moduleResult

    #  These private methods are set to static to ensure immutability since
    #  they may be called more than once in the lifetime of the class
    @staticmethod
    def _decompress_file(self, moduleResult, scanObject, file_limit, byte_limit):
        '''
        Attempts to decompress the file

        Arguments:
        moduleResult -- an instance of the ModuleResult class created above
        scanObject -- an instance of the ScanObject class, created by the dispatcher
        file_limit -- the maximum number of files for an exploded tar, adds flag if exceeded
        byte_limit -- the maximum size in bytes for an exploded buffer, adds flag if exceeded

        Returns:
        Nothing, modification made directly moduleResult.
        '''
        filename = scanObject.filename
        buff = scanObject.buffer
        exceeded_byte_limit = False

        # get decompressed file contents
        tar_file = tarfile.TarFile(name=filename, mode='r', fileobj=io.BytesIO(buff))

        num_files = 0
        for tar_filename in sorted(tar_file.getnames()):
            member = tar_file.getmember(tar_filename)
            tar_member = tar_file.extractfile(member)
            num_files += 1
            # could be read permissions
            if tar_member is None:
                scanObject.addFlag("tar:NONETYPE_FOUND")
                logging.debug("EXPLODE_TAR: NoneType found")
                continue
            tar_out = tar_member.read()

            scanObject.addMetadata(self.module_name, "filename", member.name)
            scanObject.addMetadata(self.module_name, "size", member.size)
            scanObject.addMetadata(self.module_name, "modification_time", member.mtime)
            scanObject.addMetadata(self.module_name, "permission_bits", member.mode)
            scanObject.addMetadata(self.module_name, "uid", member.uid)
            scanObject.addMetadata(self.module_name, "gid", member.gid)
            scanObject.addMetadata(self.module_name, "uname", member.uname)
            scanObject.addMetadata(self.module_name, "gname", member.gname)

            if byte_limit and member.size > byte_limit:
                logging.debug("EXPLODE_TAR: skipping file due to byte limit")
                exceeded_byte_limit = True
            else:
                moduleResult.append(ModuleObject(buffer=tar_out, externalVars=ExternalVars(filename="e_tar_%s" % member.size)))

            # if file_limit was set
            if file_limit and num_files > file_limit:
                scanObject.addFlag("tar:FILE_LIMIT_EXCEEDED")
                logging.debug("EXPLODE_TAR: breaking due to file limit")
                exceeded_file_limit = True
                break

        if exceeded_byte_limit:
            scanObject.addFlag("tar:BYTE_LIMIT_EXCEEDED")
                
