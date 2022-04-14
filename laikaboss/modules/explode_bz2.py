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
This module decompresses bz2 files which utilize bzip2.

Sandia National Labs
'''

from laikaboss.objectmodel import ModuleObject, ExternalVars
from laikaboss.si_module import SI_MODULE
from laikaboss.util import get_option
import bz2
import logging


class EXPLODE_BZ2(SI_MODULE):
    def __init__(self,):
        self.module_name = "EXPLODE_BZ2"
    def _run(self, scanObject, result, depth, args):
        moduleResult = []

        byte_limit = int(get_option(args, 'bytelimit', 'bz2bytelimit', 0))

        try:
            self._decompress_file(self, moduleResult, scanObject, byte_limit)
        except Exception as E:
            logging.exception("Problem decompressing the file %s: (%s)" %(scanObject.filename, E))
            scanObject.addFlag("bz2:DECOMPRESS_ERROR")
            raise


        return moduleResult

    #  These private methods are set to static to ensure immutability since
    #  they may be called more than once in the lifetime of the class
    @staticmethod
    def _decompress_file(self, moduleResult, scanObject, byte_limit):
        '''
        Attempts to decompress the file

        Arguments:
        moduleResult -- an instance of the ModuleResult class created above
        scanObject -- an instance of the ScanObject class, created by the dispatcher
        byte_limit -- the maximum size in bytes for an exploded buffer, adds flag if exceeded

        Returns:
        Nothing, modification made directly moduleResult.
        '''
        filename = scanObject.filename
        buff = scanObject.buffer
        decompressor = bz2.BZ2Decompressor()
        exceeded_byte_limit = False

        #TODO decompress by chunks and compare overall size to byte_limit (if set) instead of doing it all at one go
        #get decompressed file contents
        bz2_out = decompressor.decompress(buff)
        size = len(bz2_out)

        scanObject.addMetadata(self.module_name, "Total_Size", size)
        
        #if byte_limit was set
        if byte_limit and size > byte_limit:
            logging.debug("EXPLODE_BZ2: skipping file due to byte limit")
            exceeded_byte_limit = True

        if exceeded_byte_limit:
            scanObject.addFlag("bz2:BYTE_LIMIT_EXCEEDED")
        else:
            moduleResult.append(ModuleObject(buffer=bz2_out, externalVars=ExternalVars(filename="e_bz2_%s" % size)))

