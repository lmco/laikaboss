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

import sys, hashlib, traceback, logging
import struct

from laikaboss.si_module import SI_MODULE
from laikaboss.util import get_scanObjectUID, getRootObject, get_option
from laikaboss.objectmodel import ModuleObject, ExternalVars, QuitScanException, \
                                GlobalScanTimeoutError, GlobalModuleTimeoutError

import os


class EXPLODE_PERSISTSTORAGE(SI_MODULE):
    
    def __init__(self,):
        self.module_name = "EXPLODE_PERSISTSTORAGE"

    def _run(self, scanObject, result, depth, args):
        moduleResult = [] 

        flags = []
        
        offset = int(get_option(args, 'offset', 'explodepersiststorageoffset', 0))

        errorState = False

        buffer = scanObject.buffer
        fileName = "contents_child"

        if (len(buffer) > (offset + 8) and buffer[offset:(offset + 4)] == b'fUfU'): 
            fileSize = struct.unpack('<I', buffer[(offset + 4):(offset + 8)])[0]

#            moduleResult.append(ModuleObject(buffer=buffer[(offset + 8):(offset + 8 + fileSize)],externalVars=ExternalVars(filename="contents_child")))

            metadata = offset + 8 + fileSize

            width = struct.unpack('<I', buffer[(metadata + 4):(metadata+8)])[0]
            height = struct.unpack('<I', buffer[(metadata + 8):(metadata + 12)])[0]

            if (buffer[(metadata+12):(metadata+14)] == b"\x08\x00"):

                fieldOneSize = struct.unpack('<I', buffer[(metadata + 14):(metadata + 18)])[0]

                # fieldOne = is not needed

                if (buffer[(metadata + 18 + fieldOneSize):(metadata + 18 + fieldOneSize + 2)] == b"\x08\x00"):
                    
                    fileNameSize = struct.unpack('<I', buffer[(metadata + 18 + fieldOneSize + 2):(metadata + 18 + fieldOneSize + 2 + 4)])[0]

                    fileName = buffer[(metadata + 18 + fieldOneSize + 2 + 4):(metadata + 18 + fieldOneSize + 2 + 4 + fileNameSize - 2)].decode("utf-16", errors="replace").encode("utf-8")

                    fileNameOffset = metadata+18
                    scanObject.addMetadata(self.module_name, "filename offset", fileNameOffset)
                    scanObject.addMetadata(self.module_name, "filename", fileName)

                else:
                    errorState=True

            else:
                errorState=True
                
            scanObject.addMetadata(self.module_name, "width", width) 
            scanObject.addMetadata(self.module_name, "height", height) 

            moduleResult.append(ModuleObject(buffer=buffer[(offset + 8):(offset + 8 + fileSize)],externalVars=ExternalVars(filename=fileName)))

        else:
            errorState=True
       
        if(errorState==True):
            scanObject.addFlag('persiststorage:error_parsing')
            logging.debug("EXPLODE_PERSISTSTORAGE: Parsing Error")


        return moduleResult
