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

_maxpathlen = 100

class EXPLODE_OLENATIVE(SI_MODULE):
    
    def __init__(self,):
        self.module_name = "EXPLODE_OLENATIVE"

    def _run(self, scanObject, result, depth, args):
        moduleResult = [] 

        flags = []
        
        offset = int(get_option(args, 'offset', 'explodeolenativeoffset', 0))

        errorState = False

        buffer = scanObject.buffer
        fileName = "olenative_child"
        filePath = ""

        if (len(buffer) > (offset + 6)):
            entireFileSize = struct.unpack('<I', buffer[offset:offset + 4])[0]
            entireFileSize = entireFileSize+4
            scanObject.addMetadata(self.module_name, "entireFileSize", entireFileSize)
            
            unknownFieldOne = buffer[offset + 4:offset + 6]

            if(offset+7<entireFileSize):
                fileNameOffset = buffer.find(b"\x00", (offset + 6))

                if(fileNameOffset != -1):
                    fileName = buffer[offset + 6: fileNameOffset]
                    scanObject.addMetadata(self.module_name, "fileName", fileName)

                    filePathOffset = buffer.find(b"\x00", (fileNameOffset + 1))
            
                    if(filePathOffset != -1):

                        try:
                            filePath = buffer[fileNameOffset+1:filePathOffset]
                            scanObject.addMetadata(self.module_name, "filePath", filePath)

                            unknownFieldTwo = buffer[filePathOffset+1:filePathOffset+1+4].decode("utf-16", errors="replace").encode("utf-8")

                            filePathSize = struct.unpack('<I', buffer[filePathOffset+1+4:filePathOffset+1+4+4])[0]
                            currentOffset = filePathOffset+1+4+4;
                            tempFilePath = buffer[currentOffset:currentOffset+filePathSize-1]
                            scanObject.addMetadata(self.module_name, "tempFilePath", tempFilePath, maxlen=_maxpathlen)

                            embeddedFileSize = struct.unpack('<I', buffer[currentOffset+filePathSize:currentOffset+filePathSize+4])[0]
                            scanObject.addMetadata(self.module_name, "embeddedFileSize", embeddedFileSize)

                            currentOffset = currentOffset+filePathSize+4

                            embeddedFile = buffer[currentOffset:currentOffset+embeddedFileSize]
                            moduleResult.append(ModuleObject(buffer=embeddedFile, externalVars=ExternalVars(filename=fileName)))

                            currentOffset = currentOffset+embeddedFileSize
                            unicodeTempFilePathSize = struct.unpack('<I', buffer[currentOffset:currentOffset+4])[0]
                            
                            unicodeTempFilePath = buffer[currentOffset+4:currentOffset+4+unicodeTempFilePathSize*2].decode("utf-16", errors="replace").encode("utf-8")
                            scanObject.addMetadata(self.module_name, "unicodeTempFilePath", unicodeTempFilePath)

                            currentOffset = currentOffset+4+unicodeTempFilePathSize*2
                            
                            unicodeFileNameSize = struct.unpack('<I', buffer[currentOffset:currentOffset+4])[0]
                            unicodeFileName = buffer[currentOffset+4:currentOffset+4+unicodeFileNameSize*2].decode("utf-16", errors="replace").encode("utf-8")
                            scanObject.addMetadata(self.module_name, "unicodeFileName", unicodeFileName)

                            currentOffset = currentOffset+4+unicodeFileNameSize*2

                            unicodeFilePathSize = struct.unpack('<I', buffer[currentOffset:currentOffset+4])[0]
                            unicodeFilePath = buffer[currentOffset+4:currentOffset+4+unicodeFilePathSize*2].decode("utf-16", errors="replace").encode("utf-8")
                            scanObject.addMetadata(self.module_name, "unicodeFilePath", unicodeFilePath)
                        except:
                            errorState=True
                    else:
                        errorState=True
                else:
                    errorState=True
            else:
                errorState=True
        else:
            errorState=True
       
        if(errorState==True):
            scanObject.addFlag('olenative:error_parsing')
            logging.debug("EXPLODE_OLENATIVE: Parsing Error")


        return moduleResult
