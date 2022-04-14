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


class EXPLODE_PACKAGE(SI_MODULE):
    
    def __init__(self,):
        self.module_name = "EXPLODE_PACKAGE"

    def _run(self, scanObject, result, depth, args):
        moduleResult = [] 

        flags = []
        
        offset = int(get_option(args, 'offset', 'explodepackageoffset', 0))
        
        errorState = ""

        buffer = scanObject.buffer
        fileName = "package_child"
        filePath = ""

        if (len(buffer) > (offset + 4)):
            try:
                #entireFileSize = struct.unpack('<I', buffer[offset:offset + 4])[0]
                #unknownFieldOne = buffer[offset + 4:offset + 6]
                version = struct.unpack('<I', buffer[offset:offset + 4])[0]
                offset = offset + 4
                scanObject.addMetadata(self.module_name, "version", version)
                
                logging.debug("EXPLODE_PACKAGE:version")

                formatId = struct.unpack('<I', buffer[offset:offset+4])[0]
                offset = offset + 4
                scanObject.addMetadata(self.module_name, "formatId", formatId)
                
                logging.debug("EXPLODE_PACKAGE:formatID")
                
                sizeOfClassId = struct.unpack('<I', buffer[offset:offset+4])[0]
                offset = offset + 4

                logging.debug("EXPLODE_PACKAGE:classIDSize")
    
                classId = buffer[offset:offset+sizeOfClassId-1]         # -1 because it is null terminated
                scanObject.addMetadata(self.module_name, "classId", classId)
                # The offset should now be sizeOfClassId further within the file.  
                # I also add 8 because the next 8 bytes are unknown
                offset = offset + sizeOfClassId + 8

                logging.debug("EXPLODE_PACKAGE:classID")

    
                sizeOfPackage = struct.unpack('<I', buffer[offset:offset+4])[0]
                offset = offset + 4
    
                logging.debug("EXPLODE_PACKAGE:sizeOfPackage")

                packageObjectHeader = struct.unpack('<H', buffer[offset:offset+2])[0]
                offset = offset + 2
    
                logging.debug("EXPLODE_PACKAGE:PackageObjectHeader "+str(packageObjectHeader)+ " offset: " + str(offset))

                fileNameSize = buffer.find(b"\x00", (offset)) - offset
                logging.debug("EXPLODE_PACKAGE:fileNameSize" + str(fileNameSize))
                
                if (fileNameSize != -1):
                    try:
                        fileName = buffer[offset:offset + fileNameSize]
                        logging.debug("EXPLODE_PACKAGE:fileName")
                        scanObject.addMetadata(self.module_name, "fileName", fileName)
                        offset = offset + fileNameSize+1        #fileName ends in null so accounting for that byte
        
                        originalFilePathSize = buffer.find(b"\x00", (offset)) - offset
                        if (originalFilePathSize != -1):
                            try:
                                logging.debug("EXPLODE_PACKAGE:origfilepathsize " + str(originalFilePathSize))
                                originalFilePath = buffer[offset:offset + originalFilePathSize]
                                logging.debug("EXPLODE_PACKAGE:origfilepath")
                                scanObject.addMetadata(self.module_name, "originalFilePath", originalFilePath)
                                offset = offset + originalFilePathSize + 1
                    
                                offset = offset + 4     # Another Unknown field
                    
                                targetFilePathSize = struct.unpack('<I', buffer[offset:offset+4])[0]
                                logging.debug("EXPLODE_PACKAGE:targetfilepathsize " + str(targetFilePathSize))
                                offset = offset + 4 

                                targetFilePath = buffer[offset:offset+targetFilePathSize-1]
                                scanObject.addMetadata(self.module_name, "targetFilePath", targetFilePath)
                                offset = offset + targetFilePathSize
                    
                                objectDataSize = struct.unpack('<I', buffer[offset:offset+4])[0]
                                logging.debug("EXPLODE_PACKAGE:objectDataSize %s" %(objectDataSize))
                                scanObject.addMetadata(self.module_name, "objectDataSize", objectDataSize)
                                offset = offset + 4

                                objectData = buffer[offset:offset+objectDataSize]
                                logging.debug("EXPLODE_PACKAGE:objectData")
                                moduleResult.append(ModuleObject(buffer=objectData, externalVars=ExternalVars(filename=fileName)))
                                offset = offset + objectDataSize
                    
                                unicodeTargetFilePathSize = struct.unpack('<I', buffer[offset:offset+4])[0]
                                offset = offset + 4

                                unicodeTargetFilePath = buffer[offset:offset+unicodeTargetFilePathSize*2].decode("utf-16", errors="replace").encode("utf-8")
                                logging.debug("EXPLODE_PACKAGE:unitargetfilepath")
                                scanObject.addMetadata(self.module_name, "unicodeTargetFilePath", unicodeTargetFilePath)
                                offset = offset + unicodeTargetFilePathSize*2
                    
                                unicodeFileNameSize = struct.unpack('<I', buffer[offset:offset+4])[0]
                                offset = offset + 4

                                unicodeFilename = buffer[offset:offset+unicodeFileNameSize*2].decode("utf-16", errors="replace").encode("utf-8")
                                logging.debug("EXPLODE_PACKAGE:unifileName")
                                scanObject.addMetadata(self.module_name, "unicodeFilename", unicodeFilename)
                                offset = offset + unicodeFileNameSize*2
                    
                                unicodeOriginalFilePathSize = struct.unpack('<I', buffer[offset:offset+4])[0]
                                offset = offset + 4

                                unicodeOriginalFilePath = buffer[offset:offset+unicodeOriginalFilePathSize*2].decode("utf-16", errors="replace").encode("utf-8")
                                logging.debug("EXPLODE_PACKAGE:uniorigfilepath")
                                scanObject.addMetadata(self.module_name, "unicodeOriginalFilePath", unicodeOriginalFilePath)
                                offset = offset + unicodeOriginalFilePathSize*2

                                version2 = struct.unpack('<I', buffer[offset:offset+4])[0]
                                scanObject.addMetadata(self.module_name, "version2", version2)
                                offset = offset + 4

                            except Exception as e:
                                errorState=e
                        else:
                            errorState="origFilePathSize eq -1"
                    except Exception as e:
                        errorState=e
            except Exception as e:
                errorState=e
        else:
            errorState="file is empty"

        if errorState:
            scanObject.addFlag('package:error_parsing')
            logging.debug("EXPLODE_PACKAGE: Parsing Error: %s" %(errorState))

        return moduleResult
