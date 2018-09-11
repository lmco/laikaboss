# Original work Copyright 2015 Lockheed Martin Corporation
# Modified work Copyright 2017 Kemp Langhorne (orphan entry Oletools integration)
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
import olefile
from laikaboss.objectmodel import ModuleObject, ExternalVars, QuitScanException, \
                                GlobalScanTimeoutError, GlobalModuleTimeoutError
from laikaboss.util import log_module
from laikaboss.si_module import SI_MODULE

class EXPLODE_OLE(SI_MODULE):
    def __init__(self,):
        self.module_name = "EXPLODE_OLE" 
        self.global_search = "GLOBAL_SEARCH"
    def _run(self, scanObject, result, depth, args):
        moduleResult = []
        minFileSize = 0 #Explode everything!
        useUnvalidatedFilenames = 0
        if 'minFileSize' in args:
            try:
                minFileSize = int(args['minFileSize'])
            except (QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError):
                raise
            except:
                pass 
        if 'useUnvalidatedFilenames' in args:
            try:
                minFileSize = int(args['useUnvalidatedFilenames'])
            except (QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError):
                raise
            except:
                pass 
        try:
            ole = olefile.OleFileIO(scanObject.buffer)
            
            lstStreams = ole.listdir()
            numStreams = 0
            for stream in lstStreams:
                try:
                    if ole.get_size(stream) >= minFileSize:
                        numStreams += 1
                        streamF = ole.openstream(stream)
                        childBuffer = streamF.read()
                        if childBuffer:
                            filename = "e_ole_stream_"+str(numStreams)
                            try:
                                u = unicode( str(stream), "utf-8" )
                                filename = u.encode( "utf-8" )
                                
                            except (QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError):
                                raise
                            except:
                                pass #keep ole_stream_number as filename
                            moduleResult.append(ModuleObject(buffer=childBuffer, 
                                                             externalVars=ExternalVars(filename=filename)))
                except IOError as e:  # exceptions from ole import will raise
                    log_module("MSG", self.module_name, 0, scanObject, result, "ERROR EXTRACTING STERAM: "+str(entrynum)+" "+str(e))
                except (QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError):
                    raise
                except:
                    log_module("MSG", self.module_name, 0, scanObject, result, "ERROR EXTRACTING STREAM: "+str(stream))
            
            # Orphan entry Oletools integration
            # Based on decalage2 code in oletools/oletools/oledir.py
            # Tested with olefile 0.45dev1
            
            # Object type lookup table - type names from decalage2 olefile
            objecttype = {}
            objecttype[0] = "DIRECORY_EMPTY"
            objecttype[1] = "STORAGE"
            objecttype[2] = "STREAM"
            objecttype[3] = "ILOCKBYTES"
            objecttype[4] = "IPROPERTY_STORAGE"
            objecttype[5] = "ROOT_STORAGE"
            
            # Read all of the directory entries and only output the ones that are not used or orphans
            for entrynum in range(len(ole.direntries)): # read all directory entries
                try:
                    directoryentry = ole.direntries[entrynum]
                    if directoryentry is None: # means entry is not used or is orphan which means it will not be extracted by above listdir
                        directoryentry = ole._load_direntry(entrynum)
                        entrydata = ole._open(directoryentry.isectStart, directoryentry.size).read()
                        if entrydata: #if there is data after read
                            objecttypefriendlyname = objecttype.get(directoryentry.entry_type, "UNKNOWN") # see above lookup table
                            filename = "e_ole_orphan_"+str(entrynum)+"_"+objecttypefriendlyname+"_"+directoryentry.name
                            filename = filename.encode('utf-8').decode('ascii','ignore') # probably a better way to do this...
                            moduleResult.append(ModuleObject(buffer=entrydata, 
                                                             externalVars=ExternalVars(filename=filename)))                        
                            #print(entrynum, directoryentry.entry_type, directoryentry.name)
                except IOError as e:  # exceptions from ole import will raise
                    log_module("MSG", self.module_name, 0, scanObject, result, "ERROR EXTRACTING ORPHAN: "+str(entrynum)+" "+str(e))
                            
                except (QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError):
                    raise
                except:
                    log_module("MSG", self.module_name, 0, scanObject, result, "ERROR EXTRACTING ORPHAN: "+str(entrynum))
            
            ole.close()
        except IOError as e:  # exceptions from ole import will raise
            log_module("MSG", self.module_name, 0, scanObject, result, "ERROR OPENING OLE "+str(e))
        return moduleResult
