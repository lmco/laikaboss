# Copyright 2015 Lockheed Martin Corporation
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
import StringIO
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
        file = StringIO.StringIO()
        file.write(scanObject.buffer)
        file.flush()
        file.seek(0)
        ole = olefile.OleFileIO(file)
        
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
            except (QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError):
                raise
            except:
                log_module("MSG", self.module_name, 0, scanObject, result, "ERROR EXTRACTING STREAM: "+str(stream))
        ole.close()
        file.close()
        return moduleResult
