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
from laikaboss.objectmodel import ModuleObject, ExternalVars, QuitScanException, \
                                GlobalScanTimeoutError, GlobalModuleTimeoutError
from laikaboss.si_module import SI_MODULE
from laikaboss import config
import tempfile
import pexpect
import os

class EXPLODE_UPX(SI_MODULE):
    '''a module that decompresses upx compressed executables'''
    def __init__(self,):
        ''' __init__ function merely needs to set its module_name and nothing more'''
        self.module_name = "EXPLODE_UPX" 
        self.TEMP_DIR = '/tmp/laikaboss_tmp'
        if hasattr(config, 'tempdir'):
            self.TEMP_DIR = config.tempdir.rstrip('/')
        if not os.path.isdir(self.TEMP_DIR):
            os.mkdir(self.TEMP_DIR)
            os.chmod(self.TEMP_DIR, 0777)

    def _run(self, scanObject, result, depth, args):
        ''' The core of your laika module. This is how your code will be invoked
            
            Requires:
                Package Dependencies Only
            Assumes:
                scanObject.buffer is a upx compressed executable
            Ensures:
                1. No propagating errors
                2. Decompressed buffer is returned as a new buffer to scanned
            Error Handling:
                1. If upx decompress fails, output file will not be created
                   attempt to open the decompressed file will throw file not exists exception
                   silently passed
            Module Execution:
                1. Dump the scanObject.buffer into a named temp file
                2. Call upx decompresser outputting to the <input_filename>_output
                3. Open the decompressed buffer file and read it into a buffer
                4. Close and delete the decompressed buffer file
                5. If length of the decompressed buffer is > the compressed buffer (decompression worked):
                   True:  Add the buffer to the result object
                   False: Do nothing (future perhaps add failed to decompress metadata?)
                6. Return
        '''
        moduleResult = []
        try:
            with tempfile.NamedTemporaryFile(dir=self.TEMP_DIR) as temp_file_input:
                temp_file_input_name = temp_file_input.name
                temp_file_input.write(scanObject.buffer)
                temp_file_input.flush() 
                temp_file_output_name = temp_file_input_name+"_output"
                strCMD = "upx -d "+temp_file_input_name+" -o "+temp_file_output_name
                outputString = pexpect.run(strCMD)
                f = open(temp_file_output_name) #if strCMD failed, this will throw a file not exists exception
                newbuf = f.read()
                f.close()
                os.remove(temp_file_output_name)
                if len(newbuf) > len(scanObject.buffer):
                    moduleResult.append(ModuleObject(buffer=newbuf, externalVars=ExternalVars(filename="e_upx")))
        except (QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError):
            raise
        except:
            pass
        return moduleResult
