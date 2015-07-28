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
import tempfile
from laikaboss.objectmodel import ModuleObject, ExternalVars, QuitScanException, \
                                GlobalScanTimeoutError, GlobalModuleTimeoutError
from laikaboss.si_module import SI_MODULE
from laikaboss.util import log_module
import logging
from laikaboss import config
import subprocess
import os
from shutil import rmtree



class TACTICAL(SI_MODULE):
    def __init__(self,):
        self.module_name = "TACTICAL" 
        self.TEMP_DIR = '/tmp/laikaboss_tmp'
        if hasattr(config, 'tempdir'):
            self.TEMP_DIR = config.tempdir.rstrip('/')
        if not os.path.isdir(self.TEMP_DIR):    
            try:
                os.mkdir(self.TEMP_DIR)
                os.chmod(self.TEMP_DIR, 0777)
            except:
                raise
            
    def _run(self, scanObject, result, depth, args):
        logging.debug("tactical: args: %s" % repr(args))
        moduleResult = [] 
        output = ''
        
        script_path = None
        timeout = "30";
        if 'timeout' in args:
            timeout = args['timeout']
        
        # Option to remove directory containing temp files
        unlinkDir = False 
        if 'unlinkDir' in args:
            if args['unlinkDir'].upper() == 'TRUE':
                unlinkDir = True

        #only do something if script is defined in dispatcher--without external script this does nothing        
        if 'script' in args:
            script_path = args['script'] 
        
            #temp_file_h, temp_file_name = tempfile.mkstemp()
            with tempfile.NamedTemporaryFile(dir=self.TEMP_DIR) as temp_file:
                temp_file_name = temp_file.name
            
                temp_file.write(scanObject.buffer)
                temp_file.flush() 
                #use timeout command in the command, if available on the system?
                output = self._collect("timeout %s %s %s %s" % (timeout, script_path, temp_file_name, self.TEMP_DIR), shell=True)
                logging.debug(output)
                tmp_dirs = []
                for line in output.splitlines():
                    #need to process the lines
                    line_type = line[:5]
                    line_value = line[5:].strip()
                    
                    if line_type == "FLAG:":
                        #not doing any validation on the flags, but truncating on length
                        scanObject.addFlag(line_value[:20])
                    elif line_type == "META:":
                        (meta_key, meta_sep, meta_value) = line_value.partition('=')
                        scanObject.addMetadata(self.module_name, meta_key, meta_value)
                    elif line_type == "FILE:":
                        # Check to see if the file is actually a directory (silly 7zip)
                        if os.path.isdir(line_value):
                            # If the file is a directory and we don't already know about it, add it to the list
                            if line_value not in tmp_dirs:
                                tmp_dirs.append(line_value)
                            # Skip this since it's a directory
                            continue
                        # If we don't already know about this directory, add it to the list
                        if os.path.dirname(line_value) not in tmp_dirs:
                            file_path = os.path.dirname(line_value)
                            tmp_dirs.append(file_path)
                        try:
                            with open(line_value, 'r') as result_file:
                                moduleResult.append(ModuleObject(buffer=result_file.read(),externalVars=ExternalVars(filename=os.path.basename(line_value))))
                        except:
                            raise
                        finally:
                            #make sure the incoming file is deleted, or at least we try....
                            logging.debug("Trying to unlink file: %s" % (line_value))
                            os.unlink(line_value)
                    else:
                        pass
                if unlinkDir:
                    logging.debug("Attempting to remove temp directories: %s" % (tmp_dirs))
                    # Loop through the directories and remove them, starting with the deepest level (by length)
                    for tmp_dir in sorted(tmp_dirs, key=len, reverse=True):
                        try:
                            rmtree(tmp_dir)
                        except (QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError):
                            raise
                        except:
                            log_module("MSG", self.module_name, 0, scanObject, result, "Could not remove tmp dir %s" % (tmp_dir))
                            logging.exception("Unable to remove temp directory: %s" % (tmp_dir))

        return moduleResult

    #function to do the whole backtick thing. This is like check_output of python 2.7 without the checking of return value
    @staticmethod
    def _collect(*popenargs, **kwargs):
        process = subprocess.Popen(stdout=subprocess.PIPE, *popenargs, **kwargs)
        output, unused_err = process.communicate()
        process.poll()
        return output    
    

    
