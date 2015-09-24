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
from laikaboss.si_module import SI_MODULE
from laikaboss import config
import exiftool
import tempfile
import os


class META_EXIFTOOL(SI_MODULE):
    '''
    Input: A file that is supported by EXIF Tool
    Output: None. Adds module metadata about the object.

    Purpose: Extract metadata from various types of objects that EXIF Tool supports.   
    '''
    def __init__(self,):
        self.module_name = "META_EXIFTOOL" 
        self.TEMP_DIR = '/tmp/laikaboss_tmp'
        if hasattr(config, 'tempdir'):
            self.TEMP_DIR = config.tempdir.rstrip('/')
        if not os.path.isdir(self.TEMP_DIR):    
            os.mkdir(self.TEMP_DIR)
            os.chmod(self.TEMP_DIR, 0777)

    def _run(self, scanObject, result, depth, args):
        moduleResult = [] 
        metaDict = {}
        with tempfile.NamedTemporaryFile(dir=self.TEMP_DIR) as temp_file:
            temp_file_name = temp_file.name
            temp_file.write(scanObject.buffer)
            temp_file.flush() 
            with exiftool.ExifTool() as et:
                metaDict = et.get_metadata(temp_file_name)
            if metaDict:
                for k,v in metaDict.iteritems():
                    scanObject.addMetadata(self.module_name, k, v)

        return moduleResult

