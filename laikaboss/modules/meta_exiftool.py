# Copyright 2015 Lockheed Martin Corporation
# Copyright 2020 National Technology & Engineering Solutions of Sandia, LLC 
# (NTESS). Under the terms of Contract DE-NA0003525 with NTESS, the U.S. 
# Government retains certain rights in this software.
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
from laikaboss.util import get_option, laika_temp_dir
import exiftool
import tempfile
import os
import json


class META_EXIFTOOL(SI_MODULE):
    '''
    Input: A file that is supported by EXIF Tool
    Output: None. Adds module metadata about the object.

    Purpose: Extract metadata from various types of objects that EXIF Tool supports.   
    '''
    def __init__(self,):
        self.module_name = "META_EXIFTOOL" 
        self.filtered_keys = set(['File:FileName', 'File:Directory', 'File:FilePermissions', \
                'File:FileInodeChangeDate', 'File:FileModifyDate', 'File:FileAccessDate', \
                'File:FileSize', 'SourceFile', 'ExifTool:ExifToolVersion' ])

    def _run(self, scanObject, result, depth, args):
        moduleResult = [] 
        metaDict = {}

        limit = int(get_option(args, 'limit', 'metaexiftoollimit', 100))

        with laika_temp_dir() as temp_dir, tempfile.NamedTemporaryFile(dir=temp_dir) as temp_file:
            temp_file_name = temp_file.name
            temp_file.write(scanObject.buffer)
            temp_file.flush() 
            with exiftool.ExifTool() as et:
                metaDict = json.loads(et.execute(b"-j",exiftool.fsencode(temp_file_name)).decode("utf-8", errors="replace"))[0]
            if metaDict:
                i = 0
                for k,v in metaDict.items():
                    if k not in self.filtered_keys:
                        if not (k == "ExifTool:Error" and v == "Unknown file type"):
                            scanObject.addMetadata(self.module_name, k, v)
                            i = i + 1
                            if i >= limit:
                                scanObject.addFlag("exiftool:LIMIT_EXCEEDED")
                                break

        return moduleResult

