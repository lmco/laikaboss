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
#A module to analyze.iqy files

#import classes and helpers from the Laika framework
from laikaboss.si_module import SI_MODULE

class META_IQY(SI_MODULE):
    '''Laika module for collecting metadata from .iqy files'''

    def __init__(self):
        '''init, module name'''
        self.module_name = "META_IQY"

    def _run(self, scanObject, result, depth, args):
        '''add metadata and return result (empty)'''
        s = scanObject.buffer
        index_one = s.index(b"1") #urls start after WEB1 or WEB\n1\n
        newline = b'\n' #urls end with a newline

        url = s[index_one+1:s.index(newline,index_one+2)]
        if url[:1] == newline: url=url[1:] #shave off newline if necessary

        scanObject.addMetadata(self.module_name,"url",url)

        moduleResult = []
        return moduleResult

    def _close(self):
        '''nothing to be done here'''
        pass
