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
import json

class LISTCHECK(SI_MODULE):
    def __init__(self,):
        self.module_name = "LISTCHECK"
        self.lists = {}
        
    def _run(self, scanObject, result, depth, args):
        moduleResult = [] 
        blacklist = None
        datareloaded = False
        
        if 'list' in args and 'flagPrefix' in args:
            
            if args['list'] not in self.lists:
                json_data=open(args['list'])
                thisList = {}
                thisList['flagPrefix'] = str(args['flagPrefix'])
                thisList['list'] = json.load(json_data)
                self.lists[args['list']] = thisList
                json_data.close()
                
            
            
            if scanObject.objectHash in self.lists[args['list']]['list']['type']['md5']:
                scanObject.addMetadata(self.module_name, 'list', args['list'])
                scanObject.addFlag(self.lists[args['list']]['flagPrefix']+scanObject.objectHash)
                
        return moduleResult
            
            
            
            
            
            
