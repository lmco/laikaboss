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
from laikaboss.objectmodel import ModuleObject
from laikaboss.si_module import SI_MODULE
from laikaboss.util import get_scanObjectUID, yara_on_demand, \
                         log_module, log_module_error
from laikaboss import config
from yara import SyntaxError

class DISPOSITIONER(SI_MODULE):
    def __init__(self,):
        self.module_name = "DISPOSITIONER" 
    def _run(self, scanObject, result, depth, args):
        #Initialization
        moduleResult = [] 
        verbose = False
        resultDict = {}
        strMatches = ""
        
        #Read arguments
        if 'verbose' in args:
            verbose = True 
        
        #Populate static metadata
        resultDict['Disposition_File'] = config.yaradispositionrules
        resultDict['Result'] = "Disposition Not Initialized"
        
        #Get scanObject uID for flag_rollup and rollup flags
        myUID = get_scanObjectUID(scanObject)
        flag_rollup = self._rollupToMe(result, myUID )
        resultDict['Input_Flags'] = flag_rollup
        
        if verbose: log_module("MSG", self.module_name, 0, scanObject, result, msg="dispositon_email: flag rollup: %s" % flag_rollup)
        try:
            matches = yara_on_demand(config.yaradispositionrules, ' '.join(flag_rollup))
            lstStrMatches = [str(match) for match in matches]
            resultDict['Matches'] = lstStrMatches
            if matches:
                strMatches = ' '.join(lstStrMatches)
        except SyntaxError:
            log_module_error(self.module_name, scanObject, result, "Error Compiling YARA rules file at: "+config.yaradispositionrules)
            resultDict['Result'] = "YARA RULE SYNTAX ERROR"
        
        resultDict['Result'] = "Accept"
        for match in resultDict['Matches']:
            if match.startswith("Deny"):
                resultDict['Result'] = "Deny"
                
                
            
        scanObject.addMetadata(self.module_name, 'Disposition', resultDict)
        return moduleResult
    
    
    @staticmethod
    def _rollupToMe(result, myuID):
        flag_rollup = []
        for uid, sO in result.files.iteritems():
            if uid == myuID:
                for flag in sO.flags: flag_rollup.append(flag)
            elif sO.parent == myuID: #if my direct child
                if "DISPOSITIONER" in sO.moduleMetadata:
                    if "Input_Flags" in sO.moduleMetadata["DISPOSITIONER"]["Disposition"]:
                        flag_rollup.extend(sO.moduleMetadata["DISPOSITIONER"]["Disposition"]["Input_Flags"])
                else:
                    log_module_error("DISPOSITIONER", sO, result, "Child object does not have DISPOSITIONER metadata")
        flag_rollup = list(set(flag_rollup)) # Make Unique
        return flag_rollup
    
    
    
    
    
    
    
    
    
