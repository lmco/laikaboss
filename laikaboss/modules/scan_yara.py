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
from past.builtins import unicode
import logging

from laikaboss.si_module import SI_MODULE
from laikaboss.util import yara_on_demand, log_module, get_option
from laikaboss import config


class SCAN_YARA(SI_MODULE):
    def __init__(self,):
        self.module_name = "SCAN_YARA"
    def _run(self, scanObject, result, depth, args):
        moduleResult = []
        maxBytes = 0

        # Adds strings from matches to metadata
        print_strings_limit = int(get_option(args, 'printstrings', 'scanyaraprintstrings', 0))

        # Add context around matched strings to metadata
        # ie. An input of 10 would give the 10 characters before and after a match as well
        match_context_limit = int(get_option(args, 'matchcontext', 'scanyaramatchcontext', 0))

        args_externalVars = []
        if 'ext_vars' in args:
            args_externalVars = args['ext_vars'].split(';')

        # Build the external vars from other modules' input
        # If the key is not in args, don't use it
        externalVars = {}
       
        tmp_externalVars = scanObject.getMetadata('SCAN_YARA', 'ExternalVars')
        if tmp_externalVars:
            # Due to how the framework works, ExternalVars may be a dictionary or a list of dictionaries
            # If it is neither, then the module writer did it wrong
            if isinstance(tmp_externalVars, dict):
                externalVars = self.getExternals(args_externalVars, tmp_externalVars)
            elif isinstance(tmp_externalVars, list):
                for externalVars_item in externalVars:
                    if isinstance(externalVars_item, dict):
                        externalVars.update(self.getExternals(args_externalVars, externalVars_item))
        else:
            externalVars = self.getExternals(args_externalVars, {})


        extVars_used = scanObject.getMetadata('SCAN_YARA', 'ExternalVars Used')
        # If any of the fields in externalVars have data, add to metadata for future verification/analysis
        if any([externalVars[x] if externalVars[x] != 'None' else '' for x in externalVars.keys()]) \
          and not extVars_used:
            scanObject.addMetadata(self.module_name, 'ExternalVars Used', list(externalVars.keys()))

        # Max bytes, if set in dispatcher, allows us to truncate the buffer
        if 'maxbytes' in args:
            try:
                maxBytes = int(args['maxbytes'])
            except ValueError:
                maxBytes = 0

        # Check for a custom rule set in dispatcher arguments 
        if 'rule' in args:
            sig_filepath = '%s%s' % (config.yarasigspath, args['rule'])
            if 'meta_scan' in args:
                metaBuffer = self._getnested(scanObject.moduleMetadata, args['meta_scan'])
                # If we can't find the desired metadata, just return.
                if not isinstance(metaBuffer, str):
                    return moduleResult
                matches = yara_on_demand(sig_filepath, metaBuffer, externalVars=externalVars)
            elif maxBytes and scanObject.objectSize > maxBytes:
                matches = yara_on_demand(sig_filepath, buffer(scanObject.buffer, 0, maxBytes), externalVars=externalVars)
            else:
                matches = yara_on_demand(sig_filepath, scanObject.buffer, externalVars=externalVars)
        # Use the default rule set
        else:
            if 'meta_scan' in args:
                metaBuffer = self._getnested(scanObject.moduleMetadata, args['meta_scan'])
                # If we can't find the desired metadata, just return.
                if not isinstance(metaBuffer, str):
                    return moduleResult
                matches = yara_on_demand(config.yarascanrules, metaBuffer, externalVars=externalVars)
            elif maxBytes and scanObject.objectSize > maxBytes:
                matches = yara_on_demand(config.yarascanrules, buffer(scanObject.buffer, 0, maxBytes), externalVars=externalVars)
            else:
                matches = yara_on_demand(config.yarascanrules, scanObject.buffer, externalVars=externalVars)

        print_strings = []

        # Process results
        for m in matches:
            if m.meta: 
                scanObject.addMetadata(self.module_name, str(m), m.meta)
            scanObject.addFlag("yr:%s" % str(m))
            #scanObject.addFlag("s_yr::%s" % str(m))  # Placeholder for standardized flag format

            # Get matched strings with context
            if m.strings:
                for matched_string in m.strings:
                    if len(print_strings) < print_strings_limit:
                        matched_string_dict = {}
                        if match_context_limit > 0:
                            start = matched_string[0] - match_context_limit
                            end = matched_string[0] + len(matched_string[2]) + match_context_limit
                            matched_string_dict['offset'] = start
                            matched_string_dict['matched_string'] = scanObject.buffer[start:end]
                        else:
                            matched_string_dict['offset'] = matched_string[0]
                            matched_string_dict['matched_string'] = matched_string[2]
                        matched_string_dict['rule'] = m.rule 
                        matched_string_dict['string_identifier'] = matched_string[1]
                        print_strings.append(matched_string_dict)

        if print_strings:
            scanObject.addMetadata(self.module_name, 'Matched_Strings', print_strings)


        return moduleResult

    def _cleanValue(self, value):
        newValue = 'None'
        if isinstance(value,str):
             newValue = value or 'None'
        elif isinstance(value,unicode):
            newValue = value.encode('utf8') or 'None'
        elif isinstance(value,(int,bool)):
            newValue = value
        elif type(value) is list:
            newList = []
            for l in value:
                newList.append(self._cleanValue(l))
            newValue = repr(newList)
        #else:
        #    log_module("MSG", self.module_name, 0, scanObject, result, "External variables for this object have an unsupported type.")
        return newValue
        
    # Method to pull specific key/values out of a dictionary
    def getExternals(self, args_externalVars, tmp_externalVars):
        externalVars = {}

        # For all items submitted by other modules, make sure that they are listed in args
        for key, value in tmp_externalVars.items():
            if any([x == key for x in args_externalVars]):
                externalVars[key] = self._cleanValue(value)

        # For any arguments passed, but not set by other modules, default them
        for x in args_externalVars:
            if x not in externalVars:
                externalVars[x] = 'None'
        logging.debug('EXTERNAL VARS: %s' % externalVars)
        return externalVars

    @staticmethod
    def _getnested( dictionary, location ):
        return_value = dictionary
        for key in location.split("."):
            if key in return_value:
                return_value = return_value[key]
            else:
                return_value = None
                break
        return return_value        
