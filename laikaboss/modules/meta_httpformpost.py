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
# Laika module for capturing form metadata

from future import standard_library
standard_library.install_aliases()
import logging
import urllib.parse

#Laika imports
from laikaboss.objectmodel import ExternalVars, ModuleObject, ScanObject
from laikaboss.si_module import SI_MODULE

class META_HTTPFORMPOST(SI_MODULE):
    '''
    A Laika module to extract HTTP form fields and output them as metadata
    
    Expects the form submission to be in the buffer of the scan object in x-www-form-urlencoded format
    '''
    
    def __init__(self):
        self.module_name = "META_HTTPFORMPOST"
        self.metadata_name = "META_WWWFORM"

    def _run(self, scanObject, result, depth, args):
        moduleResult = []
        queryString = scanObject.buffer
        formFields = urllib.parse.parse_qs(queryString, keep_blank_values=1)
        for field in formFields:
            scanObject.addMetadata(self.metadata_name, field, formFields[field])
        return moduleResult
