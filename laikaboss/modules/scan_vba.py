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
'''
This module scans a VBA buffer and attempts to detect potentially malicious properties

Requires oletools 0.55.dev2 or higher

Sandia National Labs
'''

from oletools.olevba import VBA_Scanner, VBA_Parser
from oletools.mraptor import MacroRaptor
import logging

from laikaboss.objectmodel import ModuleObject, ExternalVars
from laikaboss.si_module import SI_MODULE

class SCAN_VBA(SI_MODULE):
    
    def __init__(self):
        self.module_name = 'SCAN_VBA'
        self.max_script_size = 102400 #100 KB

    def _run(self, scanObject, result, depth, args):
        moduleResult = []
        #Only run deobfuscator on short scripts
        deobfuscate = False
        if len(scanObject.buffer) < self.max_script_size:
            deobfuscate = True
        #Scanned code needs to be a native string
        vba_code = scanObject.buffer
        if not isinstance(vba_code, str):
            vba_code = vba_code.decode('latin1') #Module aborts if error
        #Run VBA_Scanner on the vba
        vba_scanner = VBA_Scanner(vba_code)
        results = vba_scanner.scan(include_decoded_strings=True, deobfuscate=deobfuscate)
        #Variables to more reliably detect obfuscated strings
        obfuscationTypesDetected = 0
        #this might be too much metadata fdr some files
        for item in results:
            scanObject.addMetadata(self.module_name, item[0], item[1])
            if(item[1] == "Hex Strings" or item[1] == "Base64 Strings" or \
                    item[1] == "Dridex Strings" or item[1] == "VBA obfuscated Strings"):
                obfuscationTypesDetected += 1
        summary = vba_scanner.scan_summary()
        #Is it autoexec?
        if summary[0] > 0:
            scanObject.addFlag("macro:AUTOEXEC")
        #Does it have suspicious keywords?
        if summary[1] - obfuscationTypesDetected > 0:
            scanObject.addFlag("macro:SUSPICIOUS_KEYWORDS")
        #Does it have IOCs (probably suspicious)
        if summary[2] > 0:
            scanObject.addFlag("macro:POTENTIAL_IOCS")
        #Does it have any obfuscated strings? (In order: hex, base64, dridex, and strings
        # encoded with misc. VBA functions)
        if summary[3] > 0 or summary[4] > 0 or summary[5] > 0 or summary[6] > 0 or \
                obfuscationTypesDetected > 0:
            scanObject.addFlag("macro:POTENTIAL_OBFUSCATED_STRINGS")
        #Run MacroRaptor over it (note: this is very similar to above functionality)
        mraptor = MacroRaptor(vba_code)
        mraptor.scan()
        if mraptor.suspicious:
            scanObject.addFlag("macro:MRAPTOR_SUSPICOUS")

        return moduleResult
