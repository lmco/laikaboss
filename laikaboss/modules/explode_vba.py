# Copyright 2017 Kemp Langhorne
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
from laikaboss.objectmodel import ModuleObject, ExternalVars, QuitScanException, \
                                GlobalScanTimeoutError, GlobalModuleTimeoutError
from laikaboss.util import log_module
from oletools import olevba

class EXPLODE_VBA(SI_MODULE):
    '''
    Version: 0.50

    Input: Any supported format listed at https://bitbucket.org/decalage/oletools/wiki/olevba

    Output: Extracted and decompressed VBA objects (macro and forms).  Module also adds basic metadata about the object when possible. 

    Purpose: Uses olevba from oletools to extract embedded VBA macro and forms in various types of documents.

    Note 1: olevba has many other features beyond just macro extraction. This module does only extraction.
    Note 2: Test olevba.py (from decalage) against a known sample to verify you have decalage tools installed correctly 

    Example JSON output:

        "EXPLODE_VBA": {
          "Parsed_Macros_Metadata": [
            {
              "VBA_project": [
                "('', 'PROJECT', 'VBA/dir')"
              ],
              "OLE_stream": "VBA/Z1",
              "Type": "OLE",
              "VBA_filename": "Z1.bas"
            }
          ],
          "VBA_Forms_Found_Streams": [
            "sTVOL/o"
          ]

    Example of exploded file naming:
        e_vba_a2a729ef454c64cd44377c2703f4222e_sTVOL.frm           -> This is a macro
        e_vba_a2a729ef454c64cd44377c2703f4222e_A0.bas              -> This is a macro
        e_vba_a2a729ef454c64cd44377c2703f4222e_combined_forms.txt  -> This is a form


   '''

    def __init__(self,):
        self.module_name = "EXPLODE_VBA"

    def _run(self, scanObject, result, depth, args):
        moduleResult = []
        try:
            vbaparser = olevba.VBA_Parser(scanObject.objectHash, data=scanObject.buffer) #load ole into olevba    
            if vbaparser.detect_vba_macros(): #VBA Macro Found
                # Loop to parse VBA Macro
                for (filename, stream_path, vba_filename, vba_code) in vbaparser.extract_macros(): # macro extraction
                    macrofilesdict = {}
                    macrofilesdict.update({'Type': vbaparser.type, 'VBA_project': vbaparser.vba_projects, 'OLE_stream': stream_path, 'VBA_filename': vba_filename})
                    scanObject.addMetadata(self.module_name, "Parsed_Macros_Metadata", macrofilesdict)
                    explodevbafilename = 'e_vba_%s_%s' % (scanObject.objectHash, vba_filename) # Exploded file name contains source hash
                    moduleResult.append(ModuleObject(buffer=vba_code, externalVars=ExternalVars(filename=explodevbafilename)))
                # Loop to parse VBA Forms
                combinedstring = ""
                formfilesdlist = set()
                for (filename, stream_path, form_string) in vbaparser.extract_form_strings():
                    formfilesdlist.add(stream_path) #set because stream_path could be the same over and over again
                    combinedstring += " %s" % form_string #combining all found forms text into a single variable
                if combinedstring: #form text found
                    scanObject.addMetadata(self.module_name, "VBA_Forms_Found_Streams", formfilesdlist)
                    explodeformsfilename = 'e_vba_%s_combined_forms.txt' % (scanObject.objectHash)
                    moduleResult.append(ModuleObject(buffer=combinedstring, externalVars=ExternalVars(filename=explodeformsfilename)))
            vbaparser.close()       

        except olevba.OlevbaBaseException as e:  # exceptions from olevba import will raise
            olevbaerror = 'e_vba:err:%s' % e
            #scanObject.addFlag(olevbaerror)
            log_module("MSG", self.module_name, 0, scanObject, result, olevbaerror)
        except (QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError):
            raise
        return moduleResult
