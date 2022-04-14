# Copyright 2020 National Technology & Engineering Solutions of Sandia, LLC 
# (NTESS). Under the terms of Contract DE-NA0003525 with NTESS, the U.S. 
# Government retains certain rights in this software.
#
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
"""
This module parses an OLE file for macros.

Requires: oletools 0.52 or higher

Sandia National Labs
"""
from builtins import str
import logging
import sys
from io import BytesIO
from oletools.olevba import VBA_Parser

from laikaboss.objectmodel import ModuleObject, ExternalVars, QuitScanException, \
                                GlobalScanTimeoutError, GlobalModuleTimeoutError
from laikaboss.util import get_option
from laikaboss.si_module import SI_MODULE

class EXPLODE_MACRO(SI_MODULE):
    def __init__(self,):
        self.module_name = "EXPLODE_MACRO" 

    def _run(self, scanObject, result, depth, args):
        moduleResult = []

        byte_limit = int(get_option(args, 'bytelimit', 'macrobytelimit', 0))

        parser = VBA_Parser(scanObject.filename, scanObject.buffer)
        numMacros = 0
        if parser.detect_vba_macros():
            for (filename, stream_path, vba_filename, vba_code) in parser.extract_macros():
                numMacros += 1
                macro_name = "e_macro_" + str(numMacros)
                try:
                    u = str([str(s) for s in stream_path.split('/')])
                    macro_name = "e_macro_" + u
                except (QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError):
                    raise
                except:
                    pass #Use numbered name if can't convert to unicode
                if filename == 'xlm_macro':
                    if "Excel 4.0 macro sheet" in vba_code:
                        scanObject.addFlag("macro:XLM_MACRO")
                    else:
                        # If no Excel 4.0 macro code, don't add file as child
                        continue
                if byte_limit and len(vba_code) > byte_limit:
                    scanObject.addFlag("macro:BYTE_LIMIT_EXCEEDED")
                else:
                    moduleResult.append(ModuleObject(buffer=vba_code, externalVars=ExternalVars(filename=macro_name)))
        #Does it have stomped p-code?
        if parser.detect_vba_stomping():
            scanObject.addFlag("macro:STOMPED_PCODE")

        return moduleResult
