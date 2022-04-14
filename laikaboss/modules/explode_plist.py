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
"""
This module parses binary plist files as defined by Apple Open Source (https://opensource.apple.com/source/CF/CF-550/CFBinaryPList.c). 

Requires: biplist 1.0.1 (https://pypi.python.org/pypi/biplist/1.0.1)

Sandia National Labs
"""
from builtins import bytes
import logging
import hashlib
import biplist
from datetime import datetime

# Import classes and helpers from the Laika framework
from laikaboss.objectmodel import ExternalVars, ModuleObject, ScanError
from laikaboss.util import get_option
from laikaboss.si_module import SI_MODULE

class EXPLODE_PLIST(SI_MODULE):


    def __init__(self):

        self.module_name = "EXPLODE_PLIST"

    def _run(self, scanObject, result, depth, args):

        moduleResult = [] 
        
        try:
            plist = biplist.readPlistFromString(scanObject.buffer)
        except:
            logging.exception("Error parsing binary plist file with biplist.")
            scanObject.addFlag('plist:PARSE_ERROR')
            return []

        self._parse_plist(plist, "", moduleResult)

        return moduleResult

    def _parse_plist_item(self, buf, item_name, moduleResult):
        if isinstance(buf, (str, biplist.Uid, int, datetime, float)):
            return

        try:
            buf = bytes(buf)
        except TypeError as e:
            return
        except UnicodeEncodeError as e:
            try:
                buf = bytes(buf.encode('utf-8'))
            except:
                buf = buf

        moduleResult.append(ModuleObject(buffer=buf, externalVars=ExternalVars(filename=item_name)))

    def _parse_plist(self, plist, item_name, moduleResult):
    
        if type(plist) == dict:
            for key in plist:
                self._parse_plist(plist[key], "%s/%s" % (item_name, key), moduleResult)
        elif type(plist) == list:
            for i in range(len(plist)):
                self._parse_plist(plist[i], "%s/%d" % (item_name, i), moduleResult)
        else:
            self._parse_plist_item(plist, item_name, moduleResult)
    
        return
