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
'''
This module extracts metadata from OLE files

Requires the olefile module (and oletools for clsid identification)
'''
from builtins import str
from datetime import datetime
from olefile import OleFileIO, STGTY_STREAM, STGTY_STORAGE 
from oletools.common.clsid import KNOWN_CLSIDS
import logging

from laikaboss.objectmodel import ModuleObject, ExternalVars
from laikaboss.si_module import SI_MODULE

class META_OLE(SI_MODULE):

    def __init__(self):
        self.module_name = 'META_OLE'

    def _run(self, scanObject, result, depth, args):
        moduleResult = []
        #Read OLE file and get metadata
        try:
            ole = OleFileIO(scanObject.buffer)
        except IOError as e:
            scanObject.addFlag('ole:%s' % type(e).__name__)
            return moduleResult
        
        #Get metadata on OLE streams and storages
        creationTimes = []
        modificationTimes = []
        clsids = []
        for item in ole.listdir(storages=True):
            itemPath = '/'.join(item)
            ctime = ole.getctime(itemPath)
            mtime = ole.getmtime(itemPath)
            clsid = ole.getclsid(itemPath)
            if ctime:
                creationTimes.append(str(ctime))
            if mtime:
                modificationTimes.append(str(mtime))
            if clsid:
                clsids.append(str(clsid))
        if ole.root.getctime():
            creationTimes.append(str(ole.root.getctime()))
        if ole.root.getmtime():
            modificationTimes.append(str(ole.root.getmtime()))
        if ole.root.clsid:
            clsids.append(str(ole.root.clsid))
        clsid_descriptions = []
        for clsid in clsids:
            if clsid in KNOWN_CLSIDS:
                description = KNOWN_CLSIDS[clsid]
                clsid_descriptions.append(description)
                if 'Microsoft Equation' in description:
                    scanObject.addFlag('ole:ms_equation_editor')
                elif 'CVE' in description:
                    scanObject.addFlag('ole:misc_clsid_cve')
        scanObject.addMetadata(self.module_name, 'creationTimes', creationTimes)
        scanObject.addMetadata(self.module_name, 'modificationTimes', modificationTimes)
        scanObject.addMetadata(self.module_name, 'classIDs', clsids)
        scanObject.addMetadata(self.module_name, 'classIDDescriptions', clsid_descriptions)
      
        return moduleResult
