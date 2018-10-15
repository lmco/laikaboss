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
from laikaboss.objectmodel import ModuleObject, ExternalVars, ScanError
from oletools import rtfobj

class EXPLODE_RTF(SI_MODULE):
    '''
    Input: A RTF file
    Output: Extracted embedded objects in a RTF file. Output types can be OLE, OLE package, or just a raw object. Module also adds metadata about the object when possible. 

    Purpose: Uses rtfobj from oletools to extract embedded objects in RTF files.

    Note: Tested with rtfobj version 0.51 (See updates at https://github.com/decalage2/oletools/wiki/rtfobj)

    "EXPLODE_RTF": {
      "Parsed_Objects_Metadata": [
        {
          "Class_name": "AbbZwuP",
          "Index": 0,
          "Format_id": 2,
          "Type": "OLE",
          "Size": 119616
        },
        {
          "Index": 1,
          "Type": "RAW"
        },
        {
          "Index": 2,
          "Type": "RAW"
        },
        {
          "Index": 3,
          "Type": "RAW"
        },
        {
          "Index": 4,
          "Type": "RAW"
        }
      ]
    },

    '''

    def __init__(self,):
        self.module_name = "EXPLODE_RTF"

    def _run(self, scanObject, result, depth, args):
        moduleResult = []
       
        rtfp = rtfobj.RtfObjParser(scanObject.buffer) #import reference
        rtfp.parse()
        for rtfobject in rtfp.objects:
            i = rtfp.objects.index(rtfobject) #index
            if rtfobject.is_package:
                objtypeis = "OLEPackage"
                typeolepackagedict = {}
                typeolepackagedict.update({'Type': objtypeis, 'Index': i, 'Filename': rtfobject.filename, 'Source Patch': rtfobject.src_path, 'Temp Path': rtfobject.temp_path})
                scanObject.addMetadata(self.module_name, "Parsed_Objects_Metadata", typeolepackagedict)
                moduleResult.append(ModuleObject(buffer=rtfobject.olepkgdata, externalVars=ExternalVars(filename='e_rtf_object_%08X.olepackage' % rtfobject.start)))

            elif rtfobject.is_ole:
                objtypeis = "OLE"
                typeoledict = {}
                typeoledict.update({'Type': objtypeis, 'Index': i, 'Format_id': rtfobject.format_id, 'Class_name': rtfobject.class_name, 'Size': rtfobject.oledata_size})
                scanObject.addMetadata(self.module_name, "Parsed_Objects_Metadata", typeoledict)
                moduleResult.append(ModuleObject(buffer=rtfobject.oledata, externalVars=ExternalVars(filename='e_rtf_object_%08X.ole' % rtfobject.start)))

            else:
                objtypeis = "RAW" #Not a well-formed OLE object.
                typerawdict = {}
                typerawdict.update({'Type': objtypeis, 'Index': i})
                scanObject.addMetadata(self.module_name, "Parsed_Objects_Metadata", typerawdict)
                moduleResult.append(ModuleObject(buffer=rtfobject.rawdata, externalVars=ExternalVars(filename='e_rtf_object_%08X.raw' % rtfobject.start)))

        return moduleResult
