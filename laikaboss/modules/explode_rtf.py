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
# This module parses RTF files and contained objects. It uses the same rtf object parsing logic as pull request #62 in the official lmco/laikaboss repository with slight modifications for metadata placement.
# Requires: oletools (https://github.com/decalage2/oletools)
# Sandia National Labs
from __future__ import division
from laikaboss.si_module import SI_MODULE
from laikaboss.objectmodel import ModuleObject, ExternalVars
from oletools import rtfobj

class EXPLODE_RTF(SI_MODULE):

  def __init__(self,):
    self.module_name = "EXPLODE_RTF"

  def _run(self, scanObject, result, depth, args):
    moduleResult = []

    try:
      rtfp = rtfobj.RtfObjParser(scanObject.buffer)
      rtfp.parse()
    except Exception as e:
      logging.exception(e)
      scanObject.addFlag("rtf:PARSE_ERROR")
      return moduleResult

    if len(rtfp.objects) > 0:
      scanObject.addMetadata(self.module_name, "Total_Objects", len(rtfp.objects))

    for rtfobject in rtfp.objects:
      if rtfobject.is_package:
        if rtfobject.olepkgdata:

          ratio = len(rtfobject.olepkgdata)*1.0/(rtfobject.end - rtfobject.start)

          if rtfobject.filename:
            filename = rtfobject.filename
          else:
            filename = 'e_rtf_object_%08X.olepackage' % rtfobject.start

          scanObject.addFlag("rtf:EMBEDDED_OLEPACKAGE")

          ext_meta = {'src_path': rtfobject.src_path, 'temp_path': rtfobject.temp_path, 'format_id': rtfobject.format_id, 'class_name': rtfobject.class_name, 'data_size': rtfobject.oledata_size, 'decoded_to_encoded_ratio': ratio}

          moduleResult.append(ModuleObject(buffer=rtfobject.olepkgdata, externalVars=ExternalVars(filename=filename, extMetaData=ext_meta)))

      elif rtfobject.is_ole:
        scanObject.addFlag("rtf:EMBEDDED_OLE")
        if rtfobject.oledata:

          ratio = len(rtfobject.oledata)*1.0/(rtfobject.end - rtfobject.start)

          ext_meta = {'class_name': rtfobject.class_name, 'format_id': rtfobject.format_id, 'decoded_to_encoded_ratio': ratio}

          moduleResult.append(ModuleObject(buffer=rtfobject.oledata, externalVars=ExternalVars(filename='e_rtf_object_%08X.ole' % rtfobject.start, extMetaData=ext_meta)))


      elif rtfobject.rawdata:
        scanObject.addFlag("rtf:EMBEDDED_RAW")
        moduleResult.append(ModuleObject(buffer=rtfobject.rawdata, externalVars=ExternalVars(filename='e_rtf_object_%08X.raw' % rtfobject.start)))
    return moduleResult
