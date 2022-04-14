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
This module parses TNEF files and their attachments. Attachments of the TNEF files are added as children. TNEF file objects are counted. If any file exceeds a byte limit (passed in as a parameter), a flag is raised. Each TNEF can have many properties associated with it (defined in [MS-OXTNEF]) but, currently, only some are parsed out here.

Requires: tnefparse 1.2: https://pypi.python.org/pypi/tnefparse

Sandia National Labs
"""

from builtins import str
import logging
from struct import unpack
from datetime import datetime

from tnefparse import TNEF

from laikaboss.objectmodel import ExternalVars, ModuleObject, ScanError
from laikaboss.util import get_option
from laikaboss.si_module import SI_MODULE

class EXPLODE_TNEF(SI_MODULE):

  def __init__(self):

    # Disable the logging of the tnefparse module since it complains at almost all TNEF objects
    logging.getLogger('tnef-decode').setLevel(logging.CRITICAL)

    self.module_name = "EXPLODE_TNEF"

  def _run(self, scanObject, result, depth, args):

    moduleResult = [] 

    byte_limit = int(get_option(args, 'bytelimit', 'tnefbytelimit', 0))

    try:
      tnef = TNEF(scanObject.buffer, True)
    except Exception as e:
      # Unable to parse TNEF file
      logging.exception('Error parsing TNEF file')
      # Add a flag to indicate that TNEF could not be parsed
      scanObject.addFlag('tnef:PARSE_ERROR')
      raise

    scanObject.addMetadata(self.module_name, "Total_Objects", len(tnef.objects))

    flags, attach_meta = self._parse_tnef_objects(scanObject, tnef.objects)

    for flag in flags:
      scanObject.addFlag(flag)

    for ind, attachment in enumerate(tnef.attachments):
      ext_meta = {}
      attachment_name = 'tnef_attachment_%d' % ind
      if hasattr(attachment, 'name'):
        logging.debug('TNEF ATTACHMENT: %s', attachment.name)
        attachment_name = attachment.name

      # Attachment metadata is stored in parent, parse out and send as external metadata to child
      if ind < len(attach_meta["attach_crt"]):
        ext_meta["Creation Date"] = attach_meta["attach_crt"][ind]
      if ind < len(attach_meta["attach_mod"]):
        ext_meta["Modify Date"] = attach_meta["attach_mod"][ind]
      if ind < len(attach_meta["attach_rnd"]):
        ext_meta["Render Type"] = attach_meta["attach_rnd"][ind]
      # Add the attachments to moduleResult

      data = ''
      if hasattr(attachment, 'data'):
        data = attachment.data

      if byte_limit and len(data) > byte_limit:
        scanObject.addFlag("tnef:BYTE_LIMIT_EXCEEDED")
      elif len(data) > 0:
        moduleResult.append(ModuleObject(buffer=data, externalVars=ExternalVars(filename=attachment_name, extMetaData=ext_meta)))
    
    # Return a list of the attached files to this TNEF file
    return moduleResult

  def _parse_tnef_objects(self, scanObject, tnef_objects):

    flags = []
    exceeded_byte_limit = False

    # A list of the object fields which are represented in ASCII
    normal_codes = [TNEF.ATTSUBJECT, TNEF.ATTMESSAGECLASS, TNEF.ATTMESSAGEID]

    attachment_meta = {"attach_crt": [], "attach_mod": [], "attach_rnd": []}

    for o in tnef_objects:

      # Iterate through each object, attempting to parse it as according to:
      # [MS-OXTNEF], [MS-OXCMSG], [MS-OXCDATA], [MS-OXPROPS]
      try:
        if o.name in normal_codes:
          # Remove trailing null byte from normal ASCII representation
          scanObject.addMetadata(self.module_name, TNEF.codes[o.name], o.data.rstrip('\0'))

        elif o.name == TNEF.ATTDATESENT or o.name == TNEF.ATTDATERECD or o.name == TNEF.ATTATTACHCREATEDATE or o.name == TNEF.ATTATTACHMODIFYDATE or o.name == TNEF.ATTDATEMODIFY or o.name == TNEF.ATTDATESTART or o.name == TNEF.ATTDATEEND:
          dt = o.data
          if not isinstance(dt, datetime) and not isinstance(dt, str):
            dt = datetime(*tuple(unpack('<7H', o.data)[0:6]))
          if o.name == TNEF.ATTATTACHCREATEDATE:
            attachment_meta["attach_crt"].append(str(dt))
          elif o.name == TNEF.ATTATTACHMODIFYDATE:
            attachment_meta["attach_mod"].append(str(dt))
          else:
            scanObject.addMetadata(self.module_name, TNEF.codes[o.name], str(dt))
        elif o.name == TNEF.ATTTNEFVERSION:
          # The TNEF version must always be defined as this specific byte sequence.
          if o.data != b'\x00\x00\x01\x00':
            flags.append('tnef:INVALID_TNEF_VERSION')
        elif o.name == TNEF.ATTPRIORITY:
          priority = {
            2: 'High',
            1: 'Normal',
            0: 'Low'
          }
          scanObject.addMetadata(self.module_name, TNEF.codes[o.name], priority[o.data])
        elif o.name == TNEF.ATTATTACHRENDDATA:
          art = "Not Recognized"
          if o.data[0:2] == b'\x01\x00':
            art = "File"
          elif o.data[0:2] == b'\x02\x00':
            art = "OLE"
          attachment_meta["attach_rnd"].append(art)
        else:
          # Skip object property
          pass
      except Exception as e:
        # TNEF object property has invalid format, ignore
        logging.debug('Failed to parse TNEF Object with name %d and data %s, %s', o.name, o.data, e)
        pass

    return set(flags), attachment_meta
