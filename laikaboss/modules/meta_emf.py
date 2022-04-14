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
Header Metadata from EMF files
Sandia National Labs
"""

import logging
import struct

from laikaboss.objectmodel import ExternalVars, ModuleObject, ScanError
from laikaboss.util import get_option
from laikaboss.si_module import SI_MODULE

EMF_HEADER_SIZE = 108

class META_EMF(SI_MODULE):

  def __init__(self):

    self.module_name = "META_EMF"

  def _run(self, scanObject, result, depth, args):

    moduleResult = [] 

    data = scanObject.buffer

    if len(data) >= EMF_HEADER_SIZE:
        iType, nSize, bounds_x1, bounds_y1, bounds_x2, bounds_y2 = struct.unpack('<6I', data[:6*4])
        frame_x1, frame_y1, frame_x2, frame_y2 = struct.unpack('<4I', data[6*4:10*4])
        dSignature, nVersion, nBytes, nRecords = struct.unpack('<4I', data[10*4:14*4])
        nHandles, sReserved = struct.unpack('<2H', data[14*4:15*4])
        nDesc, offDesc, nPalEnt = struct.unpack('<3I', data[15*4:18*4])
        refPix_x, refPix_y, refMil_x, refMil_y  = struct.unpack('<4I', data[18*4:22*4])

        # These header fields only show up in WINVER >= 0x0400 (anything after Windows NT 4.0)
        cbPixelFormat, offPixelFormat, bOpenGL = struct.unpack('<3I', data[22*4:25*4])

        # These header fields only show up in WINVER >= 0x0500 (Windows 2000)
        refMic_x, refMic_y = struct.unpack('<2I', data[25*4:27*4])

        if nDesc > 0:
          emf_desc = data[offDesc:offDesc+nDesc]
          scanObject.addMetadata(self.module_name, "EMF_description", emf_desc)

        scanObject.addMetadata(self.module_name, "header_size", nSize)
        scanObject.addMetadata(self.module_name, "bounds_width", bounds_x2 - bounds_x1)
        scanObject.addMetadata(self.module_name, "bounds_height", bounds_y2 - bounds_y1)
        scanObject.addMetadata(self.module_name, "frame_width", frame_x2 - frame_x1)
        scanObject.addMetadata(self.module_name, "frame_height", frame_y2 - frame_y1)
        scanObject.addMetadata(self.module_name, "num_records", nRecords)
        scanObject.addMetadata(self.module_name, "num_handles", nHandles)
        scanObject.addMetadata(self.module_name, "num_pal_entries", nPalEnt)
        scanObject.addMetadata(self.module_name, "ref_device_pix_x", refPix_x)
        scanObject.addMetadata(self.module_name, "ref_device_pix_y", refPix_y)
        scanObject.addMetadata(self.module_name, "ref_mm_x", refMil_x)
        scanObject.addMetadata(self.module_name, "ref_mm_y", refMil_y)
        scanObject.addMetadata(self.module_name, "ref_um_x", refMic_x)
        scanObject.addMetadata(self.module_name, "ref_um_y", refMic_y)

        hasOpenGL = True if bOpenGL != 0 else False
        scanObject.addMetadata(self.module_name, "has_opengl_record", hasOpenGL)
 
    return moduleResult



'''
typedef struct tagENHMETAHEADER {
  DWORD iType;
  DWORD nSize;
  RECTL rclBounds;
  RECTL rclFrame;
  DWORD dSignature;
  DWORD nVersion;
  DWORD nBytes;
  DWORD nRecords;
  WORD  nHandles;
  WORD  sReserved;
  DWORD nDescription;
  DWORD offDescription;
  DWORD nPalEntries;
  SIZEL szlDevice;
  SIZEL szlMillimeters;
#if (WINVER >= 0x0400)
  DWORD cbPixelFormat;
  DWORD offPixelFormat;
  DWORD bOpenGL;
#endif 
#if (WINVER >= 0x0500)
  SIZEL szlMicrometers;
#endif 
} ENHMETAHEADER, *PENHMETAHEADER;

typedef struct _RECTL {
  LONG left;
  LONG top;
  LONG right;
  LONG bottom;
} RECTL, *PRECTL;
'''

