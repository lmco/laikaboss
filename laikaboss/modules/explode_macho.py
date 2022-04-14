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
This module extracts metadata from Mach-O and FAT files, 
and splits FAT files into separate Mach-O files for further processing.
"""

# Python library imports
import os
import logging
from past.builtins import unicode

# 3rd-party Python libraries
try:
    #import the parsing stuff from the macholib library
    from macholib.MachO import MachO
    has_macho = True
except ImportError:
    has_macho = False

 
# LaikaBoss imports
import laikaboss
import laikaboss.si_module
import laikaboss.extras.macho_util

_module_requires = ['macholib'] 

class EXPLODE_MACHO(laikaboss.si_module.SI_MODULE):

    def __init__(self):
        self.module_name = "EXPLODE_MACHO"

    def _run(self, scanObject, result, depth, args):
        result = []

        if not has_macho:
            logging.warning("The macholib Python library is not installed, EXPLODE_MACHO will not run.")
            return result

        parser = laikaboss.extras.macho_util.MachO_Parse(scanObject.buffer)
        try:
            metadata = parser.parse()
            scanObject.addMetadata("EXPLODE_MACHO", "metadata", metadata)
        except: # the Python library (macholib) fails to parse the file
            scanObject.addFlag('%s:%s' % ('macho', "UNABLE_TO_PARSE"))
            return result

        for f in parser.sub_files:
            if isinstance(f, unicode):
                f = unicode(f).encode('utf-8', 'replace')
            result.append(laikaboss.objectmodel.ModuleObject(buffer=f, 
                externalVars=laikaboss.objectmodel.ExternalVars(filename="fat_macho", contentType="macho")))

        return result
