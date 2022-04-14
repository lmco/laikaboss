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
# Module that uses binwalk to identify embedded data
# Configuration settings:
#   tempdir: A string containing the path to a designated temp file directory
#       Default value: '/tmp'
#   extractions: A regex string with only lowercase matchings to the descriptions of the files to be extracted
# Library dependencies: binwalk (manual install from git since pip/apt versions are out of date / not managed)
from laikaboss.si_module import SI_MODULE
from laikaboss.objectmodel import ExternalVars, ModuleObject
from laikaboss.util import get_option, laika_temp_dir
from laikaboss import config
import binwalk
import logging
import tempfile
import os

class EXPLODE_BINWALK(SI_MODULE):

  def __init__(self,):
    self.module_name = "EXPLODE_BINWALK"

  def _run(self, scanObject, result, depth, args):
    # Extract out files that have the following LOWERCASE matches in their descriptions (can be regex)
    # Default: Do not extract out any files
    extractions = get_option(args, 'binwalk_extraction', 'binwalk_extraction', '')

    # Perform extractions for carvings at offset 0
    # Prevents duplicate explosions of object already present
    # Defaults to False
    zero_offset_extraction = get_bool(get_option(args, 'binwalk_zero_offset', 'binwalk_zero_offset', 'False'))

    moduleResult = []
    embedded_info = []

    with laika_temp_dir() as tempdir, tempfile.NamedTemporaryFile(delete=True, dir=tempdir) as temp_file:
      temp_file_name = temp_file.name
      temp_file.write(scanObject.buffer)
      temp_file.flush()
      try:
        if extractions:
          binwalk_scan_results = binwalk.scan(temp_file_name, signature=True, quiet=True, dd=extractions, directory=tempdir)
        else:
          binwalk_scan_results = binwalk.scan(temp_file_name, signature=True, quiet=True)

        # Get metadata info from binwalk
        for module in binwalk_scan_results:
          for index, result in enumerate(module.results):
            embedded_info.append({'description': result.description, 'offset': result.offset})

        # Perform file extractions
        if extractions:
          extraction_path = os.path.abspath(os.path.join(tempdir, '_%s.extracted' % (os.path.basename(temp_file_name))))
          for (dirpath, dirnames, filenames) in os.walk(extraction_path):
            for filename in filenames:
              if filename == '0' or filename.startswith('0-'):
                if not zero_offset_extraction:
                  continue
              buf = open(os.path.join(dirpath, filename), 'rb').read()
              moduleResult.append(ModuleObject(buffer=buf, externalVars=ExternalVars(filename='e_binwalk_offset_0x%s' % (filename))))
      except Exception as e:
        logging.error("ERROR running EXPLODE_BINWALK: %s" % (str(e)), exc_info=True)

    if embedded_info:
      scanObject.addMetadata(self.module_name, 'embedded_info', embedded_info)
    return moduleResult

def get_bool(s):
  if isinstance(s, bool):
    return s 
  if s.lower() == 'false' or s == '0' or s.lower() == 'no':
    return False
  return True
