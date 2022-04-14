# Copyright 2017 Chuck DiRaimondi
# Modified by Sandia National Labs
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

from laikaboss.objectmodel import ExternalVars, ModuleObject, ScanError
from laikaboss.si_module import SI_MODULE
from laikaboss.util import laika_temp_dir
from laikaboss import config
import os
import tempfile
import getnetguids

class META_DOTNET(SI_MODULE):
  def __init__(self):
    self.module_name = "META_DOTNET"

  def _run(self, scanObject, result, depth, args):

    moduleResult = []
    guids = {}

    try:

      with laika_temp_dir() as temp_dir, tempfile.NamedTemporaryFile(dir=temp_dir) as temp_file_input:
        temp_file_input_name = temp_file_input.name
        temp_file_input.write(scanObject.buffer)
        temp_file_input.flush()

        # Get guids
        netguids = getnetguids.get_assembly_guids(temp_file_input_name)

        if netguids:
          if "typelib_id" in netguids:
            guids['Typelib_ID'] = netguids['typelib_id']
          else:
            guids['Typelib_ID'] = "None"
          if "mvid" in netguids:
            guids['MVID'] = netguids['mvid']
          else:
            guids['MVID'] = "None"

      # Only attach metadata if metadata exists
      if guids:
        scanObject.addMetadata(self.module_name, 'DotNet_GUIDs', guids)

    except ScanError:
      raise

    return moduleResult
