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
from laikaboss.si_module import SI_MODULE
from laikaboss import config
from laikaboss.util import get_option
import binascii 


class META_MAGIC(SI_MODULE):
    '''
    Add magic numbers (hex encoded) to metadata
    '''
    def __init__(self,):
        self.module_name = "META_MAGIC" 

    def _run(self, scanObject, result, depth, args):
        moduleResult = [] 

        limit = int(get_option(args, 'limit', 'metamagiclimit', 8))

        scanObject.addMetadata(self.module_name, "magic", binascii.hexlify(scanObject.buffer[:limit]))

        return moduleResult

