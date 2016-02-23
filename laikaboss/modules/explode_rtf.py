# Copyright 2016 Josh Liburdi
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
from laikaboss.si_module import SI_MODULE
from laikaboss.objectmodel import ModuleObject, ExternalVars, ScanError
from oletools import rtfobj

class EXPLODE_RTF(SI_MODULE):
    def __init__(self,):
        self.module_name = "EXPLODE_RTF"

    def _run(self, scanObject, result, depth, args):
        moduleResult = []

        try:
            for index, obj_len, obj_data in rtfobj.rtf_iter_objects(scanObject.buffer):
                # index location of the RTF object becomes the file name
                name = 'index_' + str(index)
                try:
                    moduleResult.append(ModuleObject(buffer=obj_data, externalVars=ExternalVars(filename='e_rtf_%s' % name)))

                except:
                    scanObject.addFlag('explode_rtf:err:explode_%s_failed' % name)

        except ScanError:
            raise

        return moduleResult
