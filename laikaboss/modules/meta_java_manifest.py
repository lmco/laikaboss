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
from javatools.manifest import Manifest

class META_JAVA_MANIFEST(SI_MODULE):
    def __init__(self,):
        self.module_name = "META_JAVA_MANIFEST"

    def _run(self, scanObject, result, depth, args):
        moduleResult = []

        mf = Manifest()
        mf.parse(scanObject.buffer)

        for key,val in mf.items():
            scanObject.addMetadata(self.module_name, key, val)

        return moduleResult
