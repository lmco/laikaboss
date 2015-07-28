# Copyright 2015 Lockheed Martin Corporation
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
from laikaboss.objectmodel import ModuleObject, ExternalVars
from laikaboss.si_module import SI_MODULE
import gzip
import StringIO


class EXPLODE_GZIP(SI_MODULE):
    def __init__(self,):
        self.module_name = "EXPLODE_GZIP"
    def _run(self, scanObject, result, depth, args):
        moduleResult = []

        file = StringIO.StringIO(scanObject.buffer)
        gzip_file = gzip.GzipFile(fileobj=file)

        new_buffer = gzip_file.read()

        moduleResult.append(ModuleObject(buffer=new_buffer,
                                         externalVars=ExternalVars(filename="gzip_%s" % len(new_buffer))))

        return moduleResult

