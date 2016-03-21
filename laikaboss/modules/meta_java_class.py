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
from laikaboss.objectmodel import ScanError
from javatools import unpack_class, Unimplemented, ClassUnpackException

class META_JAVA_CLASS(SI_MODULE):
    def __init__(self,):
        self.module_name = "META_JAVA_CLASS"

    def _run(self, scanObject, result, depth, args):
        moduleResult = []

        try:
            class_obj = unpack_class(scanObject.buffer)

            class_requires = class_obj.get_requires()
            scanObject.addMetadata(self.module_name, 'Requires', class_requires)

            class_provides = class_obj.get_provides()
            scanObject.addMetadata(self.module_name, 'Provides', class_provides)

            class_constants = tuple(class_obj.cpool.pretty_constants())
            constantsDict = dict((i,v) for i,t,v in class_constants)
            scanObject.addMetadata(self.module_name, 'Constants', constantsDict)

        except ScanError:
            raise
        except Unimplemented:
            scanObject.addFlag('java_class:err:unimplemented_feature')
        except ClassUnpackException:
            scanObject.addFlag('java_class:err:class_unpack_exception')

        return moduleResult
