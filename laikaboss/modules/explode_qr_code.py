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
from future import standard_library
standard_library.install_aliases()
import logging
from io import BytesIO
from pyzbar.pyzbar import decode
from PIL import Image, ImageDraw
from laikaboss.objectmodel import ModuleObject, ExternalVars, QuitScanException, \
                                GlobalScanTimeoutError, GlobalModuleTimeoutError
from laikaboss.util import log_module
from laikaboss.si_module import SI_MODULE

class EXPLODE_QR_CODE(SI_MODULE):
    def __init__(self,):
        self.module_name = "EXPLODE_QR_CODE"
        self.global_search = "GLOBAL_SEARCH"
    def _run(self, scanObject, result, depth, args):
        moduleResult = []
        minFileSize = 0 #Explode everything!
        useUnvalidatedFilenames = 0
        if 'minFileSize' in args:
            try:
                minFileSize = int(args['minFileSize'])
            except (QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError):
                raise
            except:
                pass
        if 'useUnvalidatedFilenames' in args:
            try:
                minFileSize = int(args['useUnvalidatedFilenames'])
            except (QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError):
                raise
            except:
                pass
        try:
            image = Image.open(BytesIO(scanObject.buffer))
            data = decode(image)
            log_module("MSG", self.module_name, 0, scanObject, result, "QR CODE data: "+str(data))
            if len(data) != 0:
                scanObject.addMetadata(self.module_name, "qr_codes", data)
                scanObject.addFlag('qr_codes:%d' % len(data))
            for qr_code in data:
                moduleResult.append(ModuleObject(buffer=qr_code.data, externalVars=ExternalVars(contentType="text")))
        except Exception as e:
            logging.exception(e)
        return moduleResult
