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
import struct
import zlib
import pylzma
import logging
from cStringIO import StringIO
from laikaboss.objectmodel import ModuleObject, ExternalVars, QuitScanException, \
                                GlobalScanTimeoutError, GlobalModuleTimeoutError
from laikaboss.si_module import SI_MODULE

class EXPLODE_SWF(SI_MODULE):
    def __init__(self,):
        self.module_name = "EXPLODE_SWF"
    def _run(self, scanObject, result, depth, args):
        moduleResult = [] 
        try:
            fstr = StringIO(scanObject.buffer) 
            fstr.seek(4)
            swf_size = struct.unpack("<i", fstr.read(4))[0]
            logging.debug("swf size is %s" % swf_size) 
            fstr.seek(0)
            fws = self._decompressSWF(fstr, swf_size)
            if fws != None and fws != "ERROR":
                moduleResult.append(ModuleObject(buffer=fws, externalVars=ExternalVars(filename='e_swf_%s' % swf_size)))
            return moduleResult
        except:
            raise
        finally:
            logging.debug("extract_swf - closing stringio handle in run")
            fstr.close()
    #  These private methods are set to static to ensure immutability since
    #  they may be called more than once in the lifetime of the class
    @staticmethod 
    def _decompressSWF(f, swf_size):
        magic = f.read(3)
        if magic == "CWS":
            try:
                header = "FWS" + f.read(5)
                data = zlib.decompress(f.read())[:swf_size-8]
                return header + data 
            except (QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError):
                raise
            except Exception:
                return "ERROR"
            finally:
                logging.debug("extract_swf - closing stringio handle in decompress")
                f.close()
        elif magic == "ZWS":
            try:
                header = "FWS" + f.read(5)
                f.seek(12)
                data = pylzma.decompress(f.read())[:swf_size-8]
                return header + data
            except (QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError):
                raise
            except Exception:
                return "ERROR"
            finally:
                logging.debug("extract_swf - closing stringio handle in decompress")
                f.close()
        else:
            return None
