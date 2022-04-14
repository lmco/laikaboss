# Copyright 2015 Lockheed Martin Corporation
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
import os
import syslog
import traceback
import sys
import logging
from laikaboss.objectmodel import QuitScanException, \
                                GlobalScanTimeoutError, GlobalModuleTimeoutError

_module_list = []
# This block of code looks for all py files in the current directory
# and imports the class with the same name (except uppercase) as the file.
# This ensures that the dispatcher can access every module in this folder without 
# any further configuration needed.
def log_debug(message):
    syslog.syslog(syslog.LOG_DEBUG, "DEBUG %s" % message)

def module_list():
    return _module_list[:]

module=None
_temp=None

for module in os.listdir(os.path.dirname(__file__)):
    try:
        if module == '__init__.py' or module[-3:] != '.py':
            continue
        _temp = __import__(module[:-3], locals(), globals(), [module[:-3].upper()], 1)
        globals()[module[:-3].upper()] = getattr(_temp, module[:-3].upper())
    except (QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError):
        raise
    except:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        logging.exception("Import Exception for %s module: %s" % (module ,repr(traceback.format_exception(exc_type, exc_value, exc_traceback))))
        log_debug("Import Exception for %s module: %s" % (module ,repr(traceback.format_exception(exc_type, exc_value, exc_traceback))))
        continue
    _module_list.append(module[:-3].upper())
del module
del _temp
