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

import logging
import sys
import time
import traceback

from interruptingcow import timeout
from objectmodel import (
    GlobalModuleTimeoutError,
    GlobalScanTimeoutError,
    QuitScanException
)

from laikaboss import config
from laikaboss.util import (
    getRootObject,
    get_option,
    get_scanObjectUID,
    log_module,
    log_module_error
)


class SI_MODULE:
    '''Base module class for Laika'''
    def __init__(self,):
        '''Empty init method, to be overridden by modules'''
        pass

    def run(self, scanObject, result, depth, args):
        '''Wrapper method around _run for error handling'''
        moduleLoggingBool = config.modulelogging
        try:
            starttime = time.time()
            if moduleLoggingBool:
                log_module("START", self.module_name, 0, scanObject, result)

            # Get a configured timeout
            timeout_seconds = int(
                get_option(
                    args,
                    'module_timeout',
                    'global_module_timeout',
                    3600
                )
            )

            with timeout(timeout_seconds, exception=GlobalModuleTimeoutError):
                moduleResult = self._run(scanObject, result, depth, args)

            if moduleLoggingBool:
                log_module(
                    "END",
                    self.module_name,
                    time.time() - starttime,
                    scanObject,
                    result
                )
            if type(moduleResult) is not list:
                msg = (
                    "{0} returned an object with type {1}. ".format(
                        self.module_name, type(moduleResult)) +
                    "Only lists are allowed! Skipping this result."
                )
                logging.debug(msg)
                if moduleLoggingBool:
                    log_module_error(
                        self.module_name,
                        scanObject,
                        result,
                        msg
                    )
                return []

            return moduleResult

        except GlobalScanTimeoutError:
            raise
        except GlobalModuleTimeoutError:
            # If the module times out, add a flag and continue as a normal error
            scanObject.addFlag(
                "dispatch:err:module_timeout:{0}".format(self.module_name))

            exc_type, exc_value, exc_traceback = sys.exc_info()
            logging.exception(
                "error on {0} running module {1}. ".format(
                    get_scanObjectUID(getRootObject(result)),
                    self.module_name) +
                "exception details below: "
            )

            if moduleLoggingBool:
                log_module_error(
                    self.module_name,
                    scanObject,
                    result,
                    repr(traceback.format_exception(
                        exc_type,
                        exc_value,
                        exc_traceback)
                    )
                )
            return []

        except QuitScanException:
            # If the module is terminated early, add a flag and proceed the
            # exception up the stack
            scanObject.addFlag("dispatch:err:quit_scan")
            logging.warn(
                "quitting scan while running module {0}".format(
                    self.module_name)
            )
            raise

        except Exception:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            logging.exception(
                "error on {0} running module {1}. ".format(
                    get_scanObjectUID(getRootObject(result)),
                    self.module_name) +
                "exception details below: "
            )

            if moduleLoggingBool:
                log_module_error(
                    self.module_name,
                    scanObject,
                    result,
                    repr(traceback.format_exception(
                        exc_type,
                        exc_value,
                        exc_traceback)
                    )
                )
            return []

    def _run(self, scanObject, result, depth, args):
        ''' Blank method to be overridden by modules for scan operations '''
        pass

    def close(self, ):
        ''' Wrapper method around _close for error handling '''

        moduleLoggingBool = config.modulelogging

        try:
            self._close()
        except QuitScanException:
            logging.warn(
                "quitting destructor early on module {0}".format(
                    self.module_name)
            )
            raise
        except Exception:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            logging.exception(
                "error closing module {0}. exception details below: ".format(
                    self.module_name)
            )
            if moduleLoggingBool:
                log_module_error(
                    self.module_name,
                    None,
                    None,
                    repr(traceback.format_exception(
                        exc_type,
                        exc_value,
                        exc_traceback)
                    )
                )

    def _close(self, ):
        ''' Blank method to be overridden by modules for any operations that
        need to occur after all scans have been completed. '''
        pass

    module_name = ""
