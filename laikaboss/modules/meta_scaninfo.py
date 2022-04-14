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
# Module to collect scan information
#

import time
import logging

from laikaboss.si_module import SI_MODULE
from laikaboss.util import get_option, log_module_error
from laikaboss.objectmodel import QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError
from laikaboss.extras.extra_util import config_path, Lock

class CollectHandler(logging.Handler):
    def __init__(self, countlimit=1000, lengthlimit=1000):
        super(CollectHandler, self).__init__()
        self.entries = []
        self.countlimit = countlimit
        self.lengthlimit = lengthlimit
        self.countexceeded = 0

    def emit(self, record):
        if len(self.entries) < self.countlimit:
            self.entries.append(self.format(record)[:self.lengthlimit])
        else:
            self.countexceeded = self.countexceeded + 1

    def reset(self):
        return_val = (self.entries, self.countexceeded)
        self.entries = []
        self.countexceeded = 0
        return return_val


class META_SCANINFO(SI_MODULE):
    '''
    Module to report scan information in metadata (instead of solely in logs)

    META_SCANINFO should be run exactly twice per scan, on the root object. 
        -at the very start of a scan
        -near the end of the scan, but possibly before logging modules

    only runtime is measured and debug, errors are collected that occur 
    between the two runs of module


    parameters:
        errorlimit (scaninfo_errorlimit): max error message to report? 0 to disable, 1000 default
        debuglimit (scaninfo_debuglimit): max debug limit to report? 0 to disable, 0 default
        lengthlimit (scaninfo_lengthlimit): max length for messages, default 1000 
    '''
    def __init__(self,):
        self.module_name = "META_SCANINFO"
        self.started = False
        self.start_timestamp = None
        self.error_handler = None
        self.debug_handler = None
        self.errorlimit = 0
        self.debuglimit = 0
        self.lengthlimit = 0
        self.ld = "##" # log delimiter
        # format is uuid|runtime|filetype|rootobjectsize|numerrors|source|flags
        self.log_record = u"%s%s%f%s%s%s%d%s%d%s%s%s%s"

    def _run(self, scanObject, result, depth, args):
        moduleResult = [] 
        if self.started:
            self._end(scanObject)
            self.log_type = get_option(args, "type", "scaninfo_log_type", "file")
            self.log_path = get_option(args, "logfile", "scaninfo_logfile", "/tmp/metrics.log")
        else:
            self.errorlimit = int(get_option(args, 'errorlimit', 'scaninfo_errorlimit', 1000))
            self.debuglimit = int(get_option(args, 'debuglimit', 'scaninfo_debuglimit', 0))
            self.lengthlimit = int(get_option(args, 'lengthlimit', 'scaninfo_lengthlimit', 1000))
            self.summary_log_type = get_option(args, "type", "scaninfo_summary_log_type", "file")
            self.summary_log_path = get_option(args, "summary_logfile", "scaninfo_summary_logfile", "/tmp/summary_metrics.log")
            self._start()
        return moduleResult 
        

    def _start(self):
        self.start_timestamp = time.time()
        if self.errorlimit:
            if not self.error_handler:
                self.error_handler = CollectHandler(countlimit=self.errorlimit,lengthlimit=self.lengthlimit)
                self.error_handler.setLevel(logging.ERROR)
            logging.getLogger().addHandler(self.error_handler)
        if self.debuglimit:
            if not self.debug_handler:
                self.debug_handler = CollectHandler(countlimit=self.debuglimit,lengthlimit=self.lengthlimit)
                self.debug_handler.setLevel(logging.DEBUG)
                logging.getLogger().setLevel(logging.DEBUG)
            logging.getLogger().addHandler(self.debug_handler)
        self.started = True
    
    def _end(self, scanObject):
        runtime = time.time() - self.start_timestamp
        scanObject.addMetadata(self.module_name, "runtime", runtime)
        self.start_timestamp = None
        if self.errorlimit:
            errors, exceeded = self.error_handler.reset()
            if errors:
                scanObject.addMetadata(self.module_name, "errors", errors)
            if exceeded:
                scanObject.addFlag("scaninfo:ERROR_LIMIT_EXCEEDED")
            logging.getLogger().removeHandler(self.error_handler)
        if self.debuglimit:
            debug, exceeded = self.debug_handler.reset()
            if debug:
                scanObject.addMetadata(self.module_name, "debug", debug)
            if exceeded:
                scanObject.addFlag("scaninfo:DEBUG_LIMIT_EXCEEDED")
            logging.getLogger().removeHandler(self.debug_handler)
        self.started = False

        # write extra summary logs
        # format is uuid|runtime|filetype|rootobjectsize|numerrors|source|flags
        root = scanObject.__dict__
        parent_order = root.get('parent_order', 0)

        if parent_order == -1:
            uuid = root.get('uuid','None')
            source = root.get('source','None')
            obj_size = root.get('objectSize', 0)
            ftype = root.get('fileType',['text'])
            if len(ftype) < 1:
                ftype = 'text'
            else:
                ftype = ftype[0]
            num_errors = len(errors)

            # get flags
            flags = root.get('moduleMetadata', {}).get('DISPOSITIONER', {}).get('Disposition', {}).get('Input_Flags', [])
            flag_string = ','.join(flags)
            record = self.log_record % (uuid, self.ld, runtime, self.ld, ftype, self.ld, obj_size, self.ld, num_errors,  self.ld, source, self.ld, flag_string)
            self._write_to_log(self.summary_log_path, self.summary_log_type, [record], False)


    def _write_to_log(self, log_path, log_type, log_records, is_json=True):
        lock = None
        output_log = None
        if log_type in ['file', 'both']:
            try:

              with open(log_path, "ab", 0) as output_log:
                lock_filename = log_path + ".lock"
                with open(lock_filename, 'w') as lock_fh:
                    try:
                        lock = Lock(lock_fh)
                    except Exception as e:
                        logging.error("Could not open lock file, %s: %s" % (lock_filename, str(e)))
                        raise RuntimeError("Could not lock/unlock log file for logging", lock_filename, ':', str(e))

                    if lock and output_log:
                        lock.acquire()

                        for log_record in log_records:

                            if is_json:
                                entry = json.dumps(log_record, ensure_ascii=False)
                            else:
                                entry = log_record

                            if output_log:
                                output_log.write(entry.encode('utf-8') + b"\r\n")

                            if output_log:
                                output_log.close()
                    lock.release()

            except Exception as e:
                logging.error('Failed to write to logfile: %s' % e)

