'''
This module logs to a file in a splunk friendly format and/or to a socket on a splunk forwarder.
copied heavily from laikaboss/laikaboss/modules/log_fluent.py - the original copyright header is below
'''

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

import copy
from copy import deepcopy as clone_object
from math import isnan, isinf
from laikaboss.si_module import SI_MODULE
from laikaboss.util import get_option, log_module_error
from laikaboss.extras.extra_util import Lock, parse_log_record_nonsummary
from laikaboss.extras.dictParser import DictParser
import laikaboss
import hashlib
import logging
import json
import ast

from uuid import UUID
import time,socket,datetime,json
from collections import OrderedDict

import socket

_module_name = "LOG_SPLUNK"

class LOG_SPLUNK(SI_MODULE):
  '''Laika module for logging scan results using splunk.'''

  def __init__(self,):
    '''Main constructor'''
    self.module_name = _module_name
    self.hostname = socket.gethostname()

  def _run(self, scanObject, result, depth, args):
    """Main module execution. Logs the scan result to splunk."""

    laikaboss_log_path = get_option(args, "logfile", "splunk_laikaboss_logfile", "/var/log/laikaboss/laikaboss_splunk.log")
    split_log = get_option(args, "split_log", "splunk_split_log", None)

    headers = {}

    try:
      if hasattr(laikaboss.config, "splunkcommonheaders") and laikaboss.config.splunkcommonheaders:
         headers = json.loads(laikaboss.config.splunkcommonheaders)
    except Exception as e:
      logging.exception('%s: Error parsing common Splunk headers in laikaboss.conf' % self.module_name)
      return []

    log_records = parse_log_record_nonsummary(result, split_log=split_log, headers=headers)

    # Write to log file
    if split_log:
      new_log_records = self._map_new_fields(log_records)

      for log_record in log_records:
        if 'moduleMetadata' in log_record:
          if 'SUBMIT_STORAGE_META' in log_record['moduleMetadata']:
            log_record['moduleMetadata'].pop('SUBMIT_STORAGE_META', None)

      self._write_to_log(laikaboss_log_path, new_log_records)

      log_record_dumps = []
      for log_record in log_records:
        log_record_dumps.append(json.dumps(log_record, ensure_ascii=False))
      scanObject.addMetadata('SUBMIT_STORAGE_META', 'nonsummary', log_record_dumps)

    else:

      self._write_to_log(laikaboss_log_path, log_records)
    
    return []

  def _map_new_fields(self, log_records):
    mappings = {'scanTime': 'scan_time',
                'fileType': 'file_type',
                'contentType': 'lb_content_type'}
    new_field_records = []
    for od in log_records:
      tmp_field_record = []
      for field_name in od:
        if field_name in mappings:
          tmp_field_record.append((mappings[field_name], od[field_name]))
        else:
          tmp_field_record.append((field_name, od[field_name]))
      new_field_records.append(OrderedDict(tmp_field_record))
    return new_field_records

  def _write_to_log(self, log_path, log_records):
    lock = None
    output_log = None

    with open(log_path, "ab", 0) as output_log:
        lock_filename = log_path + ".lock"
        with open(lock_filename, 'w') as lock_fh:
          try:
            lock = Lock(lock_fh)
          except Exception as e:
            logging.exception("Could not open lock file, %s: %s" % (lock_filename, str(e)))
            raise RuntimeError("Could not lock/unlock log file for splunk logging", lock_filename, ':', str(e))

          if lock and output_log:
            lock.acquire()

            try:
              for log_record in log_records:

                entry = json.dumps(log_record, ensure_ascii=False)
                if not isinstance(entry, bytes):
                    entry = entry.encode('utf-8')

                if output_log:
                  output_log.write(entry + b"\r\n")

              if output_log:
                output_log.close()
            except Exception as e:
              logging.exception('Failed to write to logfile')

            lock.release()

