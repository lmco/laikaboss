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
from __future__ import division
from builtins import str as text
from past.builtins import unicode
from past.utils import old_div
from builtins import object
import os
import sys
import fcntl
import copy
import json
import logging
import datetime
from math import isnan, isinf
from uuid import UUID
from copy import deepcopy as clone_object
from collections import OrderedDict, namedtuple
import time
import binascii
import hashlib
import socket

DEFAULT_CONFIGS = {
    'laika_dev_config_path' : 'etc',
    'laika_sys_config_path' : '/etc/laikaboss/'
    }

_LBCUSTOM_PREFIX="LB-"
_storage_url=None
_storage_url_config_cache=None

CustomID = namedtuple('CustomID', ['version', 'random', 'server'], verbose=False)

def str_to_bool(s):
  if type(s) == bool:
    return s
  if s.strip().lower() in ['true', 'yes', '1', 'y']:
    return True 
  return False

def remove_sys_paths(rm_paths):
   orig_path = copy.copy(sys.path)
   for sys_path in orig_path:
       for rm_path in rm_paths:
          if rm_path in sys_path:
             while True:
                try:
                   # this removes all instances not just the first
                   sys.path.remove(sys_path)
                except:
                   break

   # return the unmodified path for you to reset later
   return orig_path

def safe_filename(filename, drop=None):
    keep = ['.','_', '-']

    if not drop:
       drop = []

    result = ""
    for i,c in enumerate(filename):
        if i == 0 and c == '.':
           result += ('%' + str(ord(c)))
        elif c not in drop and (c.isalnum() or c in keep):
           result += c
        else:
           result += ('%' + str(ord(c)))

    return result

def config_path(path):

    if path and not os.path.isabs(path):

       use_dev = False

       try:
          # this find the location to this util.py file, and go up 3 directories to find the root lb directory
          path_to_install = os.path.abspath(os.path.join(os.path.realpath(__file__), os.pardir, os.pardir, os.pardir))
          if os.path.exists(os.path.join(path_to_install, DEFAULT_CONFIGS["laika_dev_config_path"], path)):
             use_dev = True
       except:
           pass

       if use_dev:
          path = os.path.join(DEFAULT_CONFIGS["laika_dev_config_path"], path) 
       else:
          path = os.path.join(DEFAULT_CONFIGS["laika_sys_config_path"], path) 

       path = os.path.abspath(path)

    return path

# Multi process or thread locking
# Idea was from here http://blog.vmfarms.com/2011/03/cross-process-locking-and.html
class Lock(object):

    def __init__(self, fh):
        self.fh = fh

    def acquire(self):
        if self.fh != None:
            while True:
               try:
                  fcntl.flock(self.fh, fcntl.LOCK_EX)
                  break
               except IOError as e:
                  # raise on unrelated IOErrors
                  if e.errno != errno.EAGAIN:
                     raise
                  else:
                     logging.exception('file locked waiting....')
                     time.sleep(0.1)

    def release(self):
        if self.fh != None:
            fcntl.flock(self.fh, fcntl.LOCK_UN)

    def __del__(self):
        if self.fh != None:
            self.fh.close()

def cleanup_brackets(v, ind):
  if v and isinstance(v, str) and v.startswith('[') and v.endswith(']'):
    try:
      v = ast.literal_eval(v)[ind]
    except:
      # The format of originating-ip came through like:
      # [255.255.255.0] which is invalid inside.
      pass

  if v and type(v) == list:
    return v[ind].rstrip(']').lstrip('[')
  elif v and isinstance(v, str):
    return v.rstrip(']').lstrip('[')

def get_common_headers(base_record, headers):
    #Import here to avoid recursive import problems
    from laikaboss.extras.dictParser import DictParser
    d = DictParser(base_record)
    t = []

    for key in headers:
        if '|' in headers[key]:
            header_sources = headers[key].split('|')
            val = None
            for src in header_sources:
                if not val:
                    val = d.eval(src).value()
                    if type(val) == list:
                        val = val[0]
        else:
            val = d.eval(headers[key]).value()

        # Do not output None or null values
        if val or type(val) in [bool]:
            if key in ['message_id']:
                val = cleanup_brackets(val, -1)

            t.append((key, val))

    return t

def parse_log_record(result, extended=False):
    '''
    Construct a log record from data within the scan result.

    Arguments:
    result  --  The scan result.

    Returns:
    A log record respresenting the scan result.
    '''

    # Build the results portion of the log record. This will be a list of
    # dictionaries, where each dictionary is the result of a single buffer's
    # scan. The list will contain all of the buffers that were exploded from
    # a root buffer's scan in no particular order.
    buffer_results = [None] * len(result.files)
    doc_hash = None
    for scan_object in result.files.values():
        # Do not damage the original result -> clone
        buffer_result = clone_object(scan_object.__dict__)

        if not doc_hash and scan_object.order == 0:
            # TODO: SHA256 is stored in scan result. No need to recalculate
            doc_hash = hashlib.sha256(scan_object.buffer).hexdigest()

        # Don't log buffers here, just metadata
        if 'buffer' in buffer_result:
            del buffer_result['buffer']
        buffer_results[buffer_result['order']] = buffer_result

    buffer_results.sort(key=lambda k: k.get("order", 0))

    scan_result = log_record_strainer(buffer_results)

    if extended:
        base_log_record = OrderedDict([
            ('datetime', datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")),
            ('source', result.source),
            ('scanhost', socket.gethostname()),
            ('dochash', doc_hash),
            ('scan_result', scan_result),
        ])
    else:
        base_log_record = OrderedDict([('scan_result', scan_result)])

    return base_log_record

def parse_log_record_nonsummary(result, split_log=False, headers={}):
    base_record = parse_log_record(result, extended=True)
    dt = base_record['datetime']
    scan_result = base_record['scan_result']
    common_headers = log_record_strainer(get_common_headers(scan_result[0], headers))

    results = []
    if split_log:
        for record in scan_result:
            data = [('datetime', dt), ('summary', False)] + common_headers
            for key in record:
                if key == 'source':
                    data.append(('lb_source', record[key]))
                else:
                    data.append((key, record[key]))
            results.append(OrderedDict(data))
    else:
        results.append(base_record)

    return results

def log_record_strainer(thing):
  '''
  Prepare object for recording to log. The record must be able to be
  marshalled into JSON without using custom encoders, since this
  marshalling occurs after the log record has been emitted.

  Arguments:
  thing   --  The object that needs to be strained.

  Returns:
  The object converted into a state that can be emitted to the log.
  '''
  thing_type = type(thing)
  if thing_type in [list, set, frozenset]:
    new_thing = []
    for element in thing:
      new_thing.append(log_record_strainer(element))
    return new_thing
  elif thing_type is dict:
    new_thing = {}
    for key, value in thing.items():
      new_key = log_record_strainer(key)
      new_value = log_record_strainer(value)
      # Don't output empty strings or lists
      if isinstance(new_value, (bool, int)):
        new_thing[new_key] = new_value
      elif isinstance(new_value, (bytes, unicode)) and new_value.lower() in ['true', 'false', b'true', b'false']:
        if new_value.lower() == 'false' or new_value.lower() == b'false':
          new_thing[new_key] = False
        elif new_value.lower() == 'true' or new_value.lower() == b'true':
          new_thing[new_key] = True
      else:
        new_thing[new_key] = new_value
    return new_thing
  elif thing_type is OrderedDict:
    new_list = []
    for key in thing:
      new_key = log_record_strainer(key)
      new_value = log_record_strainer(thing[key])
      new_list.append((new_key, new_value))

    return OrderedDict(new_list)
  elif thing_type is tuple:
    l = list(thing)
    new_list = []
    for i in l:
      new_list.append(log_record_strainer(i))
    return tuple(new_list)
  elif thing_type is UUID:
    return unicode(thing)
  # JSON does not fully support NaN and Infinity in its spec, so some JSON libraries do not
  # handle these values and instead raise an error. Serializing these to the string
  # respresentation to prevent these errors from disrupting logging.
  elif thing_type is float:
    if isnan(thing):
      return 'NaN'
    elif isinf(thing):
      return 'Inf'
    else:
      return thing
  elif thing_type is bytes:
    return unicode(thing, 'utf-8', errors='replace')
  elif thing_type is text or thing_type is unicode:
    return unicode(thing)
  else:
    return thing

def get_timestamp_from_uuid(uuid1):
   epoch = datetime.datetime(1582, 10, 15)
   uuid_obj = uuid.UUID(uuid1)
   timestamp = epoch + datetime.timedelta(microseconds = old_div(uuid_obj.time,10))
   return timestamp

def storage_server_lookup_from_name(servers, name, version=1):
    ''' send in an ordered Dict of server_str, server_connection tuples, and a name identifier,
        it will hash the name, and give you the tuple of server, 
        short - specified if you want the shorthostame, otherwise return the fully qualified name
    '''
    if isinstance(name, text):
        name = name.encode('utf-8')
    hexbytes = hashlib.md5(name).hexdigest()[0:4]
    v = int(hexbytes, 16)
    index = v % len(servers)
    server = servers[index]
    return server

def id_lookup_details(servers, id1, short=False):
    ''' send a rootUID or other uuid and it will extract which
        storage server to use
        format:  LB-n|lb_source|lb_worker_short_host|lb_storage_short_host|pid|epochtime_with_2_decimals|6 random hex bytes
    '''

    result = None
    version = "1"
    server = None
    random = id1
    #timestamp = get_timestamp_from_uuid(id1)

    try:

        server = storage_server_lookup_from_name(servers, id1)
        result = CustomID(version=version, random=id1, server=server)

        if not result:
             logging.warn("No Details found for UUID: %s" % (id1))

    except Exception as e:
        logging.exception("Error parsing UUID: %s" % (id1))

    return result

def write_to_log(log_path, log_record):
    lock = None
    output_log = None
    try:
        output_log = open(log_path, "ab")
    except IOError as e:
        logging.error("Could not open log file %s, got error [%s]" % (log_path, e))

    if output_log != None:
        lock_filename = log_path + ".lock"
        lock_fh = None
        try:
            lock_fh = open(lock_filename, 'w')
        except IOError as e:
            logging.error("Could not open log file %s, got error [%s]" % (lock_filename, e))

        if lock_fh != None:
            try:
                lock = Lock(lock_fh)
            except Exception as e:
                logging.error("Could not open lock file, %s: %s" % (lock_filename, str(e)))
                raise RuntimeError("Could not lock/unlock log file", lock_filename, ":", str(e))

            if lock and output_log:
                lock.acquire()

                try:
                    entry = json.dumps(log_record, ensure_ascii=False)
                    if not isinstance(entry, bytes):
                        entry = entry.encode("utf-8", errors="replace")
                    output_log.write(entry + b"\r\n")
                    output_log.close()
                except Exception as e:
                    logging.exception('Error dumping as JSON and writing to log file')
                    raise e
                finally:
                    lock.release()
                    lock_fh.close()
