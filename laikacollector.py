#!/usr/bin/env python
# Copyright 2020 National Technology & Engineering Solutions of Sandia, LLC 
# (NTESS). Under the terms of Contract DE-NA0003525 with NTESS, the U.S. 
# Government retains certain rights in this software.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from __future__ import division
from laikaboss.objectmodel import ExternalObject, ExternalVars
from laikaboss.redisClientLib import Client, parse_local_queue_info
import os, logging
from optparse import OptionParser
from random import randint
import castleblack as cb
import socket
import shutil
import binascii
from laikaboss.lbconfigparser import LBConfigParser
import re
import datetime
import time
from redis import ConnectionError as RedisConnectionError
from redis import BusyLoadingError as RedisBusyLoadingError
from redis.sentinel import MasterNotFoundError as RedisMasterNotFoundError
import json

# Variable to store configs from file
configs = {}

# Defaults for all available configurations
# To be used if not specified on command line or config file
default_configs = {
    'redis_url' : 'redis://127.0.0.1:6379/0',
    'redis_work_queue': 'laikacollector',
    'queue_threshold': 60,
    'mem_threshold': 1 * 1024 ** 1, # value in GB
    'queue_wait': 10,
    'max_size': 1024*1024*50,
    'submission_delay': 0,
    'queue_timeout': 60 * 60,
    'submission_avg_delay': 0,
    'submission_error_dir': '/tmp',
    'num_workers': 6,
}

_queue_states = {}
_wait_on_redis_conn_err = 7

# Message-ID regex
msgid_regex = re.compile(b'Message(?:-|_)ID: (<.+@.+>)\\s', flags=re.I)

def init_config(conf_file, opts):
    # Read the laikad config file
    config_parser = LBConfigParser()
    config_parser.read(conf_file, opts=opts)
    configs.update(dict(config_parser.items("DEFAULT")))
    configs.update(dict(config_parser.items("General")))
    configs.update(dict(config_parser.items("laikacollector")))

def process_file_list(files, config, queue_name):

     class mprops:

        def __init__(self, **entries):
           self.__dict__.update(entries)

     obj = mprops(**config)

     for f in files:
        with open(f, 'rb') as fptr:
            file_buffer = fptr.read()
            process_file(obj, f, file_buffer, {}, queue_name=queue_name)

def update_status(redis_client, submitID, status, file_path = None, rootUID = None, err_msg = None, disposition=None):

    logging.info("update_status, submitID = %s" % (submitID))

    status_obj = {}

    now = datetime.datetime.utcnow()
    status_obj["datetime"] = now.strftime("%Y-%m-%d_%H:%M:%SZ")
    status_obj["status"] = status

    if rootUID:
        status_obj["rootUID"] = rootUID

    if err_msg:
        status_obj["errmsg"] = err_msg

    if disposition:
        status_obj["disposition"] = disposition

    # we need a native redis object not a laikaboss.redisClientLib.Client object
    if hasattr(redis_client, 'redis_client'):
       redis_client = redis_client.redis_client

    try:
        logging.info("update_status 500, submitID = %s, status=%s" % (submitID, str(status)))
        redis_client.hmset(submitID, status_obj)
        redis_client.publish(submitID, json.dumps(status_obj))
        logging.info("update_status 600 , submitID = %s" % (submitID))
    except RedisConnectionError as e:
        logging.warn("Redis connection failed while processing file (%s) submitID (%s)" % (file_path, submitID))

    logging.info("update_status 600, submitID = %s, status = %s" % (submitID, str(status)))

def perform_scan(redis_client, ext_obj, QID, block_for_resp, queue_threshold, queue_wait, queue_timeout, submitID, track=False, remote_queue=None, queue_mapping=None):
  num_tries = 3
  got_result = False
  senderID = None

  logging.debug("[+] sending item to be scanned remote queue %s" % (remote_queue))

  ql = redis_client.sendMsg(QID, remote_queue, ext_obj)

  logging.debug("[+] Sent item to be scanned. (Queue Length: %d)" % (ql))

  if block_for_resp:
    send_time = datetime.datetime.utcnow()
    logging.info("Blocking for reply on QID %s" % (QID))
    res = None
    while num_tries > 0 and not got_result:
      senderID = None
      try:
        prerecv_time = datetime.datetime.utcnow()
        # TODO add a timeout here rather than the default of forever
        timeout = queue_timeout
        send_elapsed = (prerecv_time - send_time).total_seconds()

        if queue_timeout > send_elapsed:
           timeout = queue_timeout - send_elapsed

        msg = redis_client.recvMsg(QID, timeout=timeout, block=True)

        if not msg:
          raise RedisConnectionError("received empty result")

        res = msg.val
        senderID = msg.senderID

        recv_time = str((datetime.datetime.utcnow() - prerecv_time).total_seconds())

        got_result = True
        if res.source == 'failedscan':
          if submitID:
             update_status(redis_client, submitID, err_msg="failed scan", status="error")
          logging.warn("Found failed result returning False to rescan file: QID:%s, submitID:%s, rootUID:%s, senderID:%s, recv_time:%s" % (QID, submitID, str(res.rootUID), str(senderID), recv_time))
          return False
        logging.info("Reply complete for QID:%s submitID:%s, rootUID:%s, senderID:%s, recv_time:%s" % (QID, submitID, str(res.rootUID), str(senderID), recv_time))
        if track and submitID:
            disposition = None
            if hasattr(res, 'disposition'):
                disposition = res.disposition
            update_status(redis_client, submitID, status="complete", rootUID=res.rootUID, disposition=disposition)
        return True
      except ValueError as e:
        recv_time = str((datetime.datetime.utcnow() - prerecv_time).total_seconds())
        logging.warn("Value error while decoding result: QID:%s, submitID:%s, rootUID:%s, senderID:%s, recv_time:%s" % (QID, submitID, str(res.rootUID), str(senderID), recv_time))
      except RedisConnectionError as e:
        now = datetime.datetime.utcnow()
        recv_time = str((now - prerecv_time).total_seconds())
        logging.exception("ConnectionError while waiting on result: delaying 3 seconds QID:%s, submitID:%s, senderID:%s, recv_time:%s" % (QID, submitID, str(senderID), recv_time))
        time.sleep(3)
        send_elapsed = (now - send_time).total_seconds()
        if send_elapsed > queue_timeout:
            logging.warn("Max queue timeout reached aborting scan: QID:%s, submitID:%s, senderID:%s, recv_time:%s send_elapsed %d " % (QID, submitID, str(senderID), recv_time, str(send_elapsed)))
            num_tries = 0
      except Exception as e:
        recv_time = str((datetime.datetime.utcnow() - prerecv_time).total_seconds())
        num_tries = num_tries - 1
        logging.exception("Exception while decoding result: QID:%s, submitID:%s, senderID:%s, recv_time:%s" % (QID, submitID, str(senderID), recv_time))
    return False
  else:
    return ql

def queue_ready(obj, queue_name=None, **kwargs):
   now = time.mktime(datetime.datetime.utcnow().timetuple())
   remote_queue = obj.queue_mapping.get(queue_name, 'laikacollector')
   queue_state = _queue_states.get(remote_queue, {})
   wait_until = queue_state.get('wait_until', None)

   if wait_until:
       if wait_until > now:
           return False
       del queue_state['wait_until']

   try:
      current_ql, mem_usage  = obj.redis_client.getQueueInfo(remote_queue)
   except (RedisConnectionError, RedisBusyLoadingError, RedisMasterNotFoundError) as e:
      logging.exception("queue_ready conn/busy sleeping %d seconds" % (_wait_on_redis_conn_err))
      time.sleep(_wait_on_redis_conn_err)
      return False
 
   if not isinstance(mem_usage, int):
       mem_usage = 0

   if mem_usage >= obj.mem_threshold:
      logging.info('[+] Current remote queue:%s length of %d and mem usage %d of hit threshold of %dB memory used, disabling queue for %s seconds' % (remote_queue, current_ql, mem_usage, obj.mem_threshold, obj.queue_wait))
      _queue_states[remote_queue] = {'wait_until': now + obj.queue_wait}
      return False


   if current_ql >= obj.queue_threshold:
      logging.info('[+] Current remote queue:%s length of %d and mem usage %d of hit threshold of %d items, disabling queue for %s seconds' % (remote_queue, current_ql, mem_usage, obj.queue_threshold, obj.queue_wait))
      _queue_states[remote_queue] = {'wait_until': now + obj.queue_wait}
      return False

   return True

def process_file(obj, file_path, file_buffer, extra_metadata, file_format=None, queue_name=None, **kwargs):

  fname = file_path.split('/')[-1]
  logging.info("Processing file %s queue %s" % (fname, str(queue_name)))
  logging.info("Processing keys %s" % (list(extra_metadata.keys())))
  submitID = None
  track = False

  #f = open("/var/log/laikaboss/" + fname, 'w')
  #f.write(file_buffer)
  #f.close()

  remote_queue = obj.queue_mapping.get(queue_name, 'laikacollector')

  logging.info("Processing submit_file %s local queue:%s remote queue:%s len:%d" % (file_path, str(queue_name), str(remote_queue), len(file_buffer)))

  if obj.file_format == "submit":

      fname = file_path.split("/")[-1]
      submitID = fname[fname.rfind("-") + 1 : fname.rfind(".")]

      try:
         externalObject = ExternalObject.decode(file_buffer)
      except Exception as e:
         error_path = os.path.join(obj.error_dir, os.path.basename(file_path) + ".decode_failure")
         time.sleep(2)
         shutil.copy(file_path, error_path)

         logging.exception("Error decoding file: " + fname + ' submitID=' + submitID + ' copying file to exception directory as ' + str(error_path))

         raise e

      if obj.max_size > 0 and len(file_buffer) > obj.max_size:
         time.sleep(2)
         logging.error("File too large: " + fname + ' submitID=' + submitID)
         raise ValueError("File too large:" + fname)

      if not externalObject.externalVars.filename:
          externalObject.externalVars.filename = fname

      externalObject.externalVars.submitID = submitID

      if externalObject.externalVars.submitter:
          track = True

      logging.info("Processing submit_file track = %s submitID = %s" % (str(track), submitID))

      if track and submitID:
         logging.info("Processing about to track submitID = %s" % (submitID))
         update_status(obj.redis_client, submitID, "processing", file_path=file_path)

  else:
      externalObject = ExternalObject(buffer=file_buffer, externalVars=ExternalVars(filename=fname, source=obj.ext_source))

  message_id = get_message_id(file_buffer)

  QID = "lbworker:%s:%s:%d:%s" % (obj.hostname, str(submitID), os.getpid(), binascii.hexlify(os.urandom(5)).decode('ascii'))

  # Sleep until current time is past the delay for submission
  if 'submission_delay' in configs:
     mod_time = os.path.getmtime(file_path)
     time_to_wait = 0
     submission_delay = int(configs['submission_delay'])
     if submission_delay > 0:
        # orig_put_time convert to seconds from microseconds
        time_to_wait = (mod_time + submission_delay) - time.time()

     if time_to_wait > 0:
        logging.info('Sleeping for %d for submission delay on %s with path %s' % (time_to_wait, message_id, file_path))
        time.sleep(time_to_wait)

     if 'submission_avg_delay' in configs:
         submission_sleep_delay = float(configs['submission_avg_delay'])
         if submission_sleep_delay > 0.0:
            delay = (submission_sleep_delay + submission_sleep_delay*float(0.5 - randint(1,100)/100.0))/1000.0
            logging.warn("submit sleep delay as not to overload cluster time:%f" % (delay))
            time.sleep(delay)

  return perform_scan(obj.redis_client, externalObject, QID , obj.block_for_resp, obj.queue_threshold, obj.queue_wait, obj.queue_timeout, submitID, track, remote_queue, obj.queue_mapping)

def post_action(obj, file_path):
  logging.debug("Post action on %s" % (file_path))
  '''
  try:
     # fully qualifying the dest should force it overwrite an existing file with the same name if it occurs
     shutil.move(file_path, os.path.join("/tmp", os.path.basename(file_path)))
  except e:
     logging.exception("Error moving file %s" % (file_path))
     return False
  '''

  return True


def get_message_id(smtp_session):
  r = msgid_regex.findall(smtp_session)
  if r:
    return r[0]
  return ''

def getConfig(option):
  value = ''

  if option:

       if option in configs:
          value = configs[option]

       if not value:
          value = default_configs.get(option)

  return value

def main():

  parser = OptionParser(usage="usage: %prog [options] (/path/to/file | stdin)")

  parser.add_option("-d", "--debug",
                    action="store_true", default=False,
                    dest="debug",
                    help="enable debug messages to the console.")
  parser.add_option("--redis-url",
                    action="store", type="string",
                    dest="redis_url",
                    help="specify an address for Redis queue server")
  parser.add_option("-q", "--redis-work-queue",
                    action="store", type="string",
                    dest="redis_work_queue",
                    help="specify the Redis queue where work should be retrieved")
  parser.add_option("-t", "--queue-threshold",
                    action="store", type="int",
                    dest="queue_threshold",
                    help="specify the queue threshold for Redis for when to block to avoid overloading Redis queue")
  parser.add_option("--file-format",
                    action="store", type="str",
                    dest="file_format",
                    help="specify the queue threshold for Redis for when to block to avoid overloading Redis queue")
  parser.add_option("--submission-delay",
                    action="store", type="int",
                    dest="submission_delay",
                    help="specify the wait time before processing the file")
  parser.add_option("--submission-avg-delay",
                    action="store", type="int",
                    dest="submission_avg_delay",
                    help="specify avg time to wait the wait time before processing the file - used to not overload the queues")
  parser.add_option("--queue-wait",
                    action="store", type="int",
                    dest="queue_wait",
                    help="specify the wait time when Redis queue threshold is met")
  parser.add_option("--queue-timeout",
                    action="store", type="int",
                    dest="queue_timeout",
                    help="specify the max timeout waiting on a submission to complete")
  parser.add_option("--max-size",
                    action="store", type="int",
                    dest="max_size",
                    help="specify the max size for input files. Set to -1 for unlimited. Default:" + str(default_configs["max_size"]))
  parser.add_option("--mem-threshold",
                    action="store", type="int",
                    dest="mem_threshold",
                    help="specify the max size in bytes for queue. Set to -1 for unlimited. Default:" + str(default_configs["mem_threshold"]))
 
  parser.add_option("--submission-dir",
                    action="store", type="string",
                    dest="submission_dir",
                    help="input directory of where files should be scanned")
  parser.add_option("--submission-error-dir",
                    action="store", type="string",
                    dest="submission_error_dir",
                    default=None,
                    help="error directory of failed scans")
  parser.add_option("--num-workers",
                    action="store", type="string",
                    dest="num_workers",
                    default=None,
                    help="number of workers")
  parser.add_option("--conf",
                    dest="conf",
                    default="/etc/laikaboss/laikacollector.conf",
                    help="source value use by dispatcher")
  parser.add_option("--local-queues",
                    dest="local_queues",
                    default="webUI",
                    help="list of in local queues to be round robinend through, order will be randomized, but you can specify a queue more than once to increase priority")
  parser.add_option("--source",
                    dest="source",
                    help="source value use by dispatcher")

  (options, file_list) = parser.parse_args()

  if options.debug:
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - [laikacollector] PID: %(process)d - %(message)s', datefmt="%Y-%m-%d %H:%M:%S%Z")

  init_config(options.conf, opts=options)

  redis_url = getConfig('redis_url')

  queue = getConfig('redis_work_queue')

  submission_dir = getConfig('submission_dir')

  queue_timeout = getConfig('queue_timeout')

  submission_error_dir = getConfig('submission_error_dir')

  hostname = getConfig('hostname')

  ext_source = getConfig('source')

  max_size = int(getConfig('max_size'))

  ext_format = getConfig('file_format')

  queue_mapping, weighted_queues = parse_local_queue_info(getConfig('queue_mapping'))

  local_queues = list(queue_mapping.keys())

  queue_threshold = int(getConfig('queue_threshold'))

  queue_wait = int(getConfig('queue_wait'))

  mem_threshold = int(getConfig('mem_threshold'))

  if "LAIKA_HOSTNAME" in os.environ:
     hostname = os.environ["LAIKA_HOSTNAME"]

  if not hostname:
     hostname = socket.gethostname()

  if '.' in hostname:
     hostname = hostname[:hostname.find('.')]

  if ext_source:
     ext_source = ext_source.replace("%LAIKA_HOSTNAME", hostname)
     ext_source = ext_source.replace("%HOST", hostname)
  else:
     ext_source = hostname

  # Initialize Redis client
  redis_client = Client(url=redis_url, work_queue=queue)

  # get the number of castleblack workers to spawn
  num_workers = int(getConfig('num_workers'))

  disk_queues = [f for f in os.listdir(submission_dir) if os.path.isdir(os.path.join(submission_dir, f)) and not f.startswith(".")]

  weighted_queues.extend([f for f in disk_queues if f not in local_queues])

  cb.init(queues=local_queues)

  extra_meta = {'hostname': hostname, 'redis_client': redis_client, 'block_for_resp': True, 'remove_after_processing': True, 'ext_source': ext_source, 'file_format': ext_format, 'queue_threshold': queue_threshold, 'queue_wait': queue_wait, 'queue_timeout': queue_timeout, 'queue_mapping': queue_mapping, 'max_size':max_size, 'mem_threshold':mem_threshold}

  logging.info('start up configs %s' % (str(extra_meta)))

  # initialize castle black workers
  workers = {}

  if file_list:
     process_file_list(file_list, extra_meta, queue)
     exit(0)

  for i in range(num_workers):
    # Setup Castleblack to monitor
    worker = cb.NightsWatch(process_file, post_action, queue_ready=queue_ready, error_threshold=5, error_wait=10, error_dir=submission_error_dir, queue_selector_args={'weighted_queues':local_queues}, **extra_meta)
    worker_name = "worker_" + str(i + 1)
    # save reference to the castleblack worker
    workers[worker_name] = worker
    logging.info('starting worker with name %s' % (worker_name))
    worker.start()

  cb.observe(submission_dir, extension=".submit", process_existing_files=True, enable_created=True, enable_moved=True, resolve_queue=cb.resolve_queue_name_by_dir)

if __name__ == '__main__':
  main()
