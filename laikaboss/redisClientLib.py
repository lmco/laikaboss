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
from builtins import str
from builtins import object
import logging
from laikaboss.objectmodel import ExternalObject, ScanResult
import redis

import zlib
from copy import deepcopy as clone_object
import json
from collections import OrderedDict, namedtuple
import time

QueueMsg = namedtuple('QueueMsg', ['senderID', 'msg_type', 'val'])

_worker_prefix="lbworker:*"
_sleep_connection_err = 5

def parse_local_queue_info(queue_info):

    queue_mapping = OrderedDict()
    weighted_queues = []

    local_queues = [x.strip() for x in queue_info.split(',')]

    for x in local_queues:
       queue_weight = 1
       info = x.split(":")
       queue_name = info[0]
       redis_queue = info[1]
       if len(info) > 2:
          queue_weight = info[2]
       queue_mapping[queue_name] = redis_queue
       weighted_queues.extend([queue_name] * int(queue_weight))

    return queue_mapping, weighted_queues

#redis_queue_mapping=laikacollector-email:5, laikacollector-webui:3
def parse_remote_queue_info(queue_info):

    weighted_queues = []

    local_queues = [x.strip() for x in queue_info.split(',')]

    for x in local_queues:
       queue_weight = 1
       info = x.split(":")
       redis_queue = info[0]
       if len(info) > 1:
          queue_weight = info[1]
       weighted_queues.extend([redis_queue] * int(queue_weight))

    return weighted_queues


class Client(object):

  def __init__(self, url='unset', work_queue='laikaboss', redis_client=None, **kwargs):

    from laikaboss.storage_utils import redisclient_from_url

    self.url = url
    self.work_queue = work_queue
    self.connect_kwargs = kwargs
    if redis_client:
        self.redis_client = redis_client
    else:
        self.redis_client = redisclient_from_url(self.url, **kwargs)

  def get(self, key, timeout=0):
     val = self.redis_client.get(key)

     try:
       val = json.loads(val)
     except:
       pass

     return val

  def delete(self, key):
     self.redis_client.delete(key)
     return None

  def __repr__(self):
        return "<Client url:%s work_queue:%s>" % (self.url, self.work_queue)

  def __str__(self):
        return "<Client url:%s work_queue:%s>" % (self.url, self.work_queue)

  def set(self, key, val, timeout=0, expire=-1):

     val = json.dumps(val)
     self.redis_client.set(key, val)
     if expire > 0:
        self.redis_client.expire(key, expire)

  @staticmethod
  def encode(senderID, val):

    enc_format='3'

    if not senderID:
       senderID = ''

    if isinstance(val, ExternalObject):
       msg_type = 'o'
       val_s = ExternalObject.encode(val)
    elif isinstance(val, ScanResult):
       msg_type = 'r'
       val_s = ScanResult.encode(val)
    else:
       raise ValueError("unknown value type for encoding")

    val = enc_format + ',' + msg_type + ',' + senderID + ',' + val_s.decode('utf-8')
    val = val.encode('utf-8')
    zval = zlib.compress(val)

    return zval

  @staticmethod
  def decode(buf):

    senderID=None
    msg_type=''
    val=''
    val_s = ''

    buf = zlib.decompress(buf)

    items = buf.split(b',', 3)

    enc_format = items[0].decode("utf-8")

    if len(items) == 2:

       senderID = items[0].decode("utf-8")
       val_s = items[1].decode("utf-8")
       msg_type = 'o'

    elif enc_format == '3':

       msg_type = items[1].decode("utf-8")
       senderID = items[2].decode("utf-8")
       val_s = items[3].decode("utf-8")


    if msg_type == "o":
       val = ExternalObject.decode(val_s)
    else:
       val = ScanResult.decode(val_s)

 
    ret = QueueMsg(senderID=senderID,val=val,msg_type=msg_type)

    #QueueMsg named tuple
    return ret

  def sendMsg(self, senderID, msg_queue, val, retry=0, timeout=0, expire=0):

    # TODO: Retry mechanism

    val = Client.encode(senderID, val)

    logging.debug("sendMsg to redis queue: " + msg_queue + " on behalf of sender:" + senderID)

    try:
       queue_len = self.redis_client.rpush(msg_queue, val)
    except(redis.exceptions.ConnectionError, redis.exceptions.BusyLoadingError):
         time.sleep(_sleep_connection_err)
         raise

    if expire:
       self.redis_client.expire(msg_queue, expire)

    return queue_len

  def recvMsg(self, msg_queue=None, block=False, timeout=0):

    #log even lower than debug
    #logging.log(5, "recvRequest on redis queue: " + msg_queue)

    try:
        if block:
            val = self.redis_client.blpop(msg_queue, timeout=timeout)
            #val[0] is just the name of the queue it found it on
            if val:
               val = val[1]
        else:
            val = self.redis_client.lpop(msg_queue)
    except(redis.exceptions.ConnectionError, redis.exceptions.BusyLoadingError):
         time.sleep(_sleep_connection_err)
         raise

    if not val:
      # Timeout happened or invalid object returned
      return None
    else:
      ret = Client.decode(val)
     
    #QueueMsg named tuple
    return ret


  def getQueueInfo(self, work_queue=None):

    queue = self.work_queue 
    if work_queue:
        queue = work_queue

    logging.debug("getting queue length and size on queue: " + queue)
    len1 = self.redis_client.llen(queue)
    #mem_usage = self.redis_client.dbsize()
    #logging.error("before mem usage")
    mem_usage = self.redis_client.memory_usage(queue, 0)
    #logging.error("after mem usage")
    logging.debug("queue length:" + str(len1) + " queue: "+ queue + " mem usage of " + str(mem_usage) + " bytes")

    return len1, mem_usage

  def list(self, key = None):

    result = []
 
    if not key:
      key = self.work_queue

    logging.debug("retrieve all objects on redis_queue: " + key)

    items = self.redis_client.lrange(key, 0, -1)

    if items:
      for x in items:
         result.append(self.decode(x))

    return result

  def listReplyQueues(self):

    resultDict = {}

    logging.debug("retrieve all objects on worker reply queues")

    for workerid in self.redis_client.scan_iter(_worker_prefix):
         worker = []
         for key in workerid:
           worker.append(self.decode(key))
         resultDict[workerid] = worker

    return resultDict

  def test(self, work_queue = None):
      import os,binascii

      key = binascii.b2a_hex(os.urandom(15))
      value = binascii.b2a_hex(os.urandom(15))

      logging.debug("writing random k=v %s = %s  " % (key, value))

      self.redis_client.set(key, value)

      logging.debug("reading key %s" % (key))

      value2 = self.redis_client.get(key)

      if value2 != value:
         logging.error("Error reading the same value to redis as was written")
         return False

      logging.debug("deleting key %s" % (key))
      self.redis_client.delete(key)

      return True

  def purgeWorkQueue(self, work_queue = None):

    queue = self.work_queue 
    if work_queue:
        queue = work_queue

    logging.debug("remove all objects on redis_queue: " + queue)

    self.redis_client.delete(queue)

    return

  def purgeReplyQueues(self):

    logging.debug("remove all worker reply queues")

    for workerid in self.redis_client.scan_iter(_worker_prefix):
       self.redis_client.delete(workerid)

    return


def getRootObject(result):
  '''
  Returns the ScanObject in a result set that contains no parent (making it the root).

  Arguments:
  result -- a fully populated scan result set

  Returns:
  The root ScanObject for the result set.
  '''
  return result.files[result.rootUID] #ScanObject type

def getJSON(result, pretty=True):
  '''
  This function takes the result of a scan, and returns the JSON output.

  Arguments:
  result -- a fully populated scan result set.

  Returns:
  A string representation of the json formatted output.
  '''
  resultText = ''

  # Build the results portion of the log record. This will be a list of
  # dictionaries, where each dictionary is the result of a single buffer's
  # scan. The list will contain all of the buffers that were exploded from
  # a root buffer's scan in the order they were processed.
  buffer_results = [None] * len(result.files)
  #print "Result files length: %d" % (len(result.files))
  for scan_object in result.files.values():
    # Do not damage the original result -> clone
    if isinstance(scan_object, dict):
        buffer_result = clone_object(scan_object)
    else:
        buffer_result = clone_object(scan_object.__dict__)
    # Don't log buffers here, just metadata
    if "buffer" in buffer_result:
      del buffer_result["buffer"]
    buffer_results[buffer_result["order"]] = buffer_result

  # Construct the log record with fields useful for log processing and
  # routing
  log_record = {
    'source': result.source,
    'scan_result': buffer_results
  }
  if pretty:
    resultText = json.dumps(log_record, indent=4, sort_keys=True)
  else:
    resultText = json.dumps(log_record)
  return resultText
