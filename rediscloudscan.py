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
from __future__ import print_function

from laikaboss.objectmodel import ExternalObject, ExternalVars
from laikaboss.redisClientLib import Client, getJSON
from laikaboss.constants import level_metadata
import sys
from optparse import OptionParser
from random import randint
from laikaboss.lbconfigparser import LBConfigParser

# Variable to store configs from file
configs = {}

# Defaults for all available configurations
# To be used if not specified on command line or config file
default_configs = {
    'redis_url' : 'redis://127.0.0.1:6379/0',
    'redis_work_queue': 'laikacollector',
    'queue_threshold': 25,
    'queue_wait': 10,
    'source': "CLICLOUDSCAN",
    'queue_timeout': 60 * 60,
}

def getConfig(option):
  value = ''

  if option:

       if option in configs:
          value = configs[option]

       if not value:
          value = default_configs.get(option)

  return value


def init_config(conf_file, opts):
    # Read the laikad config file
    config_parser = LBConfigParser()
    config_parser.read(conf_file, opts=opts)
    configs.update(dict(config_parser.items("DEFAULT")))
    configs.update(dict(config_parser.items("General")))

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
  parser.add_option("--file-format",
                    action="store", type="str",
                    dest="file_format",
                    help="specify the queue threshold for Redis for when to block to avoid overloading Redis queue")
  parser.add_option("--conf",
                    dest="conf",
                    default="/etc/laikaboss/laikaboss.conf",
                    help="source value use by dispatcher")
  parser.add_option("--source",
                    dest="source",
                    help="source value use by dispatcher")

  identity = "%04X-%04X" % (randint(0, 0x10000), randint(0, 0x10000))

  (options, file_list) = parser.parse_args()

  if options.debug:
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - [laikacollector] PID: %(process)d - %(message)s', datefmt="%Y-%m-%d %H:%M:%S%Z")

  init_config(options.conf, opts=options)

  redis_url = getConfig('redis_url')
  redis_work_queue = getConfig('redis_work_queue')
  source = getSource('source')

  try:
    file_buffer = ''
    if len(file_list) == 1:
      file_buffer = open(file_list[0], 'rb').read()
    else:
      print("Please supply file to scan")
      sys.exit(1)
  except IOError as e:
    sys.exit(1)


  fname = file_list[0]
  client = Client(url=redis_url, work_queue=redis_work_queue)

  if obj.file_format == 'submit':

      submitID = None
      fname = file_path.split("/")[-1]
      try:
         submitID = fname[fname.rfind("-") + 1 : fname.rfind(".")]
      except:
         pass

      try:
         externalObject = ExternalObject.decode(file_buffer)
      except Exception as e:
         logging.exception("Error decoding file: " + fname + ' submitID=' + submitID + ' copying file to exception directory as ' + str(error_path))
         raise e

      if not externalObject.externalVars.filename:
          externalObject.externalVars.filename = fname

      if submitID:
         externalObject.externalVars.submitID = submitID

  externalObject = ExternalObject(buffer=file_buffer, externalVars=ExternalVars(filename=fname), level=level_metadata, source=source)

  ql = client.sendMsg(identity, redis_work_queue, externalObject)

  print("[+] Sent item to be scanned. Blocking for reply... (Queue Length: %d)" % (ql))

  result = client.recvMsg(identity, block=True)

  print(getJSON(result.val))

if __name__ == '__main__':
  main()
