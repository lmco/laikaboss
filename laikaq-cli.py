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

from __future__ import print_function
from builtins import str
from laikaboss.redisClientLib import Client
from optparse import OptionParser
from laikaboss.lbconfigparser import LBConfigParser
from laikaboss.redisClientLib import parse_remote_queue_info

# Variable to store configs from file
configs = {}

# Defaults for all available configurations
# To be used if not specified on command line or config file
default_configs = {
    'redis_url': 'redis://127.0.0.1:6379/0',
    'work_queues': 'laikacollector',
}

def init_config(conf_file):
    # Read the laikad config file
    config_parser = LBConfigParser()
    config_parser.read(conf_file)

    # Parse through the config file and append each section to a single dict
    for section in config_parser.sections():
        configs.update(dict(config_parser.items(section)))


def getConfig(option):
  value = ''

  if option:

     if not isinstance(option, list):
        option = [option]

     for key in option:
       if key in configs:
          value = configs[key]
          break

     if not value:
        for key in option:
           if key in default_configs:
              value = default_configs[key]
              break

  return value


def main():

  configs = {}

  parser = OptionParser(usage="usage: %prog action [options] [where action is count, test, purge_work_queue, purge_all_work_queues, purge_reply_queues, get]")

  parser.add_option("-d", "--debug",
                    action="store_true", default=False,
                    dest="debug",
                    help="enable debug messages to the console.")
  parser.add_option("-r", "--reply",
                    action="store_true", default=False,
                    dest="reply",
                    help="enable debug messages to the console.")
  parser.add_option("--redis-url",
                    action="store", type="string",
                    dest="redis_url",
                    help="specify an address for Redis queue server")
  parser.add_option("-q", "--work-queues",
                    action="store", type="string",
                    dest="work_queues",
                    help="specify the Redis queue where work should be retrieved")
  parser.add_option("-t", "--test",
                    action="store_true", default=False,
                    dest="test",
                    help="specify the identity that is used by this scan (ignored if more than one worker)")
  parser.add_option("--conf",
                    dest="conf",
                    default="/etc/laikaboss/laikacollector.conf",
                    help="source value use by dispatcher")

  (options, args) = parser.parse_args()

  if len(args) == 0:
     parser.error('action not given')

  action = args[0]

  init_config(options.conf)

  if options.work_queues:
     queue_mappings = options.work_queues
  else:
     queue_mappings = getConfig('work_queues')

  queues = parse_remote_queue_info(queue_mappings)

  queue = queues[0]

  queues = list(set(queues))

  if options.redis_url:
    redis_url = options.redis_url
  else:
    redis_url = getConfig('redis_url')

  print("queues`:" + str(queues))
  print("redis-url:" + redis_url)

  # Initialize Redis client
  redis_client = Client(url=redis_url, work_queue=queue)

  if action == 'count':
    for x in queues:
       print("queue:%s count:%d" % (x, len(redis_client.list(x))))

    if options.reply == True:
       print("worker count:" + str(len(list(redis_client.listReplyQueues().keys()))))

  if action == 'test':
      if redis_client.test():
         print("Test succeeded!")
      else:
         print("Test failed")

  if action == 'purge_work_queue':
     print(redis_client.purgeWorkQueue(queue))

  if action == 'purge_all_work_queues':
    for queue in queues:
       print(redis_client.purgeWorkQueue(queue))

  if action == 'purge_reply_queues':
     print(redis_client.purgeReplyQueues())

  if action == 'list':
     print(redis_client.list())
  
  if action == 'info':
     print(redis_client.getQueueInfo(queue))

if __name__ == '__main__':
  main()
