#!/usr/bin/env python
#
# Copyright 2016 Lockheed Martin Corporation
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
# laika_redis_client.py
#   Middleware script for pulling extracted Suricata files from Redis and 
#   sending to Laika BOSS.
#
import json
import os
import redis
import signal
import sys
from argparse import ArgumentParser
from laikaboss.objectmodel import ExternalObject, ExternalVars
from laikaboss.constants import level_minimal
from laikaboss.clientLib import Client

def handler(signum, frame):
    '''
    Signal handler for graceful exit.
    '''
    print "\n\nSignal %s received. Exiting." % (str(signum))
    sys.exit(0)

def delete_keys(redis_conn, key):
    '''
    Delete keys from Redis once they have been used.
    '''
    redis_conn.delete("%s_buf" % (key))
    redis_conn.delete("%s_meta" % (key))

def main(laika_broker, redis_host, redis_port):
    # Register signal handler
    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)
    
    # Connect to Redis
    r = redis.StrictRedis(host=redis_host, port=redis_port)
    
    # Create Laika BOSS client object
    client = Client(laika_broker, async=True)
    
    while True:
        # pop next item off queue
        q_item = r.blpop('suricata_queue', timeout=0)
        key = q_item[1]

        print "Popped object: %s" % (key)
    
        # look up file buffer
        file_buffer = r.get("%s_buf" % (key))

        # look up file file meta
        file_meta = r.get("%s_meta" % (key))

        if not file_buffer or not file_meta:
            print "File buffer or meta for key: %s not found. Skipping this object." % (key)
            delete_keys(r, key)
            continue
    
        try:
            file_meta_dict = json.loads(file_meta)
        except:
            print "JSON decode error for key: %s. Skipping this object." % (key)
            delete_keys(r, key)
            continue

        # Extract File Name
        # Note: this is best effort - it will not always work
        filename = os.path.basename(file_meta_dict['http_request'].get('request', ""))
        filename = filename.split('?')[0]

        # Get respective content type
        http_direction = file_meta_dict['http_direction']
        if http_direction == 'request':
            content_type = file_meta_dict['http_request'].get('Content-Type', [])
        elif http_direction == 'response':
            content_type = file_meta_dict['http_response'].get('Content-Type', [])
        else:
            content_type = []
 
        externalObject = ExternalObject(buffer=file_buffer,
                externalVars=ExternalVars(filename=filename,
                    source="%s-%s" % ("suricata", "redis"),
                    extMetaData=file_meta_dict,
                    contentType=content_type),
                level=level_minimal)
    
        # send to Laika BOSS for async scanning - no response expected
        client.send(externalObject)

        print "Sent %s for scanning...\n" % (key)

        # cleanup
        delete_keys(r, key)

if __name__ == '__main__':
    parser = ArgumentParser(description=
            '''
            Middleware script for pulling extracted Suricata files from Redis and sending to Laika BOSS
            ''')
    parser.add_argument('-b', '--broker', action='store', dest='broker', default='tcp://localhost:5558',
            help='Laika BOSS broker (Default: tcp://localhost:5558)')
    parser.add_argument('-r', '--rhost', action='store', dest="rhost", default="localhost",
            help='Redis host (Default: localhost)')
    parser.add_argument('-p', '--rport', action="store", dest="rport", default=6379,
            help='Redis port (Default: 6379)')
    args = parser.parse_args()

    main(args.broker, args.rhost, args.rport)
