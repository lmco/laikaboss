#!/usr/bin/env python
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

'''
laikadq

Command line program for running the broker and worker processes for the Laika
framework. This program becomes the supervisor process that ensures the broker
and worker processes remain up and alive (replaces those that go missing).
'''
from __future__ import division
from __future__ import print_function

from future import standard_library
standard_library.install_aliases()
from builtins import str
from past.utils import old_div
from laikaboss.lbconfigparser import LBConfigParser
import functools
from interruptingcow import timeout
import logging
from multiprocessing import Process
from optparse import OptionParser
import os
from random import randint
import random
import signal
from laikaboss.objectmodel import ScanResult, ScanObject, QuitScanException
import syslog
import time
import json
import redis
import socket
from laikaboss.redisClientLib import parse_remote_queue_info, Client

_redis_work_reply_expiration=300

AVAILABLE_QUEUES = ["redis"]

SHUTDOWN_GRACE_TIMEOUT_DEFAULT = 30

# Status values for the state of a worker
LRU_READY = "\x01"          # Ready for work
LRU_RESULT_READY = "\x02"   # Here is the previous result, ready for more work
LRU_RESULT_QUIT = "\x03"    # Here is the previous result, I quit
LRU_QUIT = "\x04"           # I quit
REQ_TYPE_PICKLE = '1'
REQ_TYPE_PICKLE_ZLIB = '2'
REQ_TYPE_JSON = '3'
REQ_TYPE_JSON_ZLIB = '4'

# Class to serialize laikaboss objects to json
class ResultEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, ScanObject):
            newdict = obj.__dict__.copy()
            del newdict['buffer']
            return newdict
        if isinstance(obj, ScanResult):
            res = {}
            res['rootUID'] = obj.rootUID
            res['source'] = obj.source
            res['level'] = obj.level
            res['startTime'] = obj.startTime
            tmpFiles = {}
            for uid, sO in obj.files.items():
                tmpFiles[str(uid)] = sO
            res['files'] = tmpFiles
            return res
        return json.JSONEncoder.default(self,obj)

# Variable to store configuration options from file
CONFIGS = {}

# Defaults for all available configurations
# To be used if not specified on command line or config file
DEFAULT_CONFIGS = {
    'numprocs': '4',
    'ttl': '1000',
    'time_ttl': '30',
    'gracetimeout': '30',
    'queue_type': 'redis',
    'workerpolltimeout': '300',
    'log_result' : 'False',
    'laikad_dev_config_path' : 'etc/laikad/laikad.conf',
    'laikad_sys_config_path' : '/etc/laikaboss/laikad.conf',
    'redis_url' : 'redis://127.0.0.1:6379/0',
    'work_queues' : 'laikacollector,laikacollector-webui',
    'id_file': '/var/laikaboss/laikad_redis_id_file'
    }

def log_debug(message):
    '''Log a debug message'''
    syslog.syslog(syslog.LOG_DEBUG, "DEBUG (%s) %s" % (os.getpid(), message))

def get_option(option, default=''):
    '''Get the value of an option from the configuration'''
    value = default
    if option in CONFIGS:
        value = CONFIGS[option]
    elif option in DEFAULT_CONFIGS:
        value = DEFAULT_CONFIGS[option]
    return value

def shutdown_handler(proc, signum, frame):
    '''
    Signal handler for shutting down the given process.

    Arguments:
    proc    --  The process that should be shutdown.

    '''
    logger.debug("Shutdown handler triggered (%d)", signum)
    proc.shutdown()

class queue_selector():

    def __init__(self, queue_list, **kwargs):

        self.randomize = True
        self.queues = queue_list
        queue_set = list(set(queue_list))
        #self.queues = kwargs.get('weighted_queues', None)
        self.randomize = kwargs.get('randomize', True)

        # don't bother if the weights being used
        if len(self.queues) == len(queue_set):
           self.randomize = False

    def cycle_length(self):
        return len(self.queues)

    def generator(self):
        while True:
           if self.randomize:
               random.shuffle(self.queues)
           for queue in self.queues:
               yield queue

class RedisWorker(Process):
    def __init__(self, redis_url, queue_list, selector_queue_config, identity, config_location, max_scan_items, ttl, gracetimeout=SHUTDOWN_GRACE_TIMEOUT_DEFAULT):

        super(RedisWorker, self).__init__()
        self.redis_url = redis_url
        self.identity = identity
        self.config_location = config_location
        self.max_scan_items = max_scan_items
        self.ttl = ttl
        self.gracetimeout = gracetimeout
        self.keep_running = False

        if selector_queue_config is None:
            selector_queue_config = {}

        selector = queue_selector(queue_list, **selector_queue_config)
        self.get_next_queue = selector.generator()
        self.cycle_length = selector.cycle_length()
        self.redis_client = Client(redis_url, retry_on_timeout=True)

    def shutdown(self):
        '''Shutdown method to be called by the signal handler'''
        logging.debug("Worker (%s): shutdown handler triggered", self.identity)
        self.keep_running = False
        raise QuitScanException()

    def run(self):

        from laikaboss import config
        from laikaboss.dispatch import close_modules
        from laikaboss.util import init_logging

        logger.debug("Using config %s", self.config_location)
        config.init(path=self.config_location)
        init_logging()

        self.keep_running = True

        # Add intercept for graceful shutdown
        def shutdown(signum, frame):
            '''Signal handler for shutting down supervisor gracefully'''
            logging.debug("Supervisor: shutdown handler triggered")
            global KEEP_RUNNING
            KEEP_RUNNING = False

        # Add intercept for graceful shutdown
        signal.signal(signal.SIGTERM, functools.partial(shutdown_handler, self))
        signal.signal(signal.SIGINT, functools.partial(shutdown_handler, self))

        # Indicators for worker expiration
        counter = 0
        start_time = time.time() + randint(1, 60)

        # Check first to see if this individual worker (and not the entire process/box) failed mid-scan
        emptyCount = 0

        should_quit = False

        # Read from designated work queue based on identity
        while self.keep_running:

            queue_name = next(self.get_next_queue)

            result = None
            msg = None
            submitID = ""

            try:
                #logger.debug("[+] RedisWorker %s waiting on work queue:%s url:%s" % (self.identity, queue_name, self.redis_url))
                msg = self.redis_client.recvMsg(queue_name)

                if not msg:
                   emptyCount+=1
                    # don't overwelm the processor if there is no input to process
                   if self.cycle_length == emptyCount:
                        emptyCount = 0
                        #logging.info("Worker: sleeping because all redis queues were empty")
                        time.sleep(.1)
                   continue

                submitID = msg.val.externalVars.submitID

                logger.debug("[+] RedisWorker %s picked up work with reply queue %s" % (self.identity, msg.senderID))
                # Pushing the identity of the laikacollector worker to an "in process" queue so we know who 
                # to notify about failed scans (to be rescanned) 
                # Expire this key after 1 day so we don't continually clog up queue
                self.redis_client.set('%s-work' % (self.identity), [msg.senderID, submitID], expire=86400)

                logger.debug("[+] RedisWorker %s is starting scan" % (self.identity))

                result = self.perform_scan(msg.val)


            except redis.ConnectionError as e:
                logger.exception(" [+] RedisWorker %s error - possible missing steps" % (self.identity))
                #logger.debug("RedisWorker Connection Error: %s" % (str(e)))
                #logger.debug("Attempting to reconnect...")
                result = ScanResult(source='failedscan', submitID=submitID)
            except Exception as e:
                logger.exception("error near scan")
                result = ScanResult(source='failedscan', submitID=submitID)

            if msg and msg.senderID and result:
               try:
                  logger.debug("[+] RedisWorker %s sending result to reply queue: %s" % (self.identity, msg.senderID))
                  counter += 1
                  should_quit = (
                      counter >= self.max_scan_items or
                      (old_div((time.time() - start_time),60)) >= self.ttl or
                      not self.keep_running)

                  logger.debug("[+] RedisWorker %s rpush starting to reply queue: %s: result:%s" % (self.identity, msg.senderID, str(result)))

                  # Set this result to expire after some time to avoid clogger redis box
                  x = self.redis_client.sendMsg(self.identity, msg.senderID, result, expire=_redis_work_reply_expiration)

                  logger.debug("[+] RedisWorker %s rpush complete to reply queue: %s expire command is next x=%d" % (self.identity, msg.senderID, x))

                  # Unset current work for this client
                  self.redis_client.delete('%s-work' % (self.identity))

                  logger.debug("[+] RedisWorker %s delete to queue: %s-work " % (self.identity, msg.senderID))

               except Exception as e:
                    logger.exception(e)

            if should_quit:
               self.keep_running = False
        try:
            with timeout(self.gracetimeout, exception=QuitScanException):
                close_modules()
        except QuitScanException:
            logging.debug("Worker (%s): Caught scan termination exception during destruction", self.identity)
        log_debug("Worker %s dying after %i objects and %i seconds" % (
            self.identity, counter, time.time() - start_time))

        logging.debug("Worker (%s): finished", self.identity)

    def perform_scan(self, externalObject):

        from laikaboss.dispatch import Dispatch
        from laikaboss.objectmodel import ScanResult

        result = ScanResult(source=externalObject.externalVars.source,level=externalObject.level, submitID=externalObject.externalVars.submitID)
        result.startTime = time.time()

        try:
            Dispatch(externalObject.buffer, result, 0, externalVars=externalObject.externalVars)
        except QuitScanException:
            raise

        return result

# Globals to share in the signal hander
KEEP_RUNNING = True
logger = None

def main():
    '''Main program logic. Becomes the supervisor process.'''
    parser = OptionParser(usage="usage: %prog [options]\n"
        "Default settings in config file: laikad.conf")

    parser.add_option("-d", "--debug",
                      action="store_true", default=False,
                      dest="debug",
                      help="enable debug messages to the console.")
    parser.add_option("-q", "--queue-type",
                      action="store", default="redis",
                      dest="queue_type",
                      help="queueing mechanism to use. available options: %s. default: redis" % (', '.join(AVAILABLE_QUEUES)))
    parser.add_option("-c", "--laikad-config",
                      action="store", type="string",
                      dest="laikad_config_path",
                      help="specify a path for laikad configuration")
    parser.add_option("-i", "--id",
                      action="store", type="string",
                      dest="runas_uid",
                      help="specify a valid username to switch to after starting "
                      "as root.")
    parser.add_option("-p", "--processes",
                      action="store", type="int",
                      dest="num_procs",
                      help="specify the number of workers to launch with this "
                      "daemon")
    parser.add_option("-r", "--restart-after",
                      action="store", type="int",
                      dest="ttl",
                      help="restart worker after scanning this many items")
    parser.add_option("-t", "--restart-after-min",
                      action="store", type="int",
                      dest="time_ttl",
                      help="restart worker after scanning for this many "
                      "minutes.")
    parser.add_option("-g", "--grace-timeout",
                      action="store", type="int",
                      dest="gracetimeout",
                      help="when shutting down, the timeout to allow workers to"
                      " finish ongoing scans before being killed")
    # Redis-specific parser options
    parser.add_option("--redis-url",
                      action="store", type="string",
                      dest="redis_url",
                      help="specify an address for Redis queue server")
    parser.add_option("--work-queues",
                      action="store", type="string",
                      dest="work_queues",
                      help="list of in redis queues to be round robin-ed through followed by a colon and number for weighting")
    parser.add_option("--id-file",
                      action="store", type="string",
                      dest="id_file",
                      help="specify the file where worker IDs are stored in case of laikad failure")

    (options, _) = parser.parse_args()

    global logger

    logger = logging.getLogger(__name__)

    if options.debug:
       logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(name)s - %(levelname)s - %(process)d - %(message)s", datefmt="%Y-%m-%d %H:%M:%S%Z")
    else:
       logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(process)d - %(message)s", datefmt="%Y-%m-%d %H:%M:%S%Z")

    # Set the configuration file path for laikad
    config_location = '/etc/laikaboss/laikad.conf'
    if options.laikad_config_path:
        config_location = options.laikad_config_path
        if not os.path.exists(options.laikad_config_path):
            print("the provided config path is not valid, exiting")
            return 1
    # Next, check to see if we're in the top level source directory (dev environment)
    elif os.path.exists(DEFAULT_CONFIGS['laikad_dev_config_path']):
        config_location = DEFAULT_CONFIGS['laikad_dev_config_path']
    # Next, check for an installed copy of the default configuration
    elif os.path.exists(DEFAULT_CONFIGS['laikad_sys_config_path']):
        config_location = DEFAULT_CONFIGS['laikad_sys_config_path']
    # Exit
    else:
        print('A valid laikad configuration was not found in either of the following locations:\
\n%s\n%s' % (DEFAULT_CONFIGS['laikad_dev_config_path'],DEFAULT_CONFIGS['laikad_sys_config_path']))
        return 1

    # Read the laikad config file
    config_parser = LBConfigParser()

    config_files  = [config_location]
    config_parser.read(config_files)

    print("reading in " + str(config_files))


    # the name of the config parser std is DEFAULT in all caps but we will support both
    # for backwards compatibility
    CONFIGS.update(dict(config_parser.items("DEFAULT")))
    CONFIGS.update(dict(config_parser.items("General")))
    CONFIGS.update(dict(config_parser.items("Network")))
    CONFIGS.update(dict(config_parser.items("laikad")))

    if options.num_procs:
        num_procs = options.num_procs
    else:
        num_procs = int(get_option('numprocs'))

    logger.debug("num_procs: %d" % num_procs)

    if options.ttl:
        ttl = options.ttl
    else:
        ttl = int(get_option('ttl'))

    if options.time_ttl:
        time_ttl = options.time_ttl
    else:
        time_ttl = int(get_option('time_ttl'))

    if options.gracetimeout:
        gracetimeout = options.gracetimeout
    else:
        gracetimeout = int(get_option('gracetimeout'))

    # Redis-specific config options
    if options.redis_url:
        redis_url = options.redis_url
    else:
        redis_url = get_option('redis_url')

    hostname = get_option('hostname')

    if not hostname:
        hostname = socket.gethostname()

    if options.work_queues:
        work_queues = options.work_queues
    else:
        work_queues = get_option('work_queues')

    work_queues = parse_remote_queue_info(work_queues)

    if options.queue_type:
        queue_type = options.queue_type
    else:
        queue_type = get_option('queue_type')

    if options.id_file:
        id_file = options.id_file
    else:
        id_file = get_option('id_file')
   
    # Get the UserID to run as, if it was not specified on the command line
    # we'll use the current user by default
    runas_uid = None
    runas_gid = None

    if options.runas_uid:
        from pwd import getpwnam
        runas_uid = getpwnam(options.runas_uid).pw_uid
        runas_gid = getpwnam(options.runas_uid).pw_gid

    # Lower privileges if a UID has been set
    try:
        if runas_uid:
            os.setgid(runas_gid)
            os.setuid(runas_uid)
    except OSError:
        print("Unable to set user ID to %i, defaulting to current user" % runas_uid)

    if queue_type == "redis":
        logger.debug("Using Redis queueing mechanism: (%s: %s)" % (redis_url, str(work_queues)))

        # http://flask.pocoo.org/snippets/73/

        # Initialize workers
        worker_ids = []
        worker_procs = []
        for _ in range(num_procs):
            worker_id = "%s:%04X-%04X" % (hostname, randint(0, 0x10000), randint(0, 0x10000))
            worker_ids.append(worker_id)

            worker_proc = RedisWorker(redis_url, work_queues, None, worker_id, config_location, ttl, time_ttl, gracetimeout)
            worker_proc.start()
            logger.info("****** RedisWorker %s started. ***** " % (worker_id))
            worker_procs.append(worker_proc)

        # Check that all of our old identities are active, if not, send responses to laikacollector to resend
        try:
            old_ids = open(id_file).read().strip().split(',')


            if old_ids:
                logger.info("[+] RedisWorker is about to be opened from url:" + redis_url)

                redis_client = Client(redis_url, retry_on_timeout=True)

                logger.info("[+] RedisWorker open complete: %s" % (str(redis_client)))

                count = 0
                for old_id in old_ids:

                    origSenderID = ""
                    submitID = ""

                    val = redis_client.get('%s-work' % (old_id))
                    if val:
                        try:
                           origSenderID = val[0]
                           submitID = val[1]
                        except:
                           origSenderID = val
                           submitID = ""

                        result = ScanResult(source='failedscan', submitID=submitID)

                        count += 1
                        logger.info("Pushing fake failed result for ID %s" % (origSenderID))
                        redis_client.sendMsg(old_id, msg_queue=origSenderID, val=result, expire=_redis_work_reply_expiration)
                logger.debug("[+] RedisWorker pushing fake failed results count:%d complete" % (count))

        except Exception as e:
            logger.debug(e)

        # Write worker IDs to file
        try:
            with open(id_file, 'w') as f:
                f.write(','.join(worker_ids))
        except Exception as e:
            logger.exception(e)

        while KEEP_RUNNING and worker_procs:
            # Check that all workers are still running and start them with correct worker_id
            dead_workers = []
            for i, worker_proc in enumerate(worker_procs):
                if not worker_proc.is_alive():
                    identity = worker_proc.identity
                    dead_workers.append(worker_proc)
                    logger.info("*******restarting a RedisWorker %d id:%s pid:%d exit_code:%d because it was not alive ****" % (i, identity, worker_proc.pid, worker_proc.exitcode))
                    worker_proc = RedisWorker(redis_url, work_queues, None, identity, config_location, ttl, time_ttl, gracetimeout)
                    worker_proc.start()
                    logger.info("****** RedisWorker %s started. ***** " % (identity))
                    worker_procs.append(worker_proc)

            # remove any dead workers from the list
            for d in dead_workers:
                logger.info("****** removing older dead worker ***** ")
                worker_procs.remove(d)

            time.sleep(5)

        logger.debug("Supervisor: beginning graceful shutdown sequence - running workers: " + len(worker_procs))
        logger.info("Supervisor: giving workers %d second grace period", gracetimeout)
        time.sleep(gracetimeout)
        logger.info("Supervisor: terminating workers")

        for worker_proc in worker_procs:
            if worker_proc.is_alive():
                os.kill(worker_proc.pid, signal.SIGKILL)
        for worker_proc in worker_procs:
            worker_proc.join()

        logger.debug("Supervisor: finished")

if __name__ == '__main__':
    main()

