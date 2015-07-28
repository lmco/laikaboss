#!/usr/bin/python
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

'''
laikad

Command line program for running the broker and worker processes for the Laika
framework. This program becomes the supervisor process that ensures the broker
and worker processes remain up and alive (replaces those that go missing).
'''

# Follows the Simple Pirate Pattern for ZMQ connections

from ConfigParser import ConfigParser
import cPickle as pickle
import functools
from interruptingcow import timeout
import logging
from multiprocessing import Process
from optparse import OptionParser
import os
from random import randint
import signal
from laikaboss.objectmodel import ScanResult, ScanObject, QuitScanException
import sys
import syslog
import time
import traceback
import zlib
import zmq
import json
import base64
from distutils.util import strtobool

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
            for uid, sO in obj.files.iteritems():
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
    'brokerfrontend': 'tcp://*:5558',
    'brokerbackend': 'tcp://*:5559',
    'workerconnect': 'tcp://localhost:5559',
    'async': 'False',
    'gracetimeout': '30',
    'workerpolltimeout': '300',
    'log_result' : 'False',
    'dev_config_path' : 'etc/framework/laikaboss.conf',
    'sys_config_path' : '/usr/local/laikaboss/etc/laikaboss.conf'
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
    logging.debug("Shutdown handler triggered (%d)", signum)
    proc.shutdown()

# Follows the Load Balancing Pattern for ZMQ connections
class AsyncBroker(Process):
    '''
    Broker process for receiving asyncronous scan requests. The requests will be
    doled out to the worker processes. The results of the scan will not be
    returned back to the client.
    '''

    def __init__(self, broker_backend_address, broker_frontend_address):
        '''Main constructor'''
        super(AsyncBroker, self).__init__()
        self.broker_backend_address = broker_backend_address
        self.broker_frontend_address = broker_frontend_address
        self.keep_running = True

    def shutdown(self):
        '''Shutdown method to be called by the signal handler'''
        logging.debug("Broker: shutdown handler triggered")
        self.keep_running = False

    def run(self):
        '''Main process logic'''
        logging.debug("Broker: starting up")
        self.keep_running = True

        # Add intercept for graceful shutdown
        # functools.partial creates a function pointer with the first arguments provided
        # For the signal handler, pass in a reference to this process (self)
        signal.signal(signal.SIGTERM, functools.partial(shutdown_handler, self))
        signal.signal(signal.SIGINT, functools.partial(shutdown_handler, self))

        context = zmq.Context(1)

        # Connection for workers
        backend = context.socket(zmq.ROUTER)
        backend.bind(self.broker_backend_address)
        backend_poller = zmq.Poller()
        backend_poller.register(backend, zmq.POLLIN)

        # Connection for clients
        frontend = context.socket(zmq.PULL)
        frontend.bind(self.broker_frontend_address)
        frontend_poller = zmq.Poller()
        frontend_poller.register(frontend, zmq.POLLIN)
        frontend_poller.register(backend, zmq.POLLIN) # Also grab worker updates

        # Keep a list of the workers that have checked in as available for work
        available_workers = []

        while self.keep_running:
            logging.debug("Broker: beginning loop\n\tavailable: %s",
                str(available_workers))

            try:
                if available_workers:
                    # Poll both clients and workers
                    msgs = dict(frontend_poller.poll())
                else:
                    # Poll only workers
                    msgs = dict(backend_poller.poll())

                # Check in with clients
                if msgs.get(frontend) == zmq.POLLIN:
                    # msg should be in the following format
                    # [request]
                    # where:
                    #   request     --  The content of the request to be sent to
                    #                   the worker
                    msg = frontend.recv_multipart()
                    worker_id = available_workers.pop(0)
                    # reply should be in the following format
                    # [worker_id, '', worker_id, '', request]
                    # where:
                    #   worker_id   --  ZMQ identifier of the worker socket
                    #   request     --  The content of the request to be sent to
                    #                   the worker
                    backend.send_multipart([worker_id, '', worker_id, ''] + msg)

                # Check in with workers
                if msgs.get(backend) == zmq.POLLIN:
                    # msg should be in one of the following formats
                    # [worker_id, '', status]
                    # [worker_id, '', status, '', client_id, '', reply]
                    # where:
                    #   worker_id   --  ZMQ identifier of the worker socket
                    #   status      --  One of our defined status constants,
                    #                   determines how we handle this request
                    #   client_id   --  ZMQ identifier of the client socket
                    #   reply       --  The content of the reply
                    msg = backend.recv_multipart()
                    worker_id = msg[0]
                    status = msg[2]

                    if status == LRU_READY or status == LRU_RESULT_READY:
                        logging.debug("Broker: worker (%s) ready", worker_id)
                        if worker_id not in available_workers:
                            available_workers.append(worker_id)
                    elif status == LRU_RESULT_QUIT or status == LRU_QUIT:
                        logging.debug("Broker: worker (%s) quitting", worker_id)
                        try:
                            available_workers.remove(worker_id)
                        except ValueError:
                            pass
                    else:
                        logging.warn("Broker: bad worker message received")
            except zmq.ZMQError as zmqerror:
                if "Interrupted system call" not in str(zmqerror):
                    logging.exception("Broker: Received ZMQError")
                else:
                    logging.debug("Broker: ZMQ interrupted by shutdown signal")

        # Begin graceful shutdown
        logging.debug("Broker: beginning graceful shutdown sequence")
        # There is no reason to stay around since the workers work
        # asynchronously
        logging.debug("Broker: finished")

# Follows the Load Balancing Pattern for ZMQ connections
class SyncBroker(Process):
    '''
    Broker process for receiving syncronous scan requests. The requests will be
    doled out to the worker processes. The results of the scan will be
    returned back to the client.
    '''

    def __init__(self, broker_backend_address, broker_frontend_address,
        shutdown_grace_timeout=SHUTDOWN_GRACE_TIMEOUT_DEFAULT):
        '''Main constructor'''
        super(SyncBroker, self).__init__()
        self.broker_backend_address = broker_backend_address
        self.broker_frontend_address = broker_frontend_address
        self.shutdown_grace_timeout = shutdown_grace_timeout
        self.keep_running = True

    def shutdown(self):
        '''Shutdown method to be called by the signal handler'''
        logging.debug("Broker: shutdown handler triggered")
        self.keep_running = False

    def run(self):
        '''Main process logic'''
        logging.debug("Broker: starting up")
        self.keep_running = True

        # Add intercept for graceful shutdown
        signal.signal(signal.SIGTERM, functools.partial(shutdown_handler, self))
        signal.signal(signal.SIGINT, functools.partial(shutdown_handler, self))

        context = zmq.Context(1)

        # Connection for workers
        backend = context.socket(zmq.ROUTER)
        backend.bind(self.broker_backend_address)
        backend_poller = zmq.Poller()
        backend_poller.register(backend, zmq.POLLIN)

        # Connection for clients
        frontend = context.socket(zmq.ROUTER)
        frontend.bind(self.broker_frontend_address)
        frontend_poller = zmq.Poller()
        frontend_poller.register(frontend, zmq.POLLIN)
        frontend_poller.register(backend, zmq.POLLIN) # Also grab worker updates

        # Keep a list of the workers that have checked in as available for work
        available_workers = []
        # Keep a list of workers currently doing work, so that if we are asked
        # to shutdown, we can hang around long enough to forward the scan
        # results back to the requesting clients.
        working_workers = []

        while self.keep_running:
            logging.debug("Broker: beginning loop\n\tavailable: %s\n\tworking:"
                " %s", str(available_workers), str(working_workers))

            try:
                if available_workers:
                    # Poll both clients and workers
                    msgs = dict(frontend_poller.poll())
                else:
                    # Poll only workers
                    msgs = dict(backend_poller.poll())

                # Check in with clients
                if msgs.get(frontend) == zmq.POLLIN:
                    # msg should be in the following format
                    # [client_id, '', request]
                    # where:
                    #   client_id   --  ZMQ identifier of the client socket
                    #   request     --  The content of the request to be sent to
                    #                   the worker
                    msg = frontend.recv_multipart()
                    worker_id = available_workers.pop(0)
                    # reply should be in the following format
                    # [worker_id, '', client_id, '', request]
                    # where:
                    #   worker_id   --  ZMQ identifier of the worker socket
                    #   client_id   --  ZMQ identifier of the client socket
                    #   request     --  The content of the request to be sent to
                    #                   the worker
                    backend.send_multipart([worker_id, ''] + msg)
                    working_workers.append(worker_id)

                # Check in with workers
                if msgs.get(backend) == zmq.POLLIN:
                    # msg should be in one of the following formats
                    # [worker_id, '', status]
                    # [worker_id, '', status, '', client_id, '', reply]
                    # where:
                    #   worker_id   --  ZMQ identifier of the worker socket
                    #   status      --  One of our defined status constants,
                    #                   determines how we handle this request
                    #   client_id   --  ZMQ identifier of the client socket
                    #   reply       --  The content of the reply
                    msg = backend.recv_multipart()
                    #logging.debug("Broker: received message %s", str(msg))
                    worker_id = msg[0]
                    status = msg[2]

                    if status == LRU_READY:
                        logging.debug("Broker: worker (%s) ready", worker_id)
                        if (worker_id not in available_workers and
                            worker_id not in working_workers):
                            available_workers.append(worker_id)
                    elif status == LRU_RESULT_READY:
                        logging.debug("Broker: worker (%s) finished scan, "
                            "ready", worker_id)
                        try:
                            working_workers.remove(worker_id)
                        except ValueError:
                            pass
                        # reply should be in the following format
                        # [client_id, '', reply]
                        # where:
                        #   client_id   --  ZMQ identifier of the client socket
                        #   reply       --  The content of the reply
                        frontend.send_multipart(msg[4:])
                        if (worker_id not in available_workers and
                            worker_id not in working_workers):
                            available_workers.append(worker_id)
                    elif status == LRU_RESULT_QUIT:
                        logging.debug("Broker: worker (%s) finished scan, "
                            "quitting", worker_id)
                        try:
                            working_workers.remove(worker_id)
                        except ValueError:
                            pass
                        # reply should be in the following format
                        # [client_id, '', reply]
                        # where:
                        #   client_id   --  ZMQ identifier of the client socket
                        #   reply       --  The content of the reply
                        frontend.send_multipart(msg[4:])
                    elif status == LRU_QUIT:
                        logging.debug("Broker: worker (%s) quitting", worker_id)
                        try:
                            available_workers.remove(worker_id)
                        except ValueError:
                            pass
                    else:
                        logging.debug("Broker: bad worker message received")
            except zmq.ZMQError as zmqerror:
                if "Interrupted system call" not in str(zmqerror):
                    logging.exception("Broker: Received ZMQError")
                else:
                    logging.debug("Broker: ZMQ interrupted by shutdown signal")

        # Begin graceful shutdown
        logging.debug("Broker: beginning graceful shutdown sequence")
        # Wait for a grace period to allow workers to finish working
        poll_timeout = (self.shutdown_grace_timeout / 3) * 1000 or 1
        start_time = time.time()
        while(working_workers and
            (time.time() - start_time < self.shutdown_grace_timeout)):
            logging.debug("Broker: beginning graceful shutdown loop\n\tworking:"
                "%s", str(working_workers))
            msgs = dict(backend_poller.poll(poll_timeout))
            if msgs.get(backend) == zmq.POLLIN:
                # msg should be in one of the following formats
                # [worker_id, '', status]
                # [worker_id, '', status, '', client_id, '', reply]
                # where:
                #   worker_id   --  ZMQ identifier of the worker socket
                #   status      --  One of our defined status constants,
                #                   determines how we handle this request
                #   client_id   --  ZMQ identifier of the client socket
                #   reply       --  The content of the reply
                msg = backend.recv_multipart()
                worker_id = msg[0]
                status = msg[2]
                if status == LRU_RESULT_READY or status == LRU_RESULT_QUIT:
                    logging.debug("Broker: worker (%s) finished scan",
                        worker_id)
                    try:
                        working_workers.remove(worker_id)
                    except ValueError:
                        pass
                    # reply should be in the following format
                    # [worker_id, '', client_id, '', request]
                    # where:
                    #   worker_id   --  ZMQ identifier of the worker socket
                    #   client_id   --  ZMQ identifier of the client socket
                    #   request     --  The content of the request to be sent to
                    #                   the worker
                    frontend.send_multipart(msg[4:])

        logging.debug("Broker: finished")

# Follows the Lazy Pirate Pattern for ZMQ connections, modified to use the
# DEALER socket so that repeated status updates can be given over the same
# connection
class Worker(Process):
    '''
    Worker process for performing scans. Returns the result back to the broker.
    Workers give up and quit receiving work after either a count threshold or a
    time to live timeout triggers, whichever comes first.
    '''

    def __init__(self, config_location, broker_address, max_scan_items, ttl,
    logresult=False, 
    poll_timeout=300, 
    shutdown_grace_timeout=SHUTDOWN_GRACE_TIMEOUT_DEFAULT):
        '''Main constructor'''
        super(Worker, self).__init__()
        self.config_location = config_location
        self.max_scan_items = max_scan_items
        self.ttl = ttl
        self.shutdown_grace_timeout = shutdown_grace_timeout
        self.keep_running = False

        self.broker_address = broker_address
        self.identity = "%04X-%04X" % (randint(0, 0x10000), randint(0, 0x10000))
        self.broker = None
        self.broker_poller = zmq.Poller()
        self.poll_timeout = poll_timeout * 1000 # Poller uses milliseconds
        self.logresult = logresult

    def perform_scan(self, poll_timeout):
        '''
        Wait for work from broker then perform the scan. If timeout occurs, no
        scan is performed and no result is returned.

        Arguments:
        poll_timeout    --  The amount of time to wait for work.

        Returns:
        The result of the scan or None if no scan was performed.
        '''
        from laikaboss.dispatch import Dispatch
        from laikaboss.objectmodel import ScanResult, ExternalObject, ExternalVars
        from laikaboss.util import log_result

        # If task is found, perform scan
        try:
            logging.debug("Worker (%s): checking for work", self.identity)
            tasks = dict(self.broker_poller.poll(poll_timeout))
            if tasks.get(self.broker) == zmq.POLLIN:
                logging.debug("Worker (%s): performing scan", self.identity)
                # task should be in the following format
                # ['', client_id, '', request_type, '', request]
                # where:
                #   client_id        --  ZMQ identifier of the client socket
                #   request_type     --  The type of request (json/pickle/zlib)
                #   request          --  Object to be scanned

                task = self.broker.recv_multipart()
                
                client_id = task[1]
                if len(task) == 6:
                    request_type = task[3]
                    request = task[5]
                    if request_type in [REQ_TYPE_PICKLE, REQ_TYPE_PICKLE_ZLIB]:
                        #logging.debug("Worker: received work %s", str(task))
                        if request_type == REQ_TYPE_PICKLE_ZLIB:
                            externalObject = pickle.loads(zlib.decompress(request))
                        else:
                            externalObject = pickle.loads(request)
                    elif request_type in [REQ_TYPE_JSON, REQ_TYPE_JSON_ZLIB]:
                        if request_type == REQ_TYPE_JSON_ZLIB:
                            jsonRequest = json.loads(zlib.decompress(request))
                        else:
                            jsonRequest = json.loads(request)
                        
                        # Set default values for our request just in case some were omitted
                        if not 'buffer' in jsonRequest:
                            jsonRequest['buffer'] = ''
                        else:
                            try:
                                jsonRequest['buffer'] = base64.b64decode(jsonRequest['buffer'])
                            except:
                                # This should never happen unless invalid input is given
                                jsonRequest['buffer'] = ''
                        if not 'filename' in jsonRequest:
                            jsonRequest['filename'] = ''
                        if not 'ephID' in jsonRequest:
                            jsonRequest['ephID'] = ''
                        if not 'uniqID' in jsonRequest:
                            jsonRequest['uniqID'] = ''
                        if not 'contentType' in jsonRequest:
                            jsonRequest['contentType'] = []
                        if not 'timestamp' in jsonRequest:
                            jsonRequest['timestamp'] = ''
                        if not 'source' in jsonRequest:
                            jsonRequest['source'] = ''
                        if not 'origRootUID' in jsonRequest:
                            jsonRequest['origRootUID'] = ''
                        if not 'extMetaData' in jsonRequest:
                            jsonRequest['extMetaData'] = {}
                        if not 'level' in jsonRequest:
                            jsonRequest['level'] = 2

                        externalVars = ExternalVars(filename=jsonRequest['filename'],
                                                    ephID=jsonRequest['ephID'],
                                                    uniqID=jsonRequest['uniqID'],
                                                    contentType=jsonRequest['contentType'],
                                                    timestamp=jsonRequest['timestamp'],
                                                    source=jsonRequest['source'],
                                                    origRootUID=jsonRequest['origRootUID'],
                                                    extMetaData=jsonRequest['extMetaData'])

                        externalObject = ExternalObject(buffer=jsonRequest['buffer'],
                                                        level=jsonRequest['level'],
                                                        externalVars=externalVars)

                    else:
                        return [client_id, '', 'INVALID REQUEST']
                     
                    result = ScanResult(
                        source=externalObject.externalVars.source,
                        level=externalObject.level)
                    result.startTime = time.time()
                    try:
                        Dispatch(externalObject.buffer, result, 0,
                            externalVars=externalObject.externalVars)
                    except QuitScanException:
                        raise
                    except:
                        exc_type, exc_value, exc_traceback = sys.exc_info()
                        log_debug(
                            "exception on file: %s, detailed exception: %s" % (
                            externalObject.externalVars.filename,
                            repr(traceback.format_exception(
                                exc_type, exc_value, exc_traceback))))
                    if self.logresult:
                        log_result(result)
                    if request_type == REQ_TYPE_PICKLE_ZLIB:  
                        result = zlib.compress(
                            pickle.dumps(result, pickle.HIGHEST_PROTOCOL))
                    elif request_type == REQ_TYPE_PICKLE:  
                        result = pickle.dumps(result, pickle.HIGHEST_PROTOCOL)
                    elif request_type == REQ_TYPE_JSON_ZLIB:  
                        result = zlib.compress(
                            json.dumps(result, cls=ResultEncoder))
                    elif request_type == REQ_TYPE_JSON:  
                        result = json.dumps(result, cls=ResultEncoder)
                    return [client_id, '', result]

                else:
                    return [client_id, '', 'INVALID REQUEST']
        except zmq.ZMQError as zmqerror:
            if "Interrupted system call" not in str(zmqerror):
                logging.exception("Worker (%s): Received ZMQError", self.identity)
            else:
                logging.debug("Worker (%s): ZMQ interrupted by shutdown signal", self.identity)
        return None

    def shutdown(self):
        '''Shutdown method to be called by the signal handler'''
        logging.debug("Worker (%s): shutdown handler triggered", self.identity)
        self.keep_running = False
        raise QuitScanException()

    def run(self):
        '''Main process logic'''
        logging.debug("Worker (%s): starting up", self.identity)

        from laikaboss import config
        from laikaboss.dispatch import close_modules
        from laikaboss.util import init_logging

        logging.debug("using config %s", self.config_location)
        config.init(path=self.config_location)
        init_logging()

        log_debug("Worker %s started at %s" % (self.identity, time.time()))

        self.keep_running = True
        perform_grace_check = False

        # Add intercept for graceful shutdown
        signal.signal(signal.SIGTERM, functools.partial(shutdown_handler, self))
        signal.signal(signal.SIGINT, functools.partial(shutdown_handler, self))

        # Connect to broker
        logging.debug("Worker (%s): connecting broker", self.identity)
        context = zmq.Context(1)
        self.broker = context.socket(zmq.DEALER)
        self.broker.setsockopt(zmq.IDENTITY, self.identity)
        self.broker.connect(self.broker_address)
        self.broker_poller.register(self.broker, zmq.POLLIN)

        # Ask for work
        # request should be in one of the following formats
        # ['', status]
        # where:
        #   status      --  One of our defined status constants, determines
        #                   how we handle this request
        self.broker.send_multipart(['', LRU_READY])

        # Indicators for worker expiration
        counter = 0
        start_time = time.time() + randint(1, 60)

        while self.keep_running:
            try:
                result = self.perform_scan(self.poll_timeout)

                if result:
                    counter += 1
                should_quit = (
                    counter >= self.max_scan_items or
                    ((time.time() - start_time)/60) >= self.ttl or
                    not self.keep_running)

                # Determine next status
                status = LRU_QUIT
                if result:
                    if should_quit:
                        status = LRU_RESULT_QUIT
                    else:
                        status = LRU_RESULT_READY
                else:
                    if should_quit:
                        status = LRU_QUIT
                        perform_grace_check = True
                    else:
                        status = LRU_READY

                # Build reply
                if result:
                    reply = ['', status, ''] + result
                else:
                    reply = ['', status]

                # reply should be in one of the following formats
                # ['', status]
                # ['', status, '', client_id, '', reply]
                # where:
                #   status      --  One of our defined status constants,
                #                   determines how we handle this request
                #   client_id   --  ZMQ identifier of the client socket
                #   reply       --  The content of the reply
                #logging.debug("Worker: sending request %s", str(reply))
                tracker = self.broker.send_multipart(reply, copy=False, track=True)
                while not tracker.done and result:
                    time.sleep(0.1)

                if should_quit:
                    self.keep_running = False
            except zmq.ZMQError as zmqerror:
                if "Interrupted system call" not in str(zmqerror):
                    logging.exception("Worker (%s): Received ZMQError", self.identity)
                else:
                    logging.debug("Worker (%s): ZMQ interrupted by shutdown signal", self.identity)
            except QuitScanException:
                logging.debug("Worker (%s): Caught scan termination exception", self.identity)
                break

        # Begin graceful shutdown
        logging.debug("Worker (%s): beginning graceful shutdown sequence", self.identity)
        if perform_grace_check:
            logging.debug("Worker (%s): performing grace check", self.identity)
            try:
                result = self.perform_scan(self.poll_timeout)
                if result:
                    reply = ['', LRU_RESULT_QUIT, ''] + result
                    # reply should be in the following format
                    # ['', status, '', client_id, '', reply]
                    # where:
                    #   status      --  One of our defined status constants,
                    #                   determines how we handle this request
                    #   client_id   --  ZMQ identifier of the client socket
                    #   reply       --  The content of the reply
                    tracker = self.broker.send_multipart(reply, copy=False, track=True)
                    while not tracker.done:
                        time.sleep(0.1)
            except zmq.ZMQError as zmqerror:
                if "Interrupted system call" not in str(zmqerror):
                    logging.exception("Worker (%s): Received ZMQError", self.identity)
                else:
                    logging.debug("Worker (%s): ZMQ interrupted by shutdown signal", self.identity)

        try:
            with timeout(self.shutdown_grace_timeout, exception=QuitScanException):
                close_modules()
        except QuitScanException:
            logging.debug("Worker (%s): Caught scan termination exception during destruction",
                self.identity)
        log_debug("Worker %s dying after %i objects and %i seconds" % (
            self.identity, counter, time.time() - start_time))
        logging.debug("Worker (%s): finished", self.identity)

# Globals to share in the signal hander
KEEP_RUNNING = True

def main():
    '''Main program logic. Becomes the supervisor process.'''
    parser = OptionParser(usage="usage: %prog [options]\n"
        "Default settings in config file: laikad.conf")

    parser.add_option("-d", "--debug",
                      action="store_true", default=False,
                      dest="debug",
                      help="enable debug messages to the console.")
    parser.add_option("-s", "--scan-config",
                      action="store", type="string",
                      dest="laikaboss_config_path",
                      help="specify a path for laikaboss configuration")
    parser.add_option("-c", "--laikad-config",
                      action="store", type="string",
                      dest="laikad_config_path",
                      help="specify a path for laikad configuration")
    parser.add_option("-b", "--broker-backend",
                      action="store", type="string",
                      dest="broker_backend_address",
                      help="specify an address for the workers to connect to. "
                      "ex: tcp://*:5559")
    parser.add_option("-f", "--broker-frontend",
                      action="store", type="string",
                      dest="broker_frontend_address",
                      help="specify an address for clients to connect to. ex: "
                      "tcp://*:5558")
    parser.add_option("-w", "--worker-connect",
                      action="store", type="string",
                      dest="worker_connect_address",
                      help="specify an address for clients to connect to. ex: "
                      "tcp://localhost:5559")
    parser.add_option("-n", "--no-broker",
                      action="store_true", default=False,
                      dest="no_broker",
                      help="specify this option to disable the broker for this "
                      "instance.")
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
    parser.add_option("-a", "--async",
                      action="store_true", default=False,
                      dest="run_async",
                      help="enable async messages. "
                      "This will disable any responses back to the client.")
    parser.add_option("-g", "--grace-timeout",
                      action="store", type="int",
                      dest="gracetimeout",
                      help="when shutting down, the timeout to allow workers to"
                      " finish ongoing scans before being killed")
    (options, _) = parser.parse_args()

    # Set the configuration file path
    config_location = '/usr/local/laikaboss/etc/laikad.conf'
    if options.laikad_config_path:
        config_location = options.laikad_config_path
    
    # We need a default framework config at a minimum
    if options.laikaboss_config_path:
        laikaboss_config_path = options.laikaboss_config_path
        logging.debug("using alternative config path: %s" % options.laikaboss_config_path)
        if not os.path.exists(options.laikaboss_config_path):
            print "the provided config path is not valid, exiting"
            return 1
    # Next, check to see if we're in the top level source directory (dev environment)
    elif os.path.exists(DEFAULT_CONFIGS['dev_config_path']):
        laikaboss_config_path = DEFAULT_CONFIGS['dev_config_path']
    # Next, check for an installed copy of the default configuration
    elif os.path.exists(DEFAULT_CONFIGS['sys_config_path']):
        laikaboss_config_path = DEFAULT_CONFIGS['sys_config_path']
    # Exit
    else:
        print 'A valid framework configuration was not found in either of the following locations:\
\n%s\n%s' % (DEFAULT_CONFIGS['dev_config_path'],DEFAULT_CONFIGS['sys_config_path'])
        return 1

    # Read the config file
    config_parser = ConfigParser()
    config_parser.read(config_location)

    # Parse through the config file and append each section to a single dict
    for section in config_parser.sections():
        CONFIGS.update(dict(config_parser.items(section)))

    if options.num_procs:
        num_procs = options.num_procs
    else:
        num_procs = int(get_option('numprocs'))

    if options.ttl:
        ttl = options.ttl
    else:
        ttl = int(get_option('ttl'))

    if options.time_ttl:
        time_ttl = options.time_ttl
    else:
        time_ttl = int(get_option('time_ttl'))

    if options.broker_backend_address:
        broker_backend_address = options.broker_backend_address
    else:
        broker_backend_address = get_option('brokerbackend')

    if options.broker_frontend_address:
        broker_frontend_address = options.broker_frontend_address
    else:
        broker_frontend_address = get_option('brokerfrontend')

    if options.worker_connect_address:
        worker_connect_address = options.worker_connect_address
    else:
        worker_connect_address = get_option('workerconnect')

    if options.gracetimeout:
        gracetimeout = options.gracetimeout
    else:
        gracetimeout = int(get_option('gracetimeout'))

    if options.run_async:
        async = True
    else:
        async = strtobool(get_option('async'))
   
    logresult = strtobool(get_option('log_result'))

    # Get the UserID to run as, if it was not specified on the command line
    # we'll use the current user by default
    runas_uid = None
    runas_gid = None

    if options.runas_uid:
        from pwd import getpwnam
        runas_uid = getpwnam(options.runas_uid).pw_uid
        runas_gid = getpwnam(options.runas_uid).pw_gid

    if options.debug:
        logging.basicConfig(level=logging.DEBUG)

    # Lower privileges if a UID has been set
    try:
        if runas_uid:
            os.setgid(runas_gid)
            os.setuid(runas_uid)
    except OSError:
        print "Unable to set user ID to %i, defaulting to current user" % runas_uid

    # Add intercept for graceful shutdown
    def shutdown(signum, frame):
        '''Signal handler for shutting down supervisor gracefully'''
        logging.debug("Supervisor: shutdown handler triggered")
        global KEEP_RUNNING
        KEEP_RUNNING = False
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    # Start the broker
    broker_proc = None
    if not options.no_broker:
        if async:
            broker_proc = AsyncBroker(broker_backend_address, broker_frontend_address)
        else:
            broker_proc = SyncBroker(broker_backend_address, broker_frontend_address, gracetimeout)
        broker_proc.start()

    # Start the workers
    workers = []
    for _ in range(num_procs):
        worker_proc = Worker(laikaboss_config_path, worker_connect_address, ttl,
            time_ttl, logresult, int(get_option('workerpolltimeout')), gracetimeout)
        worker_proc.start()
        workers.append(worker_proc)

    while KEEP_RUNNING:
        # Ensure we have a broker
        if not options.no_broker and not broker_proc.is_alive():
            if async:
                broker_proc = AsyncBroker(broker_backend_address, broker_frontend_address)
            else:
                broker_proc = SyncBroker(broker_backend_address, broker_frontend_address,
                    gracetimeout)
            broker_proc.start()

        # Ensure we have living workers
        dead_workers = []
        for worker_proc in workers:
            if not worker_proc.is_alive():
                dead_workers.append(worker_proc)

        for worker_proc in dead_workers:
            workers.remove(worker_proc)
            new_proc = Worker(laikaboss_config_path, worker_connect_address, ttl, time_ttl,
                logresult, int(get_option('workerpolltimeout')), gracetimeout)
            new_proc.start()
            workers.append(new_proc)
            worker_proc.join()

        # Wait a little bit
        time.sleep(5)

    logging.debug("Supervisor: beginning graceful shutdown sequence")
    logging.info("Supervisor: giving workers %d second grace period", gracetimeout)
    time.sleep(gracetimeout)
    logging.info("Supervisor: terminating workers")
    for worker_proc in workers:
        if worker_proc.is_alive():
            os.kill(worker_proc.pid, signal.SIGKILL)
    for worker_proc in workers:
        worker_proc.join()
    if not options.no_broker:
        if broker_proc.is_alive():
            os.kill(broker_proc.pid, signal.SIGKILL)
        broker_proc.join()
    logging.debug("Supervisor: finished")

if __name__ == '__main__':
    main()

