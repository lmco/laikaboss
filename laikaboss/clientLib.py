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
#
# Copyright Lockheed Martin 2012
#
# Client Library for laikaboss framework.
#
########################################

import os, sys
import zlib, cPickle as pickle
import logging
from random import randint
import json
import traceback
import uuid
from laikaboss.objectmodel import QuitScanException
from copy import deepcopy as clone_object

REQ_TYPE_PICKLE = '1'
REQ_TYPE_PICKLE_ZLIB = '2'

def dispositionFromResult(result):
    '''
    This function examines the DISPOSITIONER module metadata in the scan results 
    to determine disposition.
    '''
    try:
        matches = result.files[result.rootUID].moduleMetadata['DISPOSITIONER']['Disposition']['Matches']
        return sorted(matches)
    except QuitScanException:
        raise
    except:
        logging.debug("Unable to disposition the result")
        return ['Error']
    
def finalDispositionFromResult(result):
    '''
    This function examines the DISPOSITIONER module metadata in the scan results 
    to determine disposition.
    '''
    try:
        return result.files[result.rootUID].moduleMetadata['DISPOSITIONER']['Disposition']['Result']
    except QuitScanException:
        raise
    except:
        logging.debug("Unable to disposition the result")
        return ['Error']
    
def getAttachmentList(result):
    children = []
    rootObject = None
    for uid, scanObject in result.files.iteritems():
        if not scanObject.parent:
            rootObject = uid
    for uid, scanObject in result.files.iteritems():
        if scanObject.parent == rootObject:
            if scanObject.filename:
                children.append(scanObject.filename)
    return children

def flagRollup(result):
    '''
    This function takes a fully populated result object and returns a list of flags
    which has been sorted and deduplicated.

    Arguments:
    result -- a fully populated scan result set

    Returns:
    A sorted/unique list of all flags in the result
    '''
    flag_rollup = [] 
    for id, scanObject in result.files.iteritems():
        flag_rollup.extend(scanObject.flags)
    flag_rollup = set(flag_rollup)
    return sorted(flag_rollup)

def getRootObject(result):
    '''
    Returns the ScanObject in a result set that contains no parent (making it the root).

    Arguments:
    result -- a fully populated scan result set

    Returns:
    The root ScanObject for the result set.
    '''
    return result.files[result.rootUID] #ScanObject type

def get_scanObjectUID(scanObject):
    '''
    Get the UID for a ScanObject instance.
    
    Arguments:
    scanObject -- a ScanObject instance

    Returns:
    A string containing the UID of the object.
    '''
    return scanObject.uuid

def getJSON(result):
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
    # a root buffer's scan in no particular order.
    buffer_results = []
    for scan_object in result.files.itervalues():
        # Do not damage the original result -> clone
        buffer_result = clone_object(scan_object.__dict__)
        # Don't log buffers here, just metadata
        if "buffer" in buffer_result:
            del buffer_result["buffer"]
        buffer_results.append(buffer_result)

    # Construct the log record with fields useful for log processing and
    # routing
    log_record = {
        'source': result.source,
        'scan_result': buffer_results
    }

    resultText = json.dumps(log_record)
    return resultText

class Client:
    _CONTEXT = None
    _CLIENT = None
    _TIMEOUT = None
    _POLL = None
    _BROKER_HOST = None
    _SSH_HOST = None
    _USE_SSH = None
    _REQUEST_TYPE = None
    
    def __init__(self, brokerHost, context=None, useSSH=False, sshHost=None, async=False, useGevent=False, requestType=REQ_TYPE_PICKLE_ZLIB):

        # Initialize Attributes
        if useGevent:
            #logging.debug("Using Gevent_zmq")
            #from gevent_zeromq import zmq
            import zmq.green as zmq
        else:
            import zmq            

        self.zmq = zmq
        self._BROKER_HOST = brokerHost
        self._SSH_HOST = sshHost
        self._USE_SSH = useSSH
        self._POLL = zmq.Poller()
        self._ID = randint(1,999)
        self._ASYNC = async
        self._REQUEST_TYPE = requestType

        if context is not None:
            self._CONTEXT = context
        else:
            self._CONTEXT = self.zmq.Context()

        # Connect Client
        self._connect()

    # END __init__
    def close(self):
        try:
            self._disconnect()
            self._CONTEXT.term()
        except:
            raise
        
    def _connect(self):
        # Get Context
        if self._ASYNC:
            self._CLIENT = self._CONTEXT.socket(self.zmq.PUSH)
        else:
            self._CLIENT = self._CONTEXT.socket(self.zmq.REQ)

        # Check if SSH is requested
        if self._USE_SSH:
            from zmq import ssh
            # Ensure there exists an SSH Host
            if self._SSH_HOST:
                try:
                    ssh.tunnel_connection(self._CLIENT, self._BROKER_HOST, self._SSH_HOST)
                except RuntimeError as e:
                    raise e
            else:
                raise AttributeError("No SSH Host.")
        else:
            self._CLIENT.connect(self._BROKER_HOST)

        # Register Poll
        self._POLL.register(self._CLIENT, self.zmq.POLLIN)
    # END _connect

    def _disconnect(self):

        self._CLIENT.setsockopt(self.zmq.LINGER, 0)
        self._CLIENT.close()
        self._POLL.unregister(self._CLIENT)
    # END _disconnect


    def _send_recv(self, externalObject):

        # Serialize and compress the externalObject
        zmo = pickle.dumps(externalObject, pickle.HIGHEST_PROTOCOL)
        if self._REQUEST_TYPE == REQ_TYPE_PICKLE_ZLIB:
            zmo = zlib.compress(zmo)
        
        # Send (if _TIMEOUT=None, there is unlimited time)
        try:
            self._CLIENT.send_multipart([self._REQUEST_TYPE, '', zmo])
        # An error will occur if the ZMQ socket is in the wrong state
        # In this case, we disconnect and then reconnect before retrying
        #except self.zmq.core.error.ZMQError:
        except:
            logging.debug("ID %i : ZMQ socket in wrong state, reconnecting." % self._ID)
            self._disconnect()
            self._connect()
            self._CLIENT.send_multipart([self._REQUEST_TYPE, '', zmo])

        socks = dict(self._POLL.poll(self._TIMEOUT))
        if socks.get(self._CLIENT) == self.zmq.POLLIN:

            # Recieve reply
            reply = self._CLIENT.recv()
            logging.debug("ID %i : got reply" % self._ID)

            # Check for non-empty reply
            if not reply:
                return None
        else:
            return None

        # Decompress and deserialize reply
        if self._REQUEST_TYPE == REQ_TYPE_PICKLE_ZLIB:
            reply = zlib.decompress(reply)
        result = pickle.loads(reply)

        # Return the result
        return result
    # END _send_recv

    def _send_only(self, externalObject, timeout=-1):

        logging.debug("AED Async Send Timeout: %s" % timeout)

        # Serialize and compress the externalObject
        zmo = pickle.dumps(externalObject, pickle.HIGHEST_PROTOCOL)
        if self._REQUEST_TYPE == REQ_TYPE_PICKLE_ZLIB:
            zmo = zlib.compress(zmo)

        # Send (if _TIMEOUT=None, there is unlimited time)
        try:
            if timeout:
                tracker = self._CLIENT.send_multipart([self._REQUEST_TYPE, '', zmo], copy=False, track=True)
                tracker.wait(timeout)
            else:
                self._CLIENT.send_multipart([self._REQUEST_TYPE, '', zmo])
        # An error will occur if the ZMQ socket is in the wrong state
        # In this case, we disconnect and then reconnect before retrying
        # If the second attempt fails, return False
        except self.zmq.NotDone:
            logging.debug("Message sending timed out...")
            return False
        except:
            try:
                logging.debug("ID %i : ZMQ socket in wrong state, reconnecting" % self._ID)
                self._disconnect()
                self._connect()
                if timeout:
                    tracker = self._CLIENT.send_multipart([self._REQUEST_TYPE, '', zmo], copy=False, track=True)
                    tracker.wait(timeout)
                else:
                    self._CLIENT.send_multipart([self._REQUEST_TYPE, '', zmo])
            except:
                return False
        # Return the result
        return True
    # END _send_only

    def send(self, externalObject, retry=0, timeout=None):
        self._TIMEOUT = timeout
        retriesLeft = retry
        result = None
        try:
            if self._ASYNC:
                result = self._send_only(externalObject, timeout=self._TIMEOUT)
            else:
                result = self._send_recv(externalObject)
            while retriesLeft and not result:
                logging.debug("ID %i : No response from broker, retrying..." % self._ID)
                self._disconnect()
                self._connect()
                if self._ASYNC:
                    result = self._send_only(externalObject, timeout=self._TIMEOUT)
                else:
                    result = self._send_recv(externalObject)
                retriesLeft -= 1
            return result

        except KeyboardInterrupt:
            print "Interrupted by user, exiting..."
            sys.exit()
        except:
            raise
    # END send

