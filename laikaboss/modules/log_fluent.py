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
from copy import deepcopy as clone_object
from fluent.sender import FluentSender
from math import isnan, isinf
from laikaboss.si_module import SI_MODULE
from laikaboss.util import get_option, log_module_error
from uuid import UUID

# XXX: Stub class for scanObject for spoofing log_module_error
class ScanObjectStub:
    def __init__(self,):
        self.parent = ''
        self.uuid = ''

# XXX: Stub class for result for spoofing log_module_error
class ResultStub:
    def __init__(self,):
        self.files = {}

class LOG_FLUENT(SI_MODULE):
    '''Laika module for logging scan results using fluentd.'''

    def __init__(self,):
        '''Main constructor'''
        self.module_name = "LOG_FLUENT"
        self._senders = {}

    def _run(self, scanObject, result, depth, args):
        """Main module execution. Logs the scan result to fluentd."""
        tag  = get_option(args, "tag",  "fluent_tag",  "laikaboss.log_fluent")
        host = get_option(args, "host", "fluent_host", "localhost")
        port = int(get_option(args, "port", "fluent_port", 24224))
        bufmax = int(get_option(args, "bufmax", "fluent_bufmax", 1048576)) # 1 MB
        timeout = float(get_option(args, "timeout", "fluent_timeout", 3.0))
        label = get_option(args, "label", "fluent_label", "scan_result")

        sender = self._get_sender(tag, host, port, bufmax, timeout)
        log_record = self._parse_log_record(result)
        sender.emit(label, log_record)
        if sender.pendings: # buffer in case of failed transmission
            log_module_error(self.module_name, scanObject, result,
                'Log event failed emition. Will retry on next emition.')
        return []

    def _close(self,):
        '''Laika framework destructor'''
        for sender in self._senders.itervalues():
            if sender.pendings:
                sender.emit('flush',
                    {'message':
                        'This event is to flush out the buffer of the python fluentd logger'})
                if sender.pendings:
                    # XXX: Laika logging hack using stubs
                    log_module_error(self.module_name, ScanObjectStub(), ResultStub(),
                        'Failed to flush buffer. Log events lost.')

    def _get_sender(self, tag, host, port, bufmax, timeout):
        '''
        Get the Fluentd sender for the given arguments.

        Arguments:
        tag     --  The base tag of the log event, representing the
                    application.
        host    --  The host name or IP address of the fluentd server.
        port    --  The port number the fluentd server is listeneing on.
        bufmax  --  The size of the buffer.
        timeout --  The timeout

        Returns:
        A FluentSender with the given configuration.
        '''
        sender = None
        key = "%s%s%d%d%f" % (tag, host, port, bufmax, timeout)
        if key in self._senders:
            sender = self._senders[key]
        else:
            sender = FluentSender(tag, host, port, bufmax, timeout)
            self._senders[key] = sender
        return sender

    def _parse_log_record(self, result):
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
            'scan_result': self._log_record_strainer(buffer_results)
        }

        return log_record

    def _log_record_strainer(self, thing):
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
                new_thing.append(self._log_record_strainer(element))
            return new_thing
        elif thing_type is dict:
            new_thing = {}
            for key, value in thing.iteritems():
                new_key = self._log_record_strainer(key)
                new_value = self._log_record_strainer(value)
                new_thing[new_key] = new_value
            return new_thing
        elif thing_type is UUID:
            return str(thing)
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
        else:
            return thing

