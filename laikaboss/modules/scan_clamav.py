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
import logging
import pyclamd
from laikaboss.util import get_option
from laikaboss.si_module import SI_MODULE

class SCAN_CLAMAV(SI_MODULE):
    '''
    Laika module for scanning with the ClamAV Daemon
    '''
    def __init__(self,):
        self.module_name = "SCAN_CLAMAV"
        self.flag_prefix = "clam"

    def _run(self, scanObject, result, depth, args):
        '''
        Arguments:
        unix_socket     -- Path to the clamd unix socket (str)
        max_bytes       -- Maximum number of bytes to scan (0 is unlimited) (int)
        timeout         -- Max number of seconds to scan (float)

        Returns:
        Flags           -- Virus name hits
        Metadata        -- Unix socket or daemon errors
        '''
        moduleResult = []

        # Defualt max of 20 MB
        default_max_bytes = 20000000
        # Default timeout of 10.0 seconds
        default_timeout = 10.0
        # Default clamd unix socket
        default_unix_socket = '/var/run/clamav/clamd.sock'

        unix_socket = str(get_option(args, 'unixsocket', 'scanclamavunixsocket', default_unix_socket))
        max_bytes = int(get_option(args, 'maxbytes', 'scanclamavmaxbytes', default_max_bytes))
        timeout = float(get_option(args, 'timeout', 'scanclamavtimeout', default_timeout))

        if timeout < 0.01:
            timeout = default_timeout

        # Connect to daemon
        try:
            clam = pyclamd.ClamdUnixSocket(filename=unix_socket, timeout=timeout)
        except IOError:
            logging.debug('IOError: Cannot connect to clamd unix socket file')
            scanObject.addMetadata(self.module_name, 'Error', 'IOError: clamd socket')
            return moduleResult

        errmsg = None
        try:
            # Scan the buffer with clamav
            if max_bytes <= 0:
                clam_result = clam.scan_stream(scanObject.buffer)
            else:
                clam_result = clam.scan_stream(str(buffer(scanObject.buffer, 0, max_bytes)))

            # Process a result
            if clam_result:
                status, virusname = clam_result['stream']
                scanObject.addFlag("%s:%s" % (self.flag_prefix, str(virusname)))
        except ValueError as e:
            errmsg = "ValueError (BufferTooLong): %s" % e
        except IOError as e:
            errmsg = "IOError (ScanError): %s" % e
        except Exception as e:
            errmsg = "Unexpected error: %s" % e

        if errmsg:
            logging.debug(errmsg)
            scanObject.addMetadata(self.module_name, 'Error', errmsg)

        return moduleResult
