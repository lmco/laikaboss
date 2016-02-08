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
SCAN CLAMAV

Laika module for scanning with the ClamAV Daemon

Install pyClamd 0.3.10 or greater from:
  https://pypi.python.org/pypi/pyClamd/
  or
  http://xael.org/norman/python/pyclamd/
'''


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
        self.clam = None

    def _run(self, scanObject, result, depth, args):
        '''
        Arguments:
        unixsocket     -- Path to the clamd unix socket (str)
        maxbytes       -- Maximum number of bytes to scan (0 is unlimited) (int)

        Returns:
        Flags           -- Virus name hits
        Metadata        -- Unix socket or daemon errors
        '''
        moduleResult = []

        unix_socket = str(get_option(args, 'unixsocket', 'scanclamavunixsocket', '/var/run/clamav/clamd.ctl'))
        max_bytes = int(get_option(args, 'maxbytes', 'scanclamavmaxbytes', 20000000))

        # Connect to daemon
        if not self.clam:
            try:
                self.clam = pyclamd.ClamdUnixSocket(filename=unix_socket)
            except IOError:
                logging.debug('IOError: Cannot connect to clamd unix socket file')
                scanObject.addMetadata(self.module_name, 'Error', 'IOError: clamd socket')
                raise

        try:
            # Scan the buffer with clamav
            if max_bytes <= 0:
                clam_result = self.clam.scan_stream(scanObject.buffer)
            else:
                clam_result = self.clam.scan_stream(str(buffer(scanObject.buffer, 0, max_bytes)))

            # Process a result
            if clam_result:
                status, virusname = clam_result['stream']
                scanObject.addFlag("%s:%s" % (self.flag_prefix, str(virusname)))
        except ValueError as e:
            scanObject.addMetadata(self.module_name, 'Error', 'ValueError (BufferTooLong): %s' % str(e))
        except IOError as e:
            scanObject.addMetadata(self.module_name, 'Error', 'IOError (ScanError): %s' % str(e))

        return moduleResult
