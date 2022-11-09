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
from __future__ import division
from future import standard_library
standard_library.install_aliases()
from builtins import range
import io
import logging
try:
    import LnkParse3 as lnkfile
except ImportError:
    import lnkfile
import uuid
import base64
from datetime import datetime

# Import classes and helpers from the Laika framework
from laikaboss.objectmodel import ExternalVars, ModuleObject, ScanError
from laikaboss.util import laika_temp_dir
from laikaboss.si_module import SI_MODULE

class META_LNK(SI_MODULE):

    def __init__(self):
        self.module_name = "META_LNK"

    def _run(self, scanObject, result, depth, args):
        moduleResult = []

        link = None

        try:
            link = lnkfile.lnk_file(io.BytesIO(scanObject.buffer))
        except Exception as e:
            logging.exception(e)
            pass
        if link:
            try:
                def add_tracker_data(tree, key):
                    try:
                        u = uuid.UUID(bytes=uuid.UUID(tree[key]).bytes_le)
                        # calculate human-readable datetime
                        tree[key + '_human'] = datetime.fromtimestamp((u.time - 0x01b21dd213814000)*100//1e9).strftime('%Y-%m-%d %H:%M:%S.%f')
                        fmt = "{:012x}".format(u.node)
                        # format mac address
                        tree[key + '_node'] = ":".join(fmt[i:i+2] for i in range(0, len(fmt), 2))
                    except Exception as e:
                        logging.exception(e)
                meta = {}

                try:
                    # LinkParse3 changed the formatting of objects, now it seems that everything is accessible through the json object
                    tmp_json = link.get_json()
                    meta['header'] = tmp_json['header']
                    # lnkparse saves the datetime.datetime object, just need to convert to readable
                    meta['header']['accessed_time'] = meta['header']['modified_time'].strftime('%Y-%m-%d %H:%M:%S.%f')
                    meta['header']['creation_time'] = meta['header']['modified_time'].strftime('%Y-%m-%d %H:%M:%S.%f')
                    meta['header']['modified_time'] = meta['header']['modified_time'].strftime('%Y-%m-%d %H:%M:%S.%f')
                    meta['data'] = tmp_json['data']
                except Exception as e:
                    pass

                #this bit may give wrong info, previous version of lnkparse may have given milliseconds instead of UTC, don't have an example with the fields
                if 'DISTRIBUTED_LINK_TRACKER_BLOCK' in tmp_json['extra']:
                      add_tracker_data(tmp_json['extra']['DISTRIBUTED_LINK_TRACKER_BLOCK'], 'droid_volume_identifier')
                      add_tracker_data(tmp_json['extra']['DISTRIBUTED_LINK_TRACKER_BLOCK'], 'birth_droid_volume_identifier')
                      add_tracker_data(tmp_json['extra']['DISTRIBUTED_LINK_TRACKER_BLOCK'], 'droid_file_identifier')
                      add_tracker_data(tmp_json['extra']['DISTRIBUTED_LINK_TRACKER_BLOCK'], 'birth_droid_file_identifier')
                meta['extra'] = tmp_json['extra'] 
                meta['link_info'] = tmp_json['link_info'] 
                meta['target'] = tmp_json['target']
                meta['data'] = tmp_json['data']
                scanObject.addMetadata(self.module_name, "lnk_file", meta)
            except Exception as e:
                logging.exception(e)
                pass

        return moduleResult

