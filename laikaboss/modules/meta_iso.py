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
# Module that uses pycdlib library to parse metadata from iso files.
# Library dependancies: pycdlib
from future import standard_library
standard_library.install_aliases()
from laikaboss.si_module import SI_MODULE
from laikaboss import config
import io
import pycdlib
import os

class META_ISO(SI_MODULE):
    b'''
    Input: An iso file to extract metadata from.
    Output: None. Adds module metadata about the object and flags if appropriate.

    Purpose: Extract metadata from iso files
    b'''
    def __init__(self,):
        self.module_name = "META_ISO"

    def _run(self, scanObject, result, depth, args):
        moduleResult = []

        iso = pycdlib.PyCdlib()
        iso.open_fp(io.BytesIO(scanObject.buffer))

        # Find a volume descriptor to parse
        if(iso.enhanced_vd):
            vd = iso.enhanced_vd
        elif iso.joliet_vd:
            vd = iso.joliet_vd
        elif iso.eltorito_boot_catalog:
            vd = iso.eltorito_boot_catalog.dirrecord.vd
        else:
            vd = None

        # Parse data from volume descriptor
        if vd:
            temp_str = vd.abstract_file_identifier.replace(b'\x00', b'').rstrip()
            if(temp_str != b''):
                scanObject.addMetadata(self.module_name, 'abstract_file_identifier', temp_str)

            temp_str = vd.application_identifier.text.replace(b'\x00', b'').rstrip()
            if(temp_str != b''):
                scanObject.addMetadata(self.module_name, 'application_identifier', temp_str)

            temp_str = vd.application_use.replace(b'\x00', b'').rstrip()
            if(temp_str != b''):
                scanObject.addMetadata(self.module_name, 'application_use', temp_str)

            temp_str = vd.bibliographic_file_identifier.replace(b'\x00', b'').rstrip()
            if(temp_str != b''):
                scanObject.addMetadata(self.module_name, 'bibliographic_file_identifier', temp_str)

            temp_str = vd.copyright_file_identifier.replace(b'\x00', b'').rstrip()
            if(temp_str != b''):
                scanObject.addMetadata(self.module_name, 'copyright_file_identifier', temp_str)

            temp_str = vd.escape_sequences.replace(b'\x00', b'').rstrip()
            if(temp_str != b''):
                scanObject.addMetadata(self.module_name, 'escape_sequences', temp_str)

            scanObject.addMetadata(self.module_name, 'file_structure_version', vd.file_structure_version)

            scanObject.addMetadata(self.module_name, 'flags', vd.flags)

            scanObject.addMetadata(self.module_name, 'logical_block_size', vd.log_block_size)


            # Still available (path_table stuff / rr_ce_entry / orig_extent_loc

            temp_str =  vd.preparer_identifier.text.replace(b'\x00', b'').rstrip()
            if(temp_str != b''):
                scanObject.addMetadata(self.module_name, 'preparer_identifier', temp_str)

            temp_str =  vd.publisher_identifier.text.replace(b'\x00', b'').rstrip()
            if(temp_str != b''):
                scanObject.addMetadata(self.module_name, 'publisher_identifier', temp_str)

            scanObject.addMetadata(self.module_name, 'sequence_number', vd.seqnum)

            scanObject.addMetadata(self.module_name, 'set_size', vd.set_size)

            scanObject.addMetadata(self.module_name, 'space_size', vd.space_size)

            temp_str =  vd.system_identifier.replace(b'\x00', b'').rstrip()
            if(temp_str != b''):
                scanObject.addMetadata(self.module_name, 'system_identifier', temp_str)

            scanObject.addMetadata(self.module_name, 'version', vd.version)

            scanObject.addMetadata(self.module_name, 'volume_creation_date', self.date_as_str(vd.volume_creation_date))
            scanObject.addMetadata(self.module_name, 'volume_effective_date', self.date_as_str(vd.volume_effective_date))
            scanObject.addMetadata(self.module_name, 'volume_expiration_date', self.date_as_str(vd.volume_expiration_date))
            scanObject.addMetadata(self.module_name, 'volume_modification_date', self.date_as_str(vd.volume_modification_date))

            temp_str = vd.volume_identifier.replace(b'\x00', b'').rstrip()
            if(temp_str != b''):
                scanObject.addMetadata(self.module_name, 'volume_identifier', temp_str)

            temp_str = vd.volume_set_identifier.replace(b'\x00', b'').rstrip()
            if(temp_str != b''):
                scanObject.addMetadata(self.module_name, 'volume_set_identifier', temp_str)

        if iso.version_vd:
            # Can't just strip file, find first null and add string up to that first null
            version_vd = iso.version_vd.record().replace(b'\x00', b'').rstrip()
            if(version_vd != b''):
                scanObject.addMetadata(self.module_name, 'version_vd', version_vd)
                #print version_vd

        iso.close()
        return moduleResult

    # Helper method that format the data into available in volume descriptor into a string
    @staticmethod
    def date_as_str(date):
        return '%d-%d-%d %d:%d:%d.%02d(%+d)' % (date.year, date.dayofmonth, date.month, date.hour, date.minute, date.second, date.hundredthsofsecond, date.gmtoffset)


    def _close(self):
        pass
