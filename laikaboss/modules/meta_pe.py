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
import struct
import hashlib
import binascii
import logging
import pefile
from datetime import datetime
from laikaboss.objectmodel import (ModuleObject,
                                   ExternalVars,
                                   ScanError)
from laikaboss.si_module import SI_MODULE

IMAGE_MAGIC_LOOKUP = {
    0x10b: '32_BIT',
    0x20b: '64_BIT',
    0x107: 'ROM_IMAGE',
}

class META_PE(SI_MODULE):
    def __init__(self):
        self.module_name = "META_PE"

    def _run(self, scanObject, result, depth, args):
        moduleResult = []
        imports = {}
        sections = {}
        exports = []

        try:
            pe = pefile.PE(data=scanObject.buffer)
            dump_dict = pe.dump_dict()

            # Parse sections
            for section in dump_dict.get('PE Sections', []):
                secName = section.get('Name', {}).get('Value', '').strip('\0')
                ptr = section.get('PointerToRawData', {}).get('Value')
                virtAddress = section.get('VirtualAddress', {}).get('Value')
                virtSize = section.get('Misc_VirtualSize', {}).get('Value')
                size = section.get('SizeOfRawData', {}).get('Value')
                secData = pe.get_data(ptr, size)
                secInfo = {
                    'Virtual Address': '0x%08X' % virtAddress,
                    'Virtual Size': virtSize,
                    'Raw Size': size,
                    'MD5': section.get('MD5', ''),
                    'SHA1': section.get('SHA1', ''),
                    'SHA256': section.get('SHA256', ''),
                    'Entropy': section.get('Entropy', ''),
                    'Section Characteristics': section.get('Flags', []),
                    'Structure': section.get('Structure', ''),
                }
                if secInfo['MD5'] != scanObject.objectHash:
                    moduleResult.append(ModuleObject(
                        buffer=secData,
                        externalVars=ExternalVars(filename=secName)))
                sections[secName] = secInfo
            sections['Total'] = pe.FILE_HEADER.NumberOfSections
            scanObject.addMetadata(self.module_name, 'Sections', sections)

            # Parse imports and exports
            try:
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    exports.append(exp.name)
                scanObject.addMetadata(self.module_name, 'Exports', exports)
            except ScanError:
                raise
            except:
                logging.debug('No export entries')

            for imp_symbol in dump_dict.get('Imported symbols',[]):
                for imp in imp_symbol:
                    if imp.get('DLL'):
                        dll = imp.get('DLL')
                        imports.setdefault(dll, [])
                        # Imports can be identified by ordinal or name
                        if imp.get('Ordinal'):
                            ordinal = imp.get('Ordinal')
                            imports[dll].append(ordinal)
                        if imp.get('Name'):
                            name = imp.get('Name')
                            imports[dll].append(name)
            scanObject.addMetadata(self.module_name, 'Imports', imports)

            # Parse resources
            try:
                for resource in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    res_type = pefile.RESOURCE_TYPE.get(resource.id, 'Unknown')
                    for entry in resource.directory.entries:
                        for e_entry in entry.directory.entries:
                            sublang = pefile.get_sublang_name_for_lang(
                                e_entry.data.lang,
                                e_entry.data.sublang,
                            )
                            offset = e_entry.data.struct.OffsetToData
                            size = e_entry.data.struct.Size
                            r_data = pe.get_data(offset, size)
                            language = pefile.LANG.get(
                                e_entry.data.lang, 'Unknown')
                            data = {
                                'Type': res_type,
                                'Id': e_entry.id,
                                'Name': e_entry.data.struct.name,
                                'Offset': offset,
                                'Size': size,
                                'SHA256': hashlib.sha256(r_data).hexdigest(),
                                'SHA1': hashlib.sha1(r_data).hexdigest(),
                                'MD5': hashlib.md5(r_data).hexdigest(),
                                'Language': language,
                                'Sub Language': sublang,
                            }
                            scanObject.addMetadata(
                                self.module_name, 'Resources', data)
            except ScanError:
                raise
            except:
                logging.debug('No resources')

            # Gather miscellaneous stuff
            try:
                scanObject.addMetadata(self.module_name,
                                       'Imphash', pe.get_imphash())
            except ScanError:
                raise
            except:
                logging.debug('Unable to identify imphash')

            imgChars = dump_dict.get('Flags', [])
            scanObject.addMetadata(
                self.module_name, 'Image Characteristics', imgChars)
            # Make a pretty date format
            date = datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp)
            isoDate = date.isoformat()
            scanObject.addMetadata(self.module_name, 'Date', isoDate)
            scanObject.addMetadata(
                self.module_name, 'Timestamp', pe.FILE_HEADER.TimeDateStamp)

            machine = pe.FILE_HEADER.Machine
            machineData = {
                'Id': machine,
                'Type': pefile.MACHINE_TYPE.get(machine)
            }
            scanObject.addMetadata(
                self.module_name, 'Machine Type', machineData)

            # Reference: http://msdn.microsoft.com/en-us/library/windows/desktop/ms680339%28v=vs.85%29.aspx
            scanObject.addMetadata(
                self.module_name,
                'Image Magic',
                IMAGE_MAGIC_LOOKUP.get(pe.OPTIONAL_HEADER.Magic, 'Unknown'))

            dllChars = dump_dict.get('DllCharacteristics', [])
            scanObject.addMetadata(
                self.module_name, 'DLL Characteristics', dllChars)

            subsystem = pe.OPTIONAL_HEADER.Subsystem
            subName = pefile.SUBSYSTEM_TYPE.get(subsystem)
            scanObject.addMetadata(self.module_name, 'Subsystem', subName)

            # Reference: http://msdn.microsoft.com/en-us/library/windows/desktop/ms648009%28v=vs.85%29.aspx

            scanObject.addMetadata(
                self.module_name,
                'Stack Reserve Size',
                pe.OPTIONAL_HEADER.SizeOfStackReserve)
            scanObject.addMetadata(
                self.module_name,
                'Stack Commit Size',
                pe.OPTIONAL_HEADER.SizeOfStackCommit)
            scanObject.addMetadata(
                self.module_name,
                'Heap Reserve Size',
                pe.OPTIONAL_HEADER.SizeOfHeapReserve)
            scanObject.addMetadata(
                self.module_name,
                'Heap Commit Size',
                pe.OPTIONAL_HEADER.SizeOfHeapCommit)
            scanObject.addMetadata(
                self.module_name,
                'EntryPoint',
                hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
            scanObject.addMetadata(
                self.module_name,
                'ImageBase',
                hex(pe.OPTIONAL_HEADER.ImageBase))

            # Parse RSDS & Rich
            scanObject.addMetadata(
                self.module_name, 'Rich Header', self.parseRich(pe))

            if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
                debug = dict()
                for e in pe.DIRECTORY_ENTRY_DEBUG:
                    rawData = pe.get_data(e.struct.AddressOfRawData, e.struct.SizeOfData)
                    if rawData.find('RSDS') != -1 and len(rawData) > 24:
                        pdb = rawData[rawData.find('RSDS'):]
                        debug["guid"] = "%s-%s-%s-%s" % (
                            binascii.hexlify(pdb[4:8]),
                            binascii.hexlify(pdb[8:10]),
                            binascii.hexlify(pdb[10:12]),
                            binascii.hexlify(pdb[12:20]))
                        debug["age"] = struct.unpack('<L', pdb[20:24])[0]
                        debug["pdb"] = pdb[24:].rstrip('\x00')
                        scanObject.addMetadata(self.module_name, 'RSDS', debug)
                    elif rawData.find('NB10') != -1 and len(rawData) > 16:
                        pdb = rawData[rawData.find('NB10')+8:]
                        debug["created"] = datetime.fromtimestamp(struct.unpack('<L', pdb[0:4])[0]).isoformat()
                        debug["age"] = struct.unpack('<L', pdb[4:8])[0]
                        debug["pdb"] = pdb[8:].rstrip('\x00')
                        scanObject.addMetadata(self.module_name, 'NB10', debug)

        except pefile.PEFormatError:
            logging.debug("Invalid PE format")
        return moduleResult

    def parseRich(self, pe):
        """
        Parses out Rich header information using pefile.
        """
        result = {}
        data = []
        if pe.RICH_HEADER:
            for x in range(0, len(pe.RICH_HEADER.values), 2):
                value = pe.RICH_HEADER.values[x] >> 16
                version = pe.RICH_HEADER.values[x] & 0xffff
                count = pe.RICH_HEADER.values[x + 1]
                data.append({
                    'Id': value,
                    'Version': version,
                    'Count': count,
                })

            result['Rich Header Values'] = data
            result['Checksum'] = pe.RICH_HEADER.checksum
            result['Hashes'] = self.richHeaderHashes(pe)

        return result

    @staticmethod
    def richHeaderHashes(pe):
        """
        Returns hashes of the Rich PE header
        """
        rich_data = pe.get_data(0x80, 0x80)
        data = list(struct.unpack('<32I', rich_data))
        checksum = data[1]
        rich_end = data.index(0x68636952)
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        for i in range(rich_end):
            md5.update(struct.pack('<I', (data[i] ^ checksum)))
            sha1.update(struct.pack('<I', (data[i] ^ checksum)))
            sha256.update(struct.pack('<I', (data[i] ^ checksum)))
        data = {
            'MD5': md5.hexdigest(),
            'SHA1': sha1.hexdigest(),
            'SHA256': sha256.hexdigest(),
        }
        return data
