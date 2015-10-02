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
import re
import struct
import hashlib
import binascii
import logging
import pefile
from datetime import datetime
from laikaboss.objectmodel import ModuleObject, ExternalVars, QuitScanException, \
                                GlobalScanTimeoutError, GlobalModuleTimeoutError
from laikaboss.si_module import SI_MODULE


class META_PE(SI_MODULE):
    def __init__(self):
        self.module_name = "META_PE"

    def _run(self, scanObject, result, depth, args):
        moduleResult = []
        imports = {}
        sections = {}
        dllChars = []
        imgChars = []
        exports = []
        cpu = []
        res_type = ""

        try:
            pe = pefile.PE(data = scanObject.buffer)
            
            # Reference: http://msdn.microsoft.com/en-us/library/windows/desktop/ms680341%28v=vs.85%29.aspx
            for section in pe.sections:
                secAttrs = []
                secName = section.Name.strip('\0')
                secData = { 'Virtual Address' : '0x%08X' % section.VirtualAddress,
                            'Virtual Size' : section.Misc_VirtualSize,
                            'Raw Size' : section.SizeOfRawData,
                            'MD5' : section.get_hash_md5() }
                if secData['MD5'] != scanObject.objectHash: 
                    moduleResult.append(ModuleObject(buffer=section.get_data(), 
                                                     externalVars=ExternalVars(filename=secName)))
    
                secChar = section.Characteristics
                if secChar & 0x20: secAttrs.append('CNT_CODE')
                if secChar & 0x40: secAttrs.append('CNT_INITIALIZED_DATA')
                if secChar & 0x80: secAttrs.append('CNT_UNINITIALIZED_DATA')
                if secChar & 0x200: secAttrs.append('LNK_INFO')
                if secChar & 0x2000000: secAttrs.append('MEM_DISCARDABLE')
                if secChar & 0x4000000: secAttrs.append('MEM_NOT_CACHED')
                if secChar & 0x8000000: secAttrs.append('MEM_NOT_PAGED')
                if secChar & 0x10000000: secAttrs.append('MEM_SHARED')
                if secChar & 0x20000000: secAttrs.append('MEM_EXECUTE')
                if secChar & 0x40000000: secAttrs.append('MEM_READ')
                if secChar & 0x80000000: secAttrs.append('MEM_WRITE')
                secData['Section Characteristics'] = secAttrs
    
                sections[secName] = secData
            sections['Total'] = pe.FILE_HEADER.NumberOfSections
            scanObject.addMetadata(self.module_name, 'Sections', sections)
    
            try:
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    exports.append(exp.name)
                scanObject.addMetadata(self.module_name, 'Exports', exports)
            except (QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError):
                raise
            except:
                logging.debug('No export entries')
  
            try:
                scanObject.addMetadata(self.module_name, 'Imphash', pe.get_imphash())
            except:
                logging.debug('Unable to identify imphash')
    
            try:
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    api = []
                    for imp in entry.imports:
                        api.append(imp.name)
                    imports[entry.dll] = filter(None, api)
            except (QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError):
                raise
            except:
                logging.debug('No import entries')
            scanObject.addMetadata(self.module_name, 'Imports', imports)
    
            # Reference: http://msdn.microsoft.com/en-us/library/windows/desktop/ms680313%28v=vs.85%29.aspx
            imgChar = pe.FILE_HEADER.Characteristics
            if imgChar & 0x1: imgChars.append('RELOCS_STRIPPED')
            if imgChar & 0x2: imgChars.append('EXECUTABLE_IMAGE')
            if imgChar & 0x4: imgChars.append('LINE_NUMS_STRIPPED')
            if imgChar & 0x8: imgChars.append('LOCAL_SYMS_STRIPPED')
            if imgChar & 0x10: imgChars.append('AGGRESIVE_WS_TRIM')
            if imgChar & 0x20: imgChars.append('LARGE_ADDRESS_AWARE')
            if imgChar & 0x80: imgChars.append('BYTES_REVERSED_LO')
            if imgChar & 0x100: imgChars.append('32BIT_MACHINE')
            if imgChar & 0x200: imgChars.append('DEBUG_STRIPPED')
            if imgChar & 0x400: imgChars.append('REMOVABLE_RUN_FROM_SWAP')
            if imgChar & 0x800: imgChars.append('NET_RUN_FROM_SWAP')
            if imgChar & 0x1000: imgChars.append('SYSTEM_FILE')
            if imgChar & 0x2000: imgChars.append('DLL_FILE')
            if imgChar & 0x4000: imgChars.append('UP_SYSTEM_ONLY')
            if imgChar & 0x8000: imgChars.append('BYTES_REVERSED_HI')
    
            scanObject.addMetadata(self.module_name, 'Image Characteristics', imgChars)
    
            scanObject.addMetadata(self.module_name, 'Date', datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp).isoformat())
            scanObject.addMetadata(self.module_name, 'Timestamp', pe.FILE_HEADER.TimeDateStamp)
    
            machine = pe.FILE_HEADER.Machine
            cpu.append(machine)
    
            # Reference: http://en.wikibooks.org/wiki/X86_Disassembly/Windows_Executable_Files#COFF_Header
            if machine == 0x14c: cpu.append('Intel 386')
            if machine == 0x14d: cpu.append('Intel i860')
            if machine == 0x162: cpu.append('MIPS R3000')
            if machine == 0x166: cpu.append('MIPS little endian (R4000)')
            if machine == 0x168: cpu.append('MIPS R10000')
            if machine == 0x169: cpu.append('MIPS little endian WCI v2')
            if machine == 0x183: cpu.append('old Alpha AXP')
            if machine == 0x184: cpu.append('Alpha AXP')
            if machine == 0x1a2: cpu.append('Hitachi SH3')
            if machine == 0x1a3: cpu.append('Hitachi SH3 DSP')
            if machine == 0x1a6: cpu.append('Hitachi SH4')
            if machine == 0x1a8: cpu.append('Hitachi SH5')
            if machine == 0x1c0: cpu.append('ARM little endian')
            if machine == 0x1c2: cpu.append('Thumb')
            if machine == 0x1d3: cpu.append('Matsushita AM33')
            if machine == 0x1f0: cpu.append('PowerPC little endian')
            if machine == 0x1f1: cpu.append('PowerPC with floating point support')
            if machine == 0x200: cpu.append('Intel IA64')
            if machine == 0x266: cpu.append('MIPS16')
            if machine == 0x268: cpu.append('Motorola 68000 series')
            if machine == 0x284: cpu.append('Alpha AXP 64-bit')
            if machine == 0x366: cpu.append('MIPS with FPU')
            if machine == 0x466: cpu.append('MIPS16 with FPU')
            if machine == 0xebc: cpu.append('EFI Byte Code')
            if machine == 0x8664: cpu.append('AMD AMD64')
            if machine == 0x9041: cpu.append('Mitsubishi M32R little endian')
            if machine == 0xc0ee: cpu.append('clr pure MSIL')
    
            # Reference: http://msdn.microsoft.com/en-us/library/windows/desktop/ms680339%28v=vs.85%29.aspx
            magic = pe.OPTIONAL_HEADER.Magic
            if magic == 0x10b: cpu.append('32_BIT')
            if magic == 0x20b: cpu.append('64_BIT')
            if magic == 0x107: cpu.append('ROM_IMAGE')
    
            cpu.append("0x%04X" % magic)
    
            scanObject.addMetadata(self.module_name, 'CPU', cpu)
    
            dllChar = pe.OPTIONAL_HEADER.DllCharacteristics
            if dllChar & 0x40: dllChars.append('DYNAMIC_BASE')
            if dllChar & 0x80: dllChars.append('FORCE_INTEGRITY')
            if dllChar & 0x100: dllChars.append('NX_COMPAT')
            if dllChar & 0x200: dllChars.append('NO_ISOLATION')
            if dllChar & 0x400: dllChars.append('NO_SEH')
            if dllChar & 0x800: dllChars.append('NO_BIND')
            if dllChar & 0x2000: dllChars.append('WDM_DRIVER')
            if dllChar & 0x8000: dllChars.append('TERMINAL_SERVER_AWARE')
    
            scanObject.addMetadata(self.module_name, 'DLL Characteristics', dllChars)
    
            subsystem = pe.OPTIONAL_HEADER.Subsystem
            if subsystem == 0: scanObject.addMetadata(self.module_name, 'Subsystem', 'UNKNOWN')
            if subsystem == 1: scanObject.addMetadata(self.module_name, 'Subsystem', 'NATIVE')
            if subsystem == 2: scanObject.addMetadata(self.module_name, 'Subsystem', 'WINDOWS_GUI')
            if subsystem == 3: scanObject.addMetadata(self.module_name, 'Subsystem', 'WINDOWS_CUI')
            if subsystem == 5: scanObject.addMetadata(self.module_name, 'Subsystem', 'OS2_CUI')
            if subsystem == 7: scanObject.addMetadata(self.module_name, 'Subsystem', 'POSIX_CUI')
            if subsystem == 9: scanObject.addMetadata(self.module_name, 'Subsystem', 'WINDOWS_CE_GUI')
            if subsystem == 10: scanObject.addMetadata(self.module_name, 'Subsystem', 'EFI_APPLICATION')
            if subsystem == 11: scanObject.addMetadata(self.module_name, 'Subsystem', 'EFI_BOOT_SERVICE_DRIVER')
            if subsystem == 12: scanObject.addMetadata(self.module_name, 'Subsystem', 'EFI_RUNTIME_DRIVER')
            if subsystem == 13: scanObject.addMetadata(self.module_name, 'Subsystem', 'EFI_ROM')
            if subsystem == 14: scanObject.addMetadata(self.module_name, 'Subsystem', 'XBOX')
            if subsystem == 16: scanObject.addMetadata(self.module_name, 'Subsystem', 'BOOT_APPLICATION')
    
            # Reference: http://msdn.microsoft.com/en-us/library/windows/desktop/ms648009%28v=vs.85%29.aspx
    
            try:
                for resource in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if resource.id == 9: res_type = "RT_ACCELERATOR"
                    if resource.id == 21: res_type = "RT_ANICURSOR"
                    if resource.id == 22: res_type = "RT_ANIICON"
                    if resource.id == 2: res_type = "RT_BITMAP"
                    if resource.id == 1: res_type = "RT_CURSOR"
                    if resource.id == 5: res_type = "RT_DIALOG"
                    if resource.id == 17: res_type = "RT_DLGINCLUDE"
                    if resource.id == 8: res_type = "RT_FONT"
                    if resource.id == 7: res_type = "RT_FONTDIR"
                    if resource.id == 12: res_type = "RT_GROUP_CURSOR"
                    if resource.id == 14: res_type = "RT_GROUP_ICON"
                    if resource.id == 23: res_type = "RT_HTML"
                    if resource.id == 3: res_type = "RT_ICON"
                    if resource.id == 24: res_type = "RT_MANIFEST"
                    if resource.id == 4: res_type = "RT_MENU"
                    if resource.id == 11: res_type = "RT_MESSAGETABLE"
                    if resource.id == 19: res_type = "RT_PLUGPLAY"
                    if resource.id == 10: res_type = "RT_RCDATA"
                    if resource.id == 6: res_type = "RT_STRING"
                    if resource.id == 16: res_type = "RT_VERSION"
                    if resource.id == 20: res_type = "RT_VXD"
    
                    for entry in resource.directory.entries:
                        scanObject.addMetadata(self.module_name, 'Resources', res_type + "_%s" % entry.id)
            except (QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError):
                raise
            except: 
                logging.debug('No resources')
         
               
            scanObject.addMetadata(self.module_name, 'Stack Reserve Size', pe.OPTIONAL_HEADER.SizeOfStackReserve)
            scanObject.addMetadata(self.module_name, 'Stack Commit Size', pe.OPTIONAL_HEADER.SizeOfStackCommit)
    
            scanObject.addMetadata(self.module_name, 'Heap Reserve Size', pe.OPTIONAL_HEADER.SizeOfHeapReserve)
            scanObject.addMetadata(self.module_name, 'Heap Commit Size', pe.OPTIONAL_HEADER.SizeOfHeapCommit)
    
            scanObject.addMetadata(self.module_name, 'EntryPoint', hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
            scanObject.addMetadata(self.module_name, 'ImageBase', hex(pe.OPTIONAL_HEADER.ImageBase))

            # Parse RSDS & Rich
            scanObject.addMetadata(self.module_name, 'RSDS', self.parseRSDS(scanObject))
            scanObject.addMetadata(self.module_name, 'Rich', self.parseRich(pe))

        except pefile.PEFormatError:
            logging.debug("Invalid PE format")

        return moduleResult

    @staticmethod
    def parseRSDS(scanObject):
        """
        Parses out RSDS pdb information

        00000000  52 53 44 53 b4 bc 76 74  d2 9f 6a 49 b5 6c 74 7c  |RSDS..vt..jI.lt||
        00000010  1d 41 bb a5 05 00 00 00  44 3a 5c 4d 69 63 72 6f  |.A......D:\Micro|
        00000020  73 6f 66 74 20 56 69 73  75 61 6c 20 53 74 75 64  |soft Visual Stud|
        00000030  69 6f 5c 66 69 6c 65 73  5c 43 23 5c 7a 63 67 2e  |io\files\C#\zcg.|
        00000040  43 68 6f 70 70 65 72 53  72 65 76 65 72 46 6f 72  |ChopperSreverFor|
        00000050  43 73 68 61 72 70 5c 6f  62 6a 5c 52 65 6c 65 61  |Csharp\obj\Relea|
        00000060  73 65 5c 53 79 73 74 65  6d 2e 57 65 62 53 65 72  |se\System.WebSer|
        00000070  76 69 63 65 73 2e 70 64  62 00 00 00 04 55 00 00  |vices.pdb....U..|

        +0h   dword        "RSDS" signature
        +4h   GUID         16-byte Globally Unique Identifier
        +14h  dword        "age"
        +18h  byte string  zero terminated UTF8 path and file name

        http://www.godevtool.com/Other/pdb.htm
        """
        
        result = dict()
        rsds = re.compile('RSDS.{24,1024}\.pdb')
        x = rsds.findall(scanObject.buffer)
        
        if x and x[-1]:
            match = x[-1]
            result["guid"] = "%s-%s-%s-%s" % (binascii.hexlify(match[4:8]),
                                              binascii.hexlify(match[8:10]),
                                              binascii.hexlify(match[10:12]),
                                              binascii.hexlify(match[12:20]))
            result["age"] = struct.unpack('<L', match[20:24])[0]
            result["pdb"] = match[24:]

        return result

    @staticmethod
    def parseRich(pe):
        """
        Parses out Rich header information using pefile.
        """
        res = list()
        result = dict()

        if pe.RICH_HEADER:
            for x in range(0, len(pe.RICH_HEADER.values), 2):
                res.append((pe.RICH_HEADER.values[x] >> 16, pe.RICH_HEADER.values[x] & 0xffff, pe.RICH_HEADER.values[x+1]))

            if res:
                result['id'] = [x[0] for x in res]
                result['version'] = [x[1] for x in res]
                result['count'] = [x[2] for x in res]
                result['hash'] = hashlib.md5(str(res)).hexdigest()

        return result
