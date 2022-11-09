#!/usr/bin/env python
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

"""
This is a helper class that parses Mach-O files and returns the metadata.

# Depends on macholib
# Macholib: https://pypi.python.org/pypi/macholib/
"""
from __future__ import absolute_import

# Python library imports
from builtins import str
from builtins import range
from builtins import object
import struct
import os
import os.path
import logging
import tempfile

# Third-party Python library imports
# The macholib library is used to handle the byte-parsing of a lot of the file structures
try:
    #import the parsing stuff from the macholib library
    from macholib.MachO import MachO
    #import the header constants
    from macholib.mach_o import *
    HAVE_MACHO = True
except ImportError:
    HAVE_MACHO = False

# LaikaBoss imports
from . import macho_data as data

class MachO_Parse(object):
    """Mach-O and FAT file static analysis"""

    def __init__(self, file_obj):
        self.file_object = file_obj
        self.sub_files = [] # list for contained files if this is a FAT file

    def parse(self):
        """Parse the file's static attributes.
        @return: analysis results dict or None.
        """
        results = {}

        #write a temporary file
        self.tfile = tempfile.NamedTemporaryFile()
        self.tfile.write(self.file_object)
        self.tfile.flush()
        self.file_name = self.tfile.name

        #Use the macho library to parse out some structures
        pFile = MachO(self.file_name)

        #if this is a fat file, it will have multiple Mach-O objects inside it
        results["FAT_header"] = self.parseFATHeader(self.tfile, pFile)

        #parse all the Mach-O headers
        i = 1
        for h in pFile.headers:
            results["MachO_header" + str(i)] = self.parseMachOHeader(h, self.file_object)
            i +=1

        #close the file
        self.tfile.close()

        #return the dict of results
        return results

    def parseMachOHeader(self, header, file_object):
        results = {}
        m = header.MH_MAGIC
        #get down to the actual header info
        h = header.header

        ### get human-readable strings ###
        cpu_type = CPU_TYPE_NAMES.get(h.cputype, h.cputype)
        results["cpu_type"] = cpu_type
        #this needs a mask due to a couple high-bit types like lib64
        hex_stype = (h.cpusubtype + (1 << 32)) % (1 << 32)  #because some numbers turn out negative when read
        cpu_stype = self.getCPUSubtype(cpu_type, hex_stype & ~0xff000000)
        #test for the high-bit ones
        try:
            s = self.getCPUSubtype('high', hex_stype & 0xff000000)
            cpu_stype += ", " + s
        except TypeError: #meaning no matches
            pass
        results["cpu_subtype"] = cpu_stype
        #get the file type - library, executable, etc.
        results["ftype"] = data.FILE_TYPE.get(int(h.filetype))
        #get the list of flags
        results["flags"] = self.getFlags(h.flags)


        #reserved field only exists in 64-bit headers, so set to None if 32-bit
        res = 'NULL'
        if hasattr(h, 'reserved'):
            res = h.reserved
        results["reserved"] = res

        #parse the load commands
        (results["load_commands"], results["sections"]) = self.parseLoadCommands(header.commands)

        #get a stand-alone list of the dynamically linked libraries, just for convenience
        libs = []
        for lib in header.walkRelocatables():
            libs.append(lib[2])
        results["DyLinkedLibs"] = libs

        #get the imports/exports from the symbol table
        sym_cmd = header.getSymbolTableCommand() #get the symbol table load command from the header
        dyn_cmd = header.getDynamicSymbolTableCommand() #get the dynamic symbol table load command from the header
        (results["DefExtSymbols"], results["UndefExtSymbols"]) = self.parseSymbolTable(sym_cmd, dyn_cmd, file_object, header)


        return results

    def parseLoadCommands(self, commands):
        results = [] #list of all load commands to return
        sections = []

        # Each command is a tuple with 3 entries
        i = 0
        for cmd in commands: #list of load commands for one MachO header
            c = {}
            #the first entry is a load_command structure, made up of the command type and its size
            #get the human-readable command name
            cmd_name = data.LOAD_CMDS.get(cmd[0].cmd)
            #test for the high-bit LC_REQ_DYLD
            if cmd_name is None:
                s1 = data.LOAD_CMDS.get(cmd[0].cmd & 0xff000000) #check the high bit separately
                cmd_name = s1
                s2 = data.LOAD_CMDS.get(cmd[0].cmd & 0x00ffffff) #check the low bits
                cmd_name += ", " + s2
            c["cmd_name"] = cmd_name
            c["cmd_size"] = int(cmd[0].cmdsize)

            #the second entry in the tuple is the actual content of the command, which varies depending on the command
            # Since we can't predict the content without an excessively long switch statement, we just pull out
            # the structure attributes directly as a dict. It's not elegant but it works.
            c["cmd_content"] = cmd[1].__dict__["_objects_"]

            #sometimes some of the dict objects will create JSON errors
            for key in c["cmd_content"]:
                if isinstance(c["cmd_content"][key], bytes): #these strings are ASCII, and sometimes they don't play well with UTF-8
                    c["cmd_content"][key] = c["cmd_content"][key].decode('utf-8', 'ignore')
                if isinstance(c["cmd_content"][key], mach_version_helper): #these are Python objects JSON can't handle
                    c["cmd_content"][key] = c["cmd_content"][key].__dict__["_objects_"]


            # the third thing in the tuple is a string used by the command (usually a library/framework name)
            if "LC_SEGMENT" in c["cmd_name"]: #unless its a segment, then the sections need to be parsed
                #get human-readable memory flags for the segment
                if 'maxprot' in c["cmd_content"]:
                	c["cmd_content"]["maxprot"] = self.getMemProt(c["cmd_content"]["maxprot"])
                	c["cmd_content"]["initprot"] = self.getMemProt(c["cmd_content"]["initprot"])
                #parse the sections in the segment
                for sec in cmd[2]:
                    sec2 = sec.__dict__["_objects_"]

                    #parse the flags of sections into human-readable text
                    # There is a type flag and one or more attribute flags in the 4-byte field
                    sec2["flags"] = self.parseSectionFlags(sec2["flags"])

                    #add the section to the list
                    sections.append(sec.__dict__["_objects_"])
            else:
                c["strings"] = cmd[2]
                if isinstance(c["strings"], bytes): #these strings are ASCII, and sometimes they don't play well with UTF-8
                    c["strings"] = c["strings"].decode('utf-8', 'ignore')

            results.append(c) #add the command to the list
            i += 1


        return (results, sections)

    def getMemProt(self, flags):
        #check to see if it has a single dict value
        if not data.VM_PROT.get(flags) is None:
            return data.VM_PROT.get(flags)
        else:
            f = '' #string to hold the flags
            for i in range(0, 31): #flags are each one bit, so check each bit in 4 bytes
                mask = 1 << i
                flag = flags & mask
                if flag in data.VM_PROT and flag != 0:
                    if f != '':
                        f += ", "
                    f += data.VM_PROT.get(flag)
            return f

    def parseSectionFlags(self, flags):
        f = '' #variable to store all the flags in

        #get the type - stored in the lowest byte
        type = data.SECTION_TYPES.get(flags & 0x000000ff)
        if not type is None:
            f += type

        #get the user-settable attributes - highest byte
        a1 = data.SECTION_ATTR.get(flags & 0xff000000)
        if not a1 is None:
            f += ", " + a1

        #get the system-settable attributes - middle two bytes
        a2 = data.SECTION_ATTR.get(flags & 0x00ffff00)
        if not a2 is None:
            f += ", " + a2

        return f


    def parseSymbolTable(self, sym_cmd, dyn_cmd, file_object, header):
        if dyn_cmd is None or sym_cmd is None:
            return
        try:
            offset = header.offset
            endian = header.endian
            # The symbol table is actually made up of several partitions. These partitions and their offsets
            # are listed in the LC_DYSYMTAB load command.
            symbols = []
            # the human-readable string of the symbol table are actually stored in the strings table, so get those
            #go to the beginning of the strings table, offset from the beginning of the Mach-O object
            file_object.seek(0)
            file_object.seek(sym_cmd.stroff+offset)
            #file_object.seek(sym_cmd.stroff, offset) #for some reason this throws an IOError
            strs = file_object.read(sym_cmd.strsize) #read in the entire string table
            #each string is null (00) terminated, so you can split on that
            # however the indexes to the string table are byte offsets, so this is not necessary really
            # strings = strs.split('\x00')

            # go to the beginning of the symbol table
            file_object.seek(0)
            file_object.seek(sym_cmd.symoff+offset)
            undef = [] #undefined external symbols
            defined = [] #defined external symbols
            #seek to the beginning index of the defined external symbols
            for i in range(dyn_cmd.iextdefsym):
                file_object.read(12)
                #if this is a 64-bit object file, there will be an extra 4 blank bytes
                if isinstance(header.header, mach_header_64):
                    file_object.read(4)

            #read the number of defined external symbols specified in LC_DYSYMTAB
            for i in range(dyn_cmd.nextdefsym):
                # get the index to the strings table - this is 4 bytes long
                t = file_object.read(4)
                # the endian of the Mach-O object is in the header
                index = struct.unpack(endian+'L', t)[0]
                #indirect.append(''.join('%02x' % ord(byte) for byte in t))
                file_object.read(8) #skip the rest of the symbol table entry - 8 bytes total
                #if this is a 64-bit object file, there will be an extra 4 blank bytes
                if isinstance(header.header, mach_header_64):
                    file_object.read(4)

                if index == 0: # a null string has an index of 0
                    defined.append('NULL')
                else: #get the human-readable string at the index
                    str = ''
                    b = strs[index]
                    i = 0
                    while (b != b'\x00'):
                        str = str + b
                        i += 1
                        b = strs[index+i]
                    defined.append(str)

            #read the number of undefined external symbols specified in LC_DYSYMTAB
            for i in range(dyn_cmd.nundefsym):
                # get the index to the strings table - this is 4 bytes long
                t = file_object.read(4)
                # the endian of the Mach-O object is in the header
                index = struct.unpack(endian+'L', t)[0]
                #indirect.append(''.join('%02x' % ord(byte) for byte in t))
                file_object.read(8) #skip the rest of the symbol table entry - 8 bytes total
                #if this is a 64-bit object file, there will be an extra 4 blank bytes
                if isinstance(header.header, mach_header_64):
                    file_object.read(4)

                if index == 0: # a null string has an index of 0
                    undef.append('NULL')
                else: #get the human-readable string at the index
                    str = ''
                    b = strs[index]
                    i = 0
                    while (b != b'\x00'):
                        str = str + b
                        i += 1
                        b = strs[index+i]
                    undef.append(str)
        except:
            defined = "Error: malformed symbol table"
            undef = []

        return (defined, undef)

    def getFlags(self, flags):
        f = '' #string to hold the flags
        for i in range(0, 31): #flags are each one bit, so check each bit in 4 bytes
            mask = 1 << i
            flag = flags & mask
            if flag in data.MACHO_FLAGS:
                if f != '':
                    f += ", "
                f += data.MACHO_FLAGS.get(flag)
        return f

    def parseFATHeader(self, f, pFile):
        results = {}
        #If this is a FAT file, it will have an extra header
        if not (pFile.fat is None):

            #insert the main FAT header fields
            results["Magic"] = pFile.fat.magic
            results["n_arch"] = pFile.fat.nfat_arch

            #seek past the first couple FAT header fields (2 fields, 4 bytes each)
            f.seek(8)
            #parse the sub-file object structures (fat_arch structures)
            archs = [fat_arch.from_fileobj(f) for i in range(pFile.fat.nfat_arch)]
            a_results = {}
            for a in archs:
                ar = {}
                #get human-readable names
                cpu_type = CPU_TYPE_NAMES.get(a.cputype, a.cputype)
                cpu_stype = self.getCPUSubtype(cpu_type, a.cpusubtype)

                ar["cpu_subtype"] = cpu_stype
                ar["offset"] = a.offset
                ar["size"] = a.size
                ar["alignment"] = a.align
                a_results[cpu_type] = ar

                # carve out file
                self.sub_files.append(self.file_object[a.offset:a.offset+a.size])

            results["archs"] = a_results

        return results

    '''Get the human-readable cpu subtype.
    This is a bit complicate because there seems to be no defined mapping for cpu_type to cpu_subtype, so I had to guess for some.
    ctype = human-readable cpu_type
    stype = cpu_subtype '''
    def getCPUSubtype(self, ctype, stype):
        if 'ARM64' in ctype:
            return data.CPU_SUBTYPE_ARM.get(stype)
        elif 'ARM' in ctype:
            return data.CPU_SUBTYPE_ARM.get(stype)
        elif 'HPPA' in ctype:
            return data.CPU_SUBTYPE_HPPA.get(stype)
        elif 'i860' in ctype:
            return data.CPU_SUBTYPE_I860.get(stype)
        elif 'i386' in ctype:
            return data.CPU_SUBTYPE_I386.get(stype)
        elif 'MC68' in ctype:
            return data.CPU_SUBTYPE_MC680x0.get(stype)
        elif 'MC88' in ctype:
            return data.CPU_SUBTYPE_MC88000.get(stype)
        elif 'MC98' in ctype:
            return data.CPU_SUBTYPE_MC98000.get(stype)
        elif 'MIPS' in ctype:
            return data.CPU_SUBTYPE_MIPS.get(stype)
        elif 'PowerPC' in ctype:
            return data.CPU_SUBTYPE_POWERPC.get(stype)
        elif 'SPARC' in ctype:
            return data.CPU_SUBTYPE_SPARC.get(stype)
        elif 'VAX' in ctype:
            return data.CPU_SUBTYPE_VAX.get(stype)
        elif 'x86_64' in ctype:
            return data.CPU_SUBTYPE_X86_64.get(stype)
        elif 'x86' in ctype:
            return data.CPU_SUBTYPE_X86.get(stype)
        elif 'high' in ctype:
            data.CPU_SUBTYPE_HIGH.get(stype)
        else:
            return data.CPU_SUBTYPE_ANY.get(stype)
