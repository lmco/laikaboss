#!/usr/bin/env python
# Copyright 2020 National Technology & Engineering Solutions of Sandia, LLC 
# (NTESS). Under the terms of Contract DE-NA0003525 with NTESS, the U.S. 
# Government retains certain rights in this software.
#
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
This file contains the dictionary structures for whatever human-readable parsing we need that wasn't done by macholib.
"""

### CPU SUBTYPES ###

CPU_SUBTYPE_ANY = {
    -1:     'MULTIPLE',
    0:      'LITTLE_ENDIAN',
    1:      'BIG_ENDIAN',
}

CPU_SUBTYPE_HIGH = {
    2147483648: 'LIB64',
    4278190080: 'MASK',
}

CPU_SUBTYPE_ARM = {
    0:     'ARM_ALL',
    5:     'ARM_V4T',
    6:     'ARM_v6',
    7:     'ARM_V5TEJ',
    9:     'ARM_V7',
    8:     'ARM_XSCALE',
}

CPU_SUBTYPE_HPPA = {
    0:     'HPPA_7100 OR HPPA_ALL',
    1:     'HPPA_7100LC',
}

CPU_SUBTYPE_I860 = {
    0:     'I860_ALL',
    1:     'I860_860',
}

CPU_SUBTYPE_I386 = {
    3:     'I386_ALL',
    5:     'PENT',
    8:     'PENTIUM_3',
    9:     'PENTIUM_M',
    10:    'PENTIUM_4',
    24:    'PENTIUM_3_M',
    22:    'PENTPRO',
    26:    'PENTIUM_4_M',
    40:    'PENTIUM_3_XEON',
    54:    'PENTII_M3',
    86:    'PENTII_M5',
    3:      '386',
    4:      '486',
    5:      '586',
    11:     'ITANIUM',
    12:     'XEON',
    15:     'INTEL_FAMILY_MAX',
    27:     'ITANIUM_2',
    28:     'XEON_MP',
    103:    'CELERON',
    119:    'CELERON_MOBILE',
}

CPU_SUBTYPE_MC680x0 = {
    1:     'MC680x0_ALL',
    2:     'MC68040',
    3:     'MC68030_ONLY',
}

CPU_SUBTYPE_MC88000 = {
    0:     'MC88000_ALL',
    1:     'MC88100',
    2:     'MC88110',

}

CPU_SUBTYPE_MIPS = {
    0:     'MIPS_ALL',
    1:     'MIPS_R2300',
    2:     'MIPS_R2600',
    3:     'MIPS_R2800',
    4:     'MIPS_R2000a',
    5:     'MIPS_R2000',
    6:     'MIPS_R3000a',
    7:     'MIPS_R3000',
}

CPU_SUBTYPE_MC98000 = {
    0:     'MC98000_ALL',
    1:     'MC98601',
}

CPU_SUBTYPE_POWERPC = {
    0:     'POWERPC_ALL',
    1:     'POWERPC_601',
    2:     'POWERPC_602',
    3:     'POWERPC_603',
    4:     'POWERPC_603e',
    5:     'POWERPC_603ev',
    6:     'POWERPC_604',
    7:     'POWERPC_604e',
    8:     'POWERPC_620',
    9:     'POWERPC_750',
    10:    'POWERPC_7400',
    11:    'POWERPC_7450',
    100:   'POWERPC_970',
}

CPU_SUBTYPE_SPARC = {
    0:     'SPARC_ALL',
}

CPU_SUBTYPE_VAX = {
    0:     'VAX_ALL',
    1:     'VAX780',
    2:     'VAX785',
    3:     'VAX750',
    4:     'VAX730',
    5:     'UVAXI',
    6:     'UVAXII',
    7:     'VAX8200',
    8:     'VAX8500',
    9:     'VAX8600',
    10:    'VAX8650',
    11:    'VAX8800',
    12:    'UVAXIII',
}

CPU_SUBTYPE_X86 = {
    3:     'X86_ALL',
    4:     'X86_ARCH1',
}

CPU_SUBTYPE_X86_64 = {
    3:     'X86_64_ALL',
}

### File Types ###

FILE_TYPE = {
    1:     'MH_OBJECT', #relocatable object file
    2:     'MH_EXECUTE', #demand page executable file
    3:     'MH_FVMLIB', #fixed VM shared library file
    4:     'MH_CORE', #core file
    5:     'MH_PRELOAD', #preloaded executable file
    6:     'MH_DYLIB', #dynamically bound shared library
    7:     'MH_DYLINKER', #dynamic link editor
    8:     'MH_BUNDLE', #dynamically bound bundle file
    9:     'MH_DYLIB_STUB', #shared library stub for static linking only
    10:    'MH_DSYM', #companion file with only debug sections
    11:    'MH_KTEXT_BUNDLE', #x86_64 ktexts
}

### Mach-O Header Flags ###

MACHO_FLAGS = {
    0x1:    'MH_NOUNDEFS', #the object file has no undefined references
    0x2:    'MH_INCRLINK', # the object file is the output of an incremental link against a base file
    0x4:    'MH_DYLDLINK',  # the object file is input for the dynamic linker
    0x8:    'MH_BINDATLOAD', # the object file's undefined references are bound by the dynamic linker when loaded.
    0x10:   'MH_PREBOUND', # the file has its dynamic undefined references prebound.
    0x20:   'MH_SPLIT_SEGS', # the file has its read-only and read-write segments split
    0x40:   'MH_LAZY_INIT', #the shared library init routine is to be run lazily via catching memory faults to its writeable segments (obsolete)
    0x80:   'MH_TWOLEVEL', # the image is using two-level name space bindings
    0x100:  'MH_FORCE_FLAT', # the executable is forcing all images to use flat name space bindings
    0x200:  'MH_NOMULTIDEFS', #this umbrella guarantees no multiple defintions of symbols in its sub-images
    0x400:  'MH_NOFIXPREBINDING', # do not have dyld notify the prebinding agent about this executable
    0x800:  'MH_PREBINDABLE', #the binary is not prebound but can have its prebinding redone. only used  when MH_PREBOUND is not set.
    0x1000: 'MH_ALLMODSBOUND', # indicates that this binary binds to all two-level namespace modules of its dependent libraries. only used when MH_PREBINDABLE and MH_TWOLEVEL are both set.
    0x2000: 'MH_SUBSECTIONS_VIA_SYMBOLS', # safe to divide up the sections into sub-sections via symbols for dead code stripping
    0x4000: 'MH_CANONICAL', # the binary has been canonicalized via the unprebind operation
    0x8000: 'MH_WEAK_DEFINES', # the final linked image contains external weak symbols
    0x10000: 'MH_BINDS_TO_WEAK', # the final linked image uses weak symbols
    0x20000: 'MH_ALLOW_STACK_EXECUTION', # When this bit is set, all stacks in the task will be given stack execution privilege.  Only used in MH_EXECUTE filetypes.
    0x40000: 'MH_ROOT_SAFE', #When this bit is set, the binary declares it is safe for use in processes with uid zero
    0x80000: 'MH_SETUID_SAFE', # When this bit is set, the binary declares it is safe for use in processes when issetugid() is true
    0x100000: 'MH_NO_REEXPORTED_DYLIBS', # When this bit is set on a dylib, the static linker does not need to examine dependent dylibs to see if any are re-exported
    0x200000: 'MH_PIE', #When this bit is set, the OS will load the main executable at a random address.  Only used in MH_EXECUTE filetypes.
    0x400000: 'MH_DEAD_STRIPPABLE_DYLIB', #Only for use on dylibs.  When linking against a dylib that has this bit set, the static linker will automatically not create a
                         # LC_LOAD_DYLIB load command to the dylib if no symbols are being referenced from the dylib.
    0x800000: 'MH_HAS_TLV_DESCRIPTORS', # Contains a section of type S_THREAD_LOCAL_VARIABLES
    0x1000000: 'MH_NO_HEAP_EXECUTION', # When this bit is set, the OS will run the main executable with a non-executable heap even on
                       # platforms (e.g. i386) that don't require it. Only used in MH_EXECUTE filetypes.
}

### Mach-O Load Commands ###

LOAD_CMDS = {
    # After MacOS X 10.1 when a new load command is added that is required to be
    # understood by the dynamic linker for the image to execute properly the
    # LC_REQ_DYLD bit will be or'ed into the load command constant.
    0x80000000:  'LC_REQ_DYLD ',

    0x1:    'LC_SEGMENT', # segment of this file to be mapped
    0x2:    'LC_SYMTAB', # link-edit stab symbol table info
    0x3:    'LC_SYMSEG', # link-edit gdb symbol table info (obsolete)
    0x4:    'LC_THREAD', # thread
    0x5:    'LC_UNIXTHREAD', # unix thread (includes a stack), replaced by LC_MAIN for OS X 10.8+
    0x6:    'LC_LOADFVMLIB', # load a specified fixed VM shared library
    0x7:    'LC_IDFVMLIB', # fixed VM shared library identification
    0x8:    'LC_IDENT', # object identification info (obsolete)
    0x9:    'LC_FVMFILE', # fixed VM file inclusion (internal use)
    0xA:    'LC_PREPAGE', # prepage command (internal use)
    0xB:    'LC_DYSYMTAB',# dynamic link-edit symbol table info
    0xC:    'LC_LOAD_DYLIB', #load a dynamically linked shared library
    0xD:    'LC_ID_DYLIB', # dynamically linked shared library identification
    0xE:    'LC_LOAD_DYLINKER', # load a dynamic linker
    0xF:    'LC_ID_DYLINKER', # dynamic linker identification
    0x10:   'LC_PREBOUND_DYLIB', # modules prebound for a dynamically linked shared library
    0x11:   'LC_ROUTINES', # image routines
    0x12:   'LC_SUB_FRAMEWORK', # sub framework
    0x13:   'LC_SUB_UMBRELLA', # sub umbrella
    0x14:   'LC_SUB_CLIENT', # sub client
    0x15:   'LC_SUB_LIBRARY', # sub library
    0x16:   'LC_TWOLEVEL_HINTS', # two-level namespace lookup hints
    0x17:   'LC_PREBIND_CKSUM', # prebind checksum
    0x18:   'LC_LOAD_WEAK_DYLIB',
    0x19:   'LC_SEGMENT_64', #64-bit segment of this file to be mapped
    0x1a:   'LC_ROUTINES_64', # 64-bit image routines
    0x1b:   'LC_UUID', # the uuid
    0x1c:   'LC_RPATH', # runpath additions
    0x1d:   'LC_CODE_SIGNATURE', # location of code signature
    0x1e:   'LC_SEGMENT_SPLIT_INFO', # location of info to split segments
    0x1f:   'LC_REEXPORT_DYLIB', # load and re-export dylib
    0x20:   'LC_LAZY_LOAD_DYLIB', # delay load of dylib until first use
    0x21:   'LC_ENCRYPTION_INFO', # encrypted segment information
    0x22:   'LC_DYLD_INFO', # compressed dyld information
    0x80000022: 'LC_DYLD_INFO_ONLY', # (0x22|LC_REQ_DYLD) - compressed dyld information only
    0x23:   'LC_LOAD_UPWARD_DYLIB', # load upward dylib
    0x24:   'LC_VERSION_MIN_MACOSX', # build for MacOSX min OS version
    0x25:   'LC_VERSION_MIN_IPHONEOS', # build for iPhoneOS min OS version
    0x26:   'LC_FUNCTION_STARTS', # compressed table of function start addresses
    0x27:   'LC_DYLD_ENVIRONMENT', # string for dyld to treat like environment variable
    0x28:   'LC_MAIN', # replacement for LC_UNIXTHREAD
    0x29:   'LC_DATA_IN_CODE', # table of non-instructions in __text
    0x2a:   'LC_SOURCE_VERSION', # source version used to build binary
    0x2b:   'LC_DYLIB_CODE_SIGN_DRS', # Code signing DRs copied from linked dylibs
    0x2c:   'LC_ENCRYPTION_INFO_64', # 64-bit encrypted segment information
    0x2d:   'LC_LINKER_OPTION', #linker options in MH_OBJECT files
}

### Section Flags ###

SECTION_TYPES = { #the lowest byte - note each section has only one type
    0x0:    'S_REGULAR', # regular section
    0x1:    'S_ZEROFILL', # zero fill on demand section
    0x2:    'S_CSTRING_LITERALS', # section with only literal C strings
    0x3:    'S_4BYTE_LITERALS', # section with only 4 byte literals
    0x4:    'S_8BYTE_LITERALS', # section with only 8 byte literals
    0x5:    'S_LITERAL_POINTERS', # section with only pointers to literals
    0x6:    'S_NON_LAZY_SYMBOL_POINTERS', # section with only non-lazy symbol pointers
    0x7:    'S_LAZY_SYMBOL_POINTERS', # section with only lazy symbol pointers
    0x8:    'S_SYMBOL_STUBS', # section with only symbol stubs, byte size of stub in the reserved2 field
    0x9:    'S_MOD_INIT_FUNC_POINTERS', #section with only function pointers for initialization
    0xa:    'S_MOD_TERM_FUNC_POINTERS', # section with only function pointers for termination
    0xb:    'S_COALESCED', # section contains symbols that are to be coalesced
    0xc:    'S_GB_ZEROFILL', # zero fill on demand section (that can be larger than 4 gigabytes)
    0xd:    'S_INTERPOSING', # section with only pairs of function pointers for interposing
    0xe:    'S_16BYTE_LITERALS', # section with only 16 byte literals
    0xf:    'S_DTRACE_DOF', # section contains DTrace Object Format
    0x10:   'S_LAZY_DYLIB_SYMBOL_POINTERS', # section with only lazy symbol pointers to lazy loaded dylibs
    #types for thread local variables (TLVs)
    0x11:   'S_THREAD_LOCAL_REGULAR', # template of initial values for TLVs
    0x12:   'S_THREAD_LOCAL_ZEROFILL', # template of initial values for TLVs
    0x13:   'S_THREAD_LOCAL_VARIABLES', # TLV descriptors
    0x14:   'S_THREAD_LOCAL_VARIABLE_POINTERS', # pointers to TLV descriptors
    0x15:   'S_THREAD_LOCAL_INIT_FUNCTION_POINTERS', # functions to call to initialize TLV values
}

SECTION_ATTR = { #a section can have multiple attributes - high 3 bytes
    #User-settable attributes -  first byte
    0x80000000:  'S_ATTR_PURE_INSTRUCTIONS', # section contains only true machine instructions
    0x40000000:  'S_ATTR_NO_TOC', # section contains coalesced symbols that are not to be in a ranlib table of contents
    0x20000000:  'S_ATTR_STRIP_STATIC_SYMS', # ok to strip static symbols in this section in files with the MH_DYLDLINK flag
    0x10000000:  'S_ATTR_NO_DEAD_STRIP', # no dead stripping
    0x08000000:  'S_ATTR_LIVE_SUPPORT', # blocks are live if they reference live blocks
    0x04000000:  'S_ATTR_SELF_MODIFYING_CODE', # Used with i386 code stubs written on by dyld
    0x02000000:  'S_ATTR_DEBUG', # a debug section
    #System-settable attributes - next two bytes
    0x00000400:  'S_ATTR_SOME_INSTRUCTIONS', # section contains some machine instructions
    0x00000200:  'S_ATTR_EXT_RELOC', # section has external relocation entries
    0x00000100:  'S_ATTR_LOC_RELOC', # section has local relocation entries
}

### Virtual Memory Protection Flags - see mach/vm_prot.h ###

VM_PROT = {
    0x00:        'VM_PROT_NONE',
    0x01:        'VM_PROT_READ', #read permission
    0x02:        'VM_PROT_WRITE', #write permission
    0x04:        'VM_PROT_EXECUTE', #execute permission
    0x08:        'VM_PROT_NO_CHANGE', #technically invalid, only used by memory_object_lock_request
    0x10:        'VM_PROT_COPY', #when the caller cannot obtain write permission, this can be used to make a working copy
    0x10:        'VM_PROT_WANTS_COPY', #only used by memory_object_data_request

    (0x01 | 0x02):  'VM_PROT_DEFAULT (rw)', #read and write permissions, the default for new virtual memory
    (0x01 | 0x02 | 0x04):   'VM_PROT_ALL (rwe)', #max possible permissions, used for parameter checking
}
