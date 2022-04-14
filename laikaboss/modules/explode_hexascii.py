#!/usr/bin/env python
# Copyright 2020 National Technology & Engineering Solutions of Sandia, LLC 
# (NTESS). Under the terms of Contract DE-NA0003525 with NTESS, the U.S. 
# Government retains certain rights in this software.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""
This module looks for hex that may be encoded ASCII characters and decodes them as a new object.
Takes args: min_size, max_size
"""
from __future__ import division

# Python library imports
from builtins import bytes
import logging
import struct
import binascii

# 3rd party Python libraries
try:
    import re2 as re
    has_re2 = True
except ImportError:
    import re
    has_re2 = False


# LaikaBoss imports
import laikaboss
import laikaboss.si_module
import laikaboss.util

_module_requires = ['re2']


class EXPLODE_HEXASCII(laikaboss.si_module.SI_MODULE):

    # the regexes to detect hex-encoded ASCII
    plain_hex_regex = b"[0-9a-fA-F]{%d}(?:[0-9a-fA-F]{2}\s*){0,%d}\\b" 
    ole_hex_regex = b"(?:&H[0-9a-fA-F]{1,2}\s?,\s?){%d,%d}&H[0-9a-fA-F]{1,2}\s?\)"
    ascii_regex = b"(?:[0-7][0-9a-fA-F]){20}(?:(?:[0-7][0-9a-fA-F]){2})*"

    min_size = 50
    max_size = 4000

    def __init__(self):
        self.module_name = "EXPLODE_HEXASCII"
        if not has_re2:
            logging.warning("The re2 Python library is not installed, there may be a decrease in performance.")

        # compile regexes
        self.plainhexfind = re.compile(self.plain_hex_regex % (self.min_size, (self.max_size - self.min_size)//2))
        self.olehexfind = re.compile(self.ole_hex_regex % (self.min_size//2, self.max_size//2))


    def _run(self, scanObject, result, depth, args):
        result = []

        # limit the number of child objects we pull out to avoid filling the filesystem
        # this is why we can't have nice things
        limit = int(laikaboss.util.get_option(args, 'max_obj_num', 'max_obj_num', 100))
        num_objs = 0
        hit_limit = False
        hit_byte_limit = False

        # min and max size for hex blobs (max is across all blobs)
        tmp_min_size = laikaboss.util.get_option(args, 'min_size', 'ha_min_size', 50)
        tmp_max_size = laikaboss.util.get_option(args, 'max_total_size', 'ha_max_total_size', 400000)

        # adjust the size via args if necessary - can't do this in init because args aren't present then
        if tmp_max_size != self.max_size or tmp_min_size != self.min_size:
            self.max_size = tmp_max_size
            self.min_size = tmp_min_size
            logging.debug("Using min size of %d and max size of %d for blobs" % (self.min_size, self.max_size))
            self.plainhexfind = re.compile(self.plain_hex_regex % (self.min_size, (self.max_size - self.min_size)//2))
            self.olehexfind = re.compile(self.ole_hex_regex % (self.min_size//2, self.max_size//2))

        # find any normal hex matches and make them new objects
        exploded_characters = 0
        for m in self.plainhexfind.finditer(scanObject.buffer):
            if num_objs > limit:
                hit_limit = True
                break
            if exploded_characters >= self.max_size:
                hit_byte_limit = True
                break
            num_objs += 1

            offset = m.start()
            data = m.group()
            data = b''.join(data.split()) # strip whitespace
            if len(data) > self.max_size - exploded_characters:
                data = data[:self.max_size - exploded_characters]
            exploded_characters += len(data)
            byte_string = self._string_to_bytes(data.lower())
            result.append(laikaboss.objectmodel.ModuleObject(buffer=byte_string, 
                    externalVars=laikaboss.objectmodel.ExternalVars(filename="ascii_hex_bytes_at_%d" % offset, contentType=None)))

        # search for OLE hex arrays
        for m in self.olehexfind.finditer(scanObject.buffer):
            if num_objs > limit:
                hit_limit = True
                break
            if exploded_characters >= self.max_size:
                hit_byte_limit = True
                break
            num_objs += 1

            offset = m.start()
            data = m.group()
            hex_string = self._ole_deobfuscator(data)
            if len(hex_string) > self.max_size - exploded_characters:
                hex_string = hex_string[:self.max_size - exploded_characters]
            exploded_characters += len(data)
            byte_string = self._string_to_bytes(hex_string.lower())
            result.append(laikaboss.objectmodel.ModuleObject(buffer=byte_string, 
                    externalVars=laikaboss.objectmodel.ExternalVars(filename="ascii_hex_bytes_at_%d" % offset, contentType=None)))
    

        if hit_limit:
            scanObject.addFlag('%s:%s' % ('hexascii', "NUMBER_OF_CHILD_OBJECTS_OVER_LIMIT"))
        if hit_byte_limit:
            scanObject.addFlag('hexascii:BYTE_LIMIT_EXCEEDED')

        return result

    """
    Convert a hex string to bytes
    :param s: the hex string
    :return: the byte buffer
    """
    @staticmethod
    def _string_to_bytes(s):
        try:
            byte_array = binascii.unhexlify(s)
        except: # invalid hex string
            logging.error("Unable to convert hex string to bytes, invalid format: %s" %s)
            return bytes()

        return byte_array

    """
    Turn an OLE hex array into a proper hex string.
    :param s: the string representing the array
    :return: a hex string
    """
    @staticmethod
    def _ole_deobfuscator(s):
        s = re.sub(b"&H", b" ", s)
        s = re.sub(b"\s?,\s?", b"", s)
        s = re.sub(b"\s?,", b"", s)
        s = re.sub(b"\)", b"", s)
        s_nums = s.split()
        final_string = b""
        for s in s_nums:
            if len(s) == 0:
                continue
            elif len(s) < 2:
                final_string += "0" + s
            else:
                final_string += s
        #logging.error(final_string)
        return final_string

