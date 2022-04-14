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
This module parses TIFF files/

Requires: libtiff5-dev Ubuntu package
"""

# Python library imports
from builtins import str
import os
import io
import tempfile
import logging

# 3rd-party Python libraries
try:
    import libtiff
    import numpy
    has_libtiff = True
except:
    has_libtiff = False


# LaikaBoss imports
import laikaboss
import laikaboss.si_module
import laikaboss.extras.tiff_util
from laikaboss.util import laika_temp_dir

_module_requires = ['libtiff', 'numpy'] #libtiff requires numpy

class META_TIFF(laikaboss.si_module.SI_MODULE):

    def __init__(self):
        self.module_name = "META_TIFF"

    def _run(self, scanObject, result, depth, args):
        result = []

        if has_libtiff:
            with laika_temp_dir() as tempdir, tempfile.NamedTemporaryFile(dir=tempdir) as fp:
                tif = self._get_tiff(scanObject, fp)

                if tif is None: # parsing error
                    scanObject.addFlag('%s:%s' % ('tiff', "PARSING_FAIL"))
                    return result

                # check if the strips are contiguous
                try:
                    if not tif.is_contiguous(): #unsure of why this is here
                        children = self._parse_tiff_contents(fp.name, tif, scanObject)
                    else:
                        children = self._parse_tiff_contents(fp.name, tif, scanObject)
                    for obj in children:
                        if isinstance(obj, str):
                            obj = obj.encode('utf-8', 'replace')
                        result.append(laikaboss.objectmodel.ModuleObject(buffer=obj, 
                    externalVars=laikaboss.objectmodel.ExternalVars(filename=scanObject.filename + "_subfile", contentType="text")))
                except Exception as e:
                    logging.exception("Unable to parse TIFF file, %s" % [str(e)])

        else:
            logging.warning("TIFF module disabled - libtiff is not installed")

        return result

    """
    Create and sanity check the TIFF object.
    :param scanObject: object to parse
    :param fp: file object of opened temporary file
    :return: the tif file object
    """
    @staticmethod
    def _get_tiff(scanObject, fp):
        tif = None
        content_file = io.BytesIO(scanObject.buffer)

        # save the data to a tmp file
        fp.write(content_file.read())
        fp.flush()

        # open tmp file to read
        try:
            tif = laikaboss.extras.tiff_util.CustomTiffFile(fp.name)
        except Exception as e:
            # cannot load a tiff
            logging.warning("Unable to parse TIFF file, %s" % [str(e)])

        return tif

    """
    Adds metadata for the TIFF file.
    :param name: name of the temporary TIFF file
    :param tif: TIFF object
    :param scanObject: LaikaBoss scan object
    :return: A list of any child files
    """
    @staticmethod
    def _parse_tiff_contents(name, tif, scanObject):
        metadata = tif.IFD[0].entries_dict
        for tag in metadata:
            try:
                if type(metadata[tag].value) == numpy.memmap:
                    if 'Name' in tag or 'Description' in tag:
                        value = metadata[tag].value.tostring()
                    else:
                        value = str(metadata[tag].value)
                else:
                    value= metadata[tag].value
            except: #malformed tag
                value = None
                scanObject.addFlag('%s:%s' % ('tiff', "MALFORMED_IFD_ENTRY"))
            scanObject.addMetadata("META_TIFF", tag, value)

        children = []
        unknown_bytes_size_thresh = 10
        overlapping_bytes_size_thresh = 40

        # file stats
        file_stat_info = os.stat(name)
        
        # get some basic information from the image
        eof_strip = tif.get_eof_strip()

        # get biggest strip
        max_strip = tif.get_biggest_strip()

        # get all unknown strips
        unknown_strips = tif.get_unknown_sections(unknown_bytes_size_thresh)

        # get all overlapping strips
        overlapping_strips = tif.get_memory_overlap(overlapping_bytes_size_thresh)

        # Make sure the eof is not somewhere else in the image but
        # at the end of the image
        if eof_strip[1] != file_stat_info.st_size:
            scanObject.addFlag('%s:%s' % ('tiff', "CORRUPTED"))

        # Make sure the biggest strip is the eof
        if eof_strip[1] != max_strip[1] and max_strip[1] <= file_stat_info.st_size:
            scanObject.addFlag('%s:%s' % ('tiff', "MISSING_EOF"))

        elif eof_strip[1] != max_strip[1] and max_strip[1] > file_stat_info.st_size:
            scanObject.addFlag('%s:%s' % ('tiff',"EXTRA_STRIPS"))

        for entry in overlapping_strips:
            if entry['last_start'] > entry['last_end']:
                scanObject.addFlag('%s:%s' % ('tiff', "CORRUPTED"))
                return children

            if entry['start'] > entry['end']:
                scanObject.addFlag('%s:%s' % ('tiff', "CORRUPTED"))
                return children

            if entry['last_start'] > eof_strip[1] or entry['last_end'] > eof_strip[1]:
                scanObject.addFlag('%s:%s' % ('tiff', "STRIP_OUT_OF_BOUNDS"))

            if entry['start'] > eof_strip[1] or entry['end'] > eof_strip[1]:
                scanObject.addFlag('%s:%s' % ('tiff', "STRIP_OUT_OF_BOUNDS"))

            # check how many bytes the last strip if over lapping the new one.
            ol_bytes = entry['last_end'] - entry['start']
            if ol_bytes > 0:
                last_strip_size = entry['last_end'] - entry['last_start']
                strip_size = entry['end'] - entry['start']
                if last_strip_size > 0:
                    byte_data = None
                    byte_data = META_TIFF._read_file_bytes(scanObject.buffer, entry['last_start'], last_strip_size)
                    if byte_data:
                        pass # TODO: should we process this?
                if strip_size > 0:
                    byte_data = None
                    byte_dat = META_TIFF._read_file_bytes(scanObject.buffer, entry['start'], strip_size)
                    if byte_data:
                        pass # TODO should we process this??

        strip_counter = 0
        for strip in unknown_strips:
            # extract bytes chunk from the file
            byte_data = None
            if strip['size'] > 0:
                byte_data = META_TIFF._read_file_bytes(scanObject.buffer, strip['start'], strip['size'])

                # base on the mime send it to other process.
                if byte_data and len(byte_data.strip("\x00")) > 0:
                    children.append(byte_daa)
            strip_counter += 1

        return children


    """
    Read a block of bytes from file and return the bytes
    :param name: name of the temporary TIFF file
    :param tif: TIFF object
    :return: block of bytes or None if the request is invalid
    """
    @staticmethod
    def _read_file_bytes(file, start, bsize):
        
        if start > len(file):
            logging.error("TIFF: Unable to extract file chink, start (%d) is greater than filesize (%d)" %[start, len(file.contents)])
            return None
        
        return file[start:start+bsize]

