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
This is a helper class for parsing TIFF files,
It requires the libtiff5-dev Ubuntu package and the libtiff and numpy pip packages.
These packages are checked in the meta_tiff.py module before this class is called.
"""
from __future__ import print_function

# Python imports
import libtiff

class CustomTiffFile(libtiff.TIFFfile):

    def get_strips(self):
        l = []
        l.extend(self.memory_usage)
        for ifd in self.IFD:
            l.extend(ifd.memory_usage)
        l.sort()
        return l

    def get_eof_strip(self):
        l = []
        l.extend(self.memory_usage)
        for ifd in self.IFD:
            l.extend(ifd.memory_usage)
        l.sort()
        # for (start_of_strip, end_of_strip, type)
        # example: (1132790, 1132790, 'eof')
        # note that a and b  should be the same and the last one is always eof
        eof_strip = [[a, b, c] for a, b, c in l if c.lower() == 'eof']

        return eof_strip[0]

    def get_biggest_strip(self):
        l = []
        l.extend(self.memory_usage)
        for ifd in self.IFD:
            l.extend(ifd.memory_usage)
        l.sort()
        return l[-1]

    def get_unknown_sections(self, threshold=100):
        ''' Get unknown sections between strips '''
        l = []
        unknown_sections = []

        l.extend(self.memory_usage)
        for ifd in self.IFD:
            l.extend(ifd.memory_usage)
        l.sort()
        last_end = None
        for start, end, resource in l:
            if last_end:
                if last_end != start and start > last_end and (start - last_end) > threshold:
                    unknown_sections.append(
                        dict(start=last_end, size=(start - last_end)))
            last_end = end
        return unknown_sections

    def get_memory_overlap(self, threshold=0):
        ''' Get memory sections that are overlapping '''
        l = []
        overlapping_sections = []
        l.extend(self.memory_usage)
        for ifd in self.IFD:
            l.extend(ifd.memory_usage)
        l.sort()
        last_end = None
        last_start = None
        for start, end, resource in l:
            if last_end and last_end != start:
                if last_end > start and (last_end - end) > threshold:
                    overlapping_sections.append(
                        dict(last_start=last_start,
                             last_end=last_end,
                             start=start,
                             end=end
                             )
                    )

            last_end = end
            last_start = start
        return overlapping_sections

    def check_memory_overlap_and_unknown(self, verbose=True):
        ''' Check memory overlapping of TIFF fields and blocks. '''

        l = []
        l.extend(self.memory_usage)
        for ifd in self.IFD:
            l.extend(ifd.memory_usage)
        l.sort()
        last_end = None
        last_start = None
        ok = True
        for start, end, resource in l:
            err_type = None
            if last_end:
                if last_end != start:
                    if start > last_end:
                        if verbose:
                            print('--- unknown %s bytes' % (start - last_end))
                        err_type = 'skip'
                    ok = False
                    if start < last_end:
                        if verbose:
                            print('--- overlapping memory area')
                        err_type = 'overlap'
                    if verbose:
                        print("{'type' : '%s', " % err_type, end=' ')
                        print("'last_start': '%s', " % last_start, end=' ')
                        print("'last_end': '%s', " % last_end, end=' ')
                        print("'start': '%s', " % start, "'end': '%s'}" % end)

                    if err_type not in ['skip', 'overlap']:
                        raise Exception("Unknown error type")
            last_end = end
            last_start = start

        if ok is True and verbose:
            print("ok")
        return ok
