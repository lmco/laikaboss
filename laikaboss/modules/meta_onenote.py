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
# Module parse metadata from Microsoft OneNote documents.
# Library dependancies: N/A
from laikaboss.objectmodel import ExternalVars, ModuleObject, ScanError
from laikaboss.si_module import SI_MODULE
from laikaboss import config
from collections import defaultdict
import re
import struct

class META_ONENOTE(SI_MODULE):
    '''
    Input: A OneNote file for data extraction
    Output: Embeded Files (images, videos, pdfs, etc)

    Purpose: Extract attached / embeded files from OneNote document.
    '''
    def __init__(self,):
        self.module_name = "META_ONENOTE"
        # "Regular Expressions" used to identify certain data structures in the OneNote file
        self.regex_text = re.compile(b"\x09\x04\x01\x00\x00\x00..\x00\x00")
        self.regex_date = re.compile(b"\x03.\x00\x00\x00(Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday)")
        self.regex_time = re.compile(b"AM|PM")
        self.regex_author = re.compile(b"\x80\x3e\x18\x00\x00\x00")
        self.regex_resolutionId = re.compile(b"\x00\x00\x18\x01\x00\x00")
        self.regex_file_meta = re.compile(b"\x09\x04\x02\x00\x00\x00")
        self.regex_file = re.compile(b"\xe7\x16\xe3\xbd\x65\x26\x11.\xa4\xc4\x8d\x4d\x0b\x7a\x9e\xac")

    def _run(self, scanObject, result, depth, args):
        moduleResult = []

        # Use methods to extract files, and filenames/paths
        page_files, page_files_location = self._extract_pages_files(self, scanObject.buffer)
        file_meta_names, file_meta_paths, file_meta_locations = self._extract_pages_file_names(self, scanObject.buffer)

        # Explode out the files, but first attempt to match the extracted file to its name/path (when applicable)
        for file, offset in zip(page_files, page_files_location):
            # Try and find the corresponding file_name / path
            '''
            if len(file) > 1500:
                i = -1
                diff = -1
                for meta_loc in file_meta_locations:
                    if meta_loc > offset:
                        break
                    i += 1
                    diff = offset - meta_loc

                fname = 'err'
                fpath = None
                if i != -1:
                    fname = file_meta_names[i]
                    fpath = file_meta_paths[i]
                    file_meta_names.pop(i)
                    file_meta_paths.pop(i)
                    file_meta_locations.pop(i)

                print fname, len(file), diff, offset
                '''
            moduleResult.append(ModuleObject(buffer=file, externalVars=ExternalVars(filename='explode_onenote_%d' % offset)))
            #with open('file_%d' % offset, 'w') as f:
            #    f.write(file)

        # Still working on matching file names to files, for now just add as metadata
        scanObject.addMetadata(self.module_name, 'included_file_names', set(file_meta_names))
        scanObject.addMetadata(self.module_name, 'included_file_paths', set(file_meta_paths))

        # Extract and add text w/ timestamps
        page_text = self._extract_pages_text(self, scanObject.buffer)
        scanObject.addMetadata(self.module_name, 'text', dict(page_text))

        # Identify author of document
        author_reg = self.regex_author.search(scanObject.buffer)
        if(author_reg is not None):
            author_start = author_end = author_reg.start()+6
            # Find end of unicode string
            while scanObject.buffer[author_end:author_end+1] != b'\x00':
                author_end += 2

            # Try to extract ascii from unicode string
            author = scanObject.buffer[author_start:author_end].replace(b'\x00', b'')
            scanObject.addMetadata(self.module_name, 'author', author)

        # Extract resolutionId from document
        resId_reg = self.regex_resolutionId.search(scanObject.buffer)
        if(resId_reg is not None):
            resId_start = resId_end = resId_reg.start()+6
            # Find end of unicode string
            while scanObject.buffer[resId_end:resId_end+1] != b'\x00':
                resId_end += 2

            # Try to extract ascii from unicode string
            resId = scanObject.buffer[resId_start:resId_end].replace(b'\x00', b'')
            scanObject.addMetadata(self.module_name, 'resId', resId)

        # Return moduleResult (including included files)
        return moduleResult

    def _close(self):
        pass

    # Find the next ascii text portion
    @staticmethod
    def _extract_next_text(self, buff):
        # Try and find text data
        text = self.regex_text.search(buff)
        if(text is None):
            return None, -1

        # Find the start of this string
        text_start = text.start() + 10

        # Extract the size of the string and skip 0 length strings
        string_len_start = text.start() + 6
        buffer_size = struct.unpack("<H", buff[string_len_start:string_len_start+2])[0]
        if(buffer_size == 0):
            return self._extract_next_text(self, buff[text_start:])

        # Find the end of the string using the decoded string length
        text_end = text_start + buffer_size

        # Return the text and the offset to the end of it
        return buff[text_start:text_end], text_end

    # Extract text w/ timestamp from the OneNote document.
    @staticmethod
    def _extract_pages_text(self, buff):
        # Setup to go through all page structures
        extracted_text = defaultdict(list)
        left_limit = 0
        right_limit = 0

        # Get date from pages in this OneNote document
        while True:
            # See if there is another timestamp in the buffer
            date_loc = self.regex_date.search(buff[left_limit:])
            if(date_loc is None):
                break

            # Find date bounds
            date_start = left_limit + 5 + date_loc.start()
            date_end = buff[date_start:].find(b'\x01') + date_start

            # Update right bound (limit search to stuff before its corresponding timestamp)
            right_limit = date_start

            # Find time bounds
            time_loc = self.regex_time.search(buff[date_end:])
            if(time_loc is None):
                break
            time_start = time_loc.start() + date_end - 6
            if(buff[time_start:time_start+1] == b'\x00'):
                time_start += 1
            time_end = buff[time_start:].find(b'\x01') + time_start

            # Create timestamp string using extracted data
            timestamp = buff[date_start:date_end] + b' ' + buff[time_start:time_end]

            # Extract data before this timestamp (text)
            cur_left_limit = left_limit
            while True:
                text, offset = self._extract_next_text(self, buff[cur_left_limit:right_limit])
                if text is None:
                    break
                else:
                    extracted_text[timestamp].append(text)
                    cur_left_limit += offset

            # Update left limit
            left_limit = time_end + 1
        
        #Remove duplicate text sections per timestamp
        for ts in extracted_text:
            dedup_text = []
            for text in extracted_text[ts]:
                if text not in dedup_text:
                    dedup_text.append(text)
            extracted_text[ts] = dedup_text
        return extracted_text

    # Find the next attached file
    @staticmethod
    def _extract_next_file(self, buff):
        file = self.regex_file.search(buff)
        if(file is None):
            return None, -1, -1

        # Find the start of this file data
        file_start = file.start() + 36

        # Extract the size of the file
        file_len_start = file.start() + 16
        buffer_size = struct.unpack("<I", buff[file_len_start:file_len_start+4])[0]
        if(buffer_size == 0):
            return self._extract_next_file(self, buff[file_start:])

        # Find the end of the string using the decoded file length
        file_end = file_start + buffer_size

        return buff[file_start:file_end], file_start, file_end

    # Extract files from the buffer using the attached file header
    # Returns a list of files
    @staticmethod
    def _extract_pages_files(self, buff):
        extracted_files = []
        file_locs = []
        left_limit = 0
        while True:
            file, file_start, file_end = self._extract_next_file(self, buff[left_limit:])
            if file is None:
                break
            else:
                extracted_files.append(file)
                file_locs.append(left_limit + file_start)
                left_limit += file_end
        return extracted_files, file_locs

    # Extract the file names from buffer
    # Returns a list of file names and a list of file paths, and a list of locations
    # (with files marked as err if finding them failed)
    @staticmethod
    def _extract_pages_file_names(self, buff):
        file_names = []
        file_paths = []
        file_locs = []
        meta_iters = self.regex_file_meta.finditer(buff)
        if meta_iters is not None:
            for meta in meta_iters:
                file_locs.append(int(meta.start()))
                try:
                    meta_name_len = 0 + meta.start() + 8
                    meta_buffer_size = struct.unpack("<I", buff[meta_name_len:meta_name_len+4])[0]
                    if meta_buffer_size > 300:
                        file_names.append('err')
                        file_paths.append('err')
                        continue
                    if(meta_buffer_size != 0):
                        meta_buffer_start = 0 + meta.start()+12
                        file_names.append(buff[meta_buffer_start:meta_buffer_start + meta_buffer_size].replace(b'\x00', b''))
                        tmp = meta_buffer_start + meta_buffer_size
                        tmp += struct.unpack("<I", buff[tmp:tmp+4])[0] + 4
                        tmp += struct.unpack("<I", buff[tmp:tmp+4])[0] + 4
                        leng = struct.unpack("<I", buff[tmp:tmp+4])[0]
                        if leng > 300:
                            file_paths.append('err')
                            continue
                        tmp += 4
                        file_paths.append(buff[tmp:tmp+leng].replace(b'\x00',b''))
                except:
                    file_names.append('err')
                    file_paths.append('err')
        return file_names, file_paths, file_locs
