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
File for creating word lists from email bodies for primary use in attempting to decrypt password-protected archive formats (zip, rar, 7z)
"""

import re
import logging

TRUNCATE_NUM_WORDS = 2000

def get_siblings(result, scanObject):

    parent = scanObject.parent

    siblings = []

    for file in result.files:
        if result.files[file].parent == parent and result.files[file].uuid != scanObject.uuid:
            siblings.append(result.files[file])

    return siblings

def get_sibling_text(result, scanObject):
    siblings = get_siblings(result, scanObject)
    sibling_text = u''
    if siblings:
        for x in siblings:
            if x.charset and x.charset != 'None':
                sibling_text += x.buffer.decode(x.charset)
            else:
                try:
                    sibling_text += x.buffer.decode('utf-8')
                except UnicodeDecodeError:
                    pass
    return sibling_text

def get_hardcoded_passwords(hardcoded_password_list_path):
    passwords = []
    try:
        with open(hardcoded_password_list_path, 'r') as f:
            lines = f.readlines()
            passwords = [line.strip() for line in lines]

    except Exception as e:
        logging.debug('word_list_util: Error reading word list (%s)' % (str(e)))

    return passwords

def create_word_list(content, hardcoded_password_list_path):
    '''
    Creates a word list from an email. 
    Taken from LMCO/LB open sourced implementation of explode_rar.py
    The value in content *must* be text
    '''
    words = list()

    for line in re.split(r'\r\n|\n', content):
        for word in re.findall(re.compile('\S+'), line):
            if word not in words and len(word) > 2 and is_printable(word):
                words.append(word)
        for word in re.findall(re.compile('\w+'), line):
            if word not in words and len(word) > 2 and is_printable(word):
                words.append(word)

    # Add default words from a hardcoded list.
    ret = get_hardcoded_passwords(hardcoded_password_list_path) + words[:TRUNCATE_NUM_WORDS]

    return ret

def is_printable(s, codec='utf8'):
    if not isinstance(s, bytes):
        return True
    if b'\x00' in s:
        return False
    try:
        s.decode(codec)
    except UnicodeDecodeError:
        return False
    return True
