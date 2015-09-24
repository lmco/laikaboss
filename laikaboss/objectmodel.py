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
#  Set up classes
from laikaboss.constants import level_minimal, level_metadata#, level_full
import time
import uuid

def convertToUTF8(thing):
    t = type(thing)
    if t in [str]:
        new_str = unicode(thing, 'utf-8', errors='replace').encode('utf-8')
        return new_str 
    elif t is unicode:
        return thing.encode('utf-8')
    elif t in [list, set, frozenset]:
        new_obj = []
        for o in thing:
            new_obj.append(convertToUTF8(o))
        return new_obj
    elif t is dict:
        new_obj = {}
        for key, value in thing.iteritems():
            new_key = cleanKey(key) 
            new_val = convertToUTF8(value)
            new_obj[new_key] = new_val
        return new_obj
    elif t in [int, float, long, complex]:
        return thing
    if t is uuid.UUID:
        return str(thing)
    else:
        return repr(thing)

def cleanKey(key):
    bad_chars = ['\0', '.', '$']
    new_key = key

    if not (isinstance(key, str) or isinstance(key, unicode)):
        new_key = str(new_key)

    for c in bad_chars:
        new_key = new_key.replace(c, '_')

    return convertToUTF8(new_key)

class ScanError(RuntimeError):
    '''Base error for any laika  runtime errors'''
    pass

class QuitScanException(ScanError):
    '''Quit a scan prematurely'''
    pass

class GlobalScanTimeoutError(ScanError):
    '''Global timeout for an entire scan'''
    pass

class GlobalModuleTimeoutError(ScanError):
    '''Global timeout for any module within a scan'''
    pass

class ScanObject(object):
    def __init__(self, objectHash = "",
                       contentType = [],
                       fileType = [],
                       buffer = "",
                       objectSize = 0,
                       filename = "",
                       ephID = "",
                       uniqID = "",
                       parent = "",
                       sourceModule = "",
                       source = "",
                       depth = -1,
                       order = -1,
                       rootUID = "",
                       origRootUID = "",
                       level = level_minimal):
        self.contentType = convertToUTF8(contentType)
        self.fileType = fileType
        self.scanModules = []
        self.flags = []
        self.objectHash = objectHash
        self.buffer = buffer
        self.objectSize = objectSize
        self.filename = filename
        self.ephID = convertToUTF8(ephID)
        self.uniqID = convertToUTF8(uniqID)
        self.uuid = str(uuid.uuid4())
        self.parent = parent
        self.sourceModule = convertToUTF8(sourceModule)
        self.source = convertToUTF8(source)
        self.moduleMetadata = {}
        self.level = level
        self.depth = convertToUTF8(depth)
        self.order = order
        self.rootUID = ""
        self.origRootUID = origRootUID
        self.scanTime = int(time.time())
    
    # Wrapper function to add flags to the object
    def addFlag(self, flag):
        flag = convertToUTF8(flag)
        if flag not in self.flags:
            self.flags.append(flag)

    # Wrapper function for adding metadata to the object
    def addMetadata(self, moduleName, key, value, unique=False):
        # Convert the value into UTF8, regardless of type (function will handle it)
        value = convertToUTF8(value)
        key = cleanKey(key)

        # If no metadata exists for this module yet, add a new dictionary with the key/value pair
        if moduleName not in self.moduleMetadata:
            self.moduleMetadata[moduleName] = { key : value }
        # If metadata already exists for this module, first check if the key exists
        else:
            # If the key doesn't already exist, add it to the dictionary
            if key not in self.moduleMetadata[moduleName]:
                if isinstance(value, list) and unique:
                    self.moduleMetadata[moduleName][key] = list(set(value))
                else:
                    self.moduleMetadata[moduleName][key] = value
            # Otherwise, check to see if its a list 
            else:
                if type(self.moduleMetadata[moduleName][key]) is list:
                    # Check to see if it's in the list. If it is and unique is specified, don't add it
                    if isinstance(value, list):
                        if unique:
                            self.moduleMetadata[moduleName][key].extend([x for x in value if x not in self.moduleMetadata[moduleName][key]])
                        else:
                            self.moduleMetadata[moduleName][key].extend(value)
                    else:
                        if value not in self.moduleMetadata[moduleName][key] or not unique:
                            self.moduleMetadata[moduleName][key].append(value)
                        
                # If it's not a list, convert it to one.
                else:
                    metalist = []
                    metalist.append(self.moduleMetadata[moduleName][key])
                    if isinstance(value, list):
                        if unique:
                            metalist.extend([x for x in list(set(value)) if x != self.moduleMetadata[moduleName][key]])
                        else:
                            metalist.extend(value)
                    else:
                        if value not in metalist or not unique:
                            metalist.append(value)
                    self.moduleMetadata[moduleName][key] = metalist

    # Wrapper function for retrieving metadata from the object.
    # If you don't specify a key this function returns a dictionary containing all metadata
    # for the specified module.
    def getMetadata(self, moduleName, key=None):
        # Return a specific piece of metadata for a specific module 
        if key is not None:
            if moduleName in self.moduleMetadata:
                if key in self.moduleMetadata[moduleName]:
                    return self.moduleMetadata[moduleName][key]
                else:
                    return '' 
            else:
                return '' 
        # Return all metadata for a specific module
        else:
            if moduleName in self.moduleMetadata:
                return self.moduleMetadata[moduleName]
            else:
                return {}

    # This function is used for serializing ScanObjects
    def __getstate__(self):
        # If the return level is minimal, delete the buffer and metadata
        if self.level == level_minimal:
            odict = self.__dict__.copy()
            del odict['buffer']
            del odict['moduleMetadata']
        # If the return level is metadata, delete the buffer
        elif self.level == level_metadata:
            odict = self.__dict__.copy()
            del odict['buffer']
        else:
            odict = self.__dict__
        return odict

class ScanResult(object):
    def __init__(self, source=None, level=None, rootUID=None):
        self.files = {} 
        self.startTime = 0 
        if source is not None:
            self.source = source
        else:
            self.source = ""
        if level is not None:
            self.level = level 
        else:
            self.level = level_minimal
        if rootUID is not None:
            self.rootUID = rootUID
        else:
            self.rootUID = ""
    files = {}
    startTime = 0
    source = ""
    level = ""
    rootUID = ""

class SI_Object(object):
    def __init__(self, buffer, externalVars):
        self.buffer = buffer
        self.externalVars = externalVars 
    buffer = ""
    externalVars = None

class ModuleObject(SI_Object):
    pass

class ExternalObject(SI_Object):
    def __init__(self, buffer, externalVars, level=level_minimal):
        self.level = level
        self.buffer = buffer
        self.externalVars = externalVars
    level = ""

class ExternalVars(object):
    def __init__(self, sourceModule = "",
                       parentModules = "",
                       contentType = [], 
                       filename = "",
                       ephID = "",
                       uniqID = "",
                       timestamp = "",
                       source = "",
                       flags = "",
                       parent = "",
                       depth = 0,
                       origRootUID = "",
                       extMetaData = {}):

        self.sourceModule = sourceModule
        self.parentModules = parentModules
        self._contentType = []
        self.set_contentType(contentType)
        self.set_filename(filename)
        self.set_ephID(ephID)
        self.set_uniqID(uniqID)
        self.set_timestamp(timestamp)
        self.set_source(source)
        self.flags = flags
        self.parent = parent
        self.depth = depth
        self.set_origRootUID(origRootUID)
        self.set_extMetaData(extMetaData)

    def get_contentType(self):
        return self._contentType
    
    def set_contentType(self, value):
        self._contentType = []
        if type(value) is list:
            self._contentType.extend(convertToUTF8(value))
        else:
            self._contentType.append(convertToUTF8(value))

    def get_filename(self):
        return self._filename

    def set_filename(self, filename):
        self._filename = convertToUTF8(filename) 

    def get_ephID(self):
        return self._ephID

    def set_ephID(self, ephID):
        self._ephID = convertToUTF8(ephID) 

    def get_uniqID(self):
        return self._uniqID

    def set_uniqID(self, uniqID):
        self._uniqID = convertToUTF8(uniqID) 

    def get_timestamp(self):
        return self._timestamp

    def set_timestamp(self, timestamp):
        self._timestamp = convertToUTF8(timestamp) 

    def get_source(self):
        return self._source

    def set_source(self, source):
        self._source = convertToUTF8(source) 

    def get_origRootUID(self):
        return self._origRootUID

    def set_origRootUID(self, origRootUID):
        self._origRootUID = convertToUTF8(origRootUID) 

    def get_extMetaData(self):
        return self._extMetaData

    def set_extMetaData(self, extMetaData):
        self._extMetaData = convertToUTF8(extMetaData) 

    sourceModule = ""
    parentModules = ""
    _contentType = []
    contentType = property(get_contentType, set_contentType)
    filename = property(get_filename, set_filename)
    ephID = property(get_ephID, set_ephID)
    uniqID = property(get_uniqID, set_uniqID)
    timestamp = property(get_timestamp, set_timestamp)
    source = property(get_source, set_source)
    flags = ""
    parent = ""
    depth = 0
    rootUID = ""
    origRootUID = property(get_origRootUID, set_origRootUID)
    extMetaData = property(get_extMetaData, set_extMetaData)

