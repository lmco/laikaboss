# Copyright 2015 Lockheed Martin Corporation
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
#  Set up classes
from builtins import bytes
from builtins import str
from past.builtins import basestring
from builtins import object
from builtins import int
from laikaboss.constants import level_minimal, level_metadata
import logging
import base64
import time
import uuid
import json

# Metadata, etc. is always stored directly as unicode
def convertToUTF8(thing):
    if isinstance(thing, bytes):
        new_str = str(thing, "utf-8", errors="replace")
        return new_str
    elif isinstance(thing, str):
        return str(thing)
    elif isinstance(thing, (list, set, frozenset)):
        new_obj = []
        for o in thing:
            new_obj.append(convertToUTF8(o))
        return new_obj
    elif isinstance(thing, tuple):
        new_tuple = ()
        for o in thing:
            new_tuple += (convertToUTF8(o), )
        return new_tuple
    elif isinstance(thing, dict):
        new_obj = {}
        for key, value in thing.items():
            new_key = cleanKey(key)
            new_val = convertToUTF8(value)
            new_obj[new_key] = new_val
        return new_obj
    elif isinstance(thing, bool):
        return thing
    elif isinstance(thing, (int, float, complex)):
        if isinstance(thing, int) and type(thing) is not int:
            return int(thing)
        return thing
    elif isinstance(thing, uuid.UUID):
        return str(thing)
    else:
        return str(repr(thing))


# Utility function to (conditionally) convert a unicode buffer to UTF-8
# Note that str is a unicode type with "from builtins import str"
def ensureNotUnicode(buffer):
    if isinstance(buffer, str):
        return buffer.encode("utf-8")
    else:
        return buffer


# Utility function to make sure the buffer is a bytestring and not None
# (or whatever other weirdness comes through)
def ensureBytes(child_buffer):
    # buffers and bytearrays can be cast to bytes
    try:
        if isinstance(child_buffer, memoryview) or isinstance(child_buffer, bytearray):
            child_buffer = bytes(child_buffer)
    except:
        # Test cases do not produce any exceptions, but it's here just in case
        raise Exception("Buffer of %s found, not creating child scanObject" % str(type(child_buffer)))

    child_buffer = ensureNotUnicode(child_buffer)

    # refuse to process anything else, as non-bytestring objects can crash the worker
    if not isinstance(child_buffer, bytes):
        raise Exception("Buffer of %s found, not creating child scanObject" % str(type(child_buffer)))

    return child_buffer


def cleanKey(key):
    bad_chars = ["\0", ".", "$"]
    new_key = convertToUTF8(key)

    if isinstance(new_key, str):  # For now, allow keys to be booleans or integers
        for c in bad_chars:
            new_key = new_key.replace(c, "_")

    return new_key


class ScanError(RuntimeError):
    """Base error for any laika  runtime errors"""

    pass


class QuitScanException(ScanError):
    """Quit a scan prematurely"""

    pass


class GlobalScanTimeoutError(ScanError):
    """Global timeout for an entire scan"""

    pass


class GlobalModuleTimeoutError(ScanError):
    """Global timeout for any module within a scan"""

    pass


class ScanObject(object):
    def __init__(
        self,
        objectHash="",
        contentType=[],
        fileType=[],
        buffer="",
        objectSize=0,
        filename="",
        ephID="",
        uniqID="",
        parent="",
        parent_order=-1,
        sourceModule="",
        source="",
        depth=-1,
        order=-1,
        rootUID="",
        origRootUID="",
        charset="",
        level=level_minimal,
        uuid=str(uuid.uuid4()),
    ):
        self.contentType = convertToUTF8(contentType)
        self.fileType = fileType
        self.scanModules = []
        self.flags = []
        self.objectHash = objectHash
        self.buffer = ensureBytes(buffer)
        self.objectSize = objectSize
        self.filename = convertToUTF8(filename)
        self.ephID = convertToUTF8(ephID)
        self.uniqID = convertToUTF8(uniqID)
        self.uuid = uuid
        self.parent = parent
        self.parent_order = parent_order
        self.sourceModule = convertToUTF8(sourceModule)
        self.source = convertToUTF8(source)
        self.moduleMetadata = {}
        self.level = level
        self.depth = convertToUTF8(depth)
        self.order = order
        self.rootUID = ""
        self.origRootUID = origRootUID
        self.charset = charset
        self.scanTime = int(time.time())

    # Wrapper function to add flags to the object
    def addFlag(self, flag):
        flag = convertToUTF8(flag)
        if flag not in self.flags:
            self.flags.append(flag)

    # Wrapper function for adding metadata to the object
    def addMetadata(self, moduleName, key, value, unique=False, maxlen=0):
        # Convert the value into UTF8, regardless of type (function will handle it)
        value = convertToUTF8(value)
        key = cleanKey(key)

        if maxlen:
            try:
              if len(value) > maxlen:
                 logging.warn('truncating value of rootUID:%s uuid:%s filename:%s, module_name:%s key:%s ' % (self.rootUID, self.uuid, self.filename, moduleName, key))
                 value = (value[:maxlen] + '.._truncated')
            except TypeError as e:
                # it may be a type which doesn't support len
                pass

        # If no metadata exists for this module yet, add a new dictionary with the key/value pair
        if moduleName not in self.moduleMetadata:
            self.moduleMetadata[moduleName] = {key: value}
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
                    return ""
            else:
                return ""
        # Return all metadata for a specific module
        else:
            if moduleName in self.moduleMetadata:
                return self.moduleMetadata[moduleName]
            else:
                return {}

    # This function is used for serializing ScanObjects
    def serialize(self):
        # If the return level is minimal, delete the buffer and metadata
        if self.level == level_minimal:
            odict = self.__dict__.copy()
            del odict["buffer"]
            del odict["moduleMetadata"]
        # If the return level is metadata, delete the buffer
        elif self.level == level_metadata:
            odict = self.__dict__.copy()
            del odict["buffer"]
        else:
            odict = self.__dict__
        return odict

    def __getstate__(self):
        return self.serialize()


class ScanResult(object):
    def __init__(self, source=None, level=None, rootUID=None, submitID=None):
        self.files = {}
        self.startTime = 0
        self.disposition = ""

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

        if submitID:
           self.submitID = submitID
        else:
           self.submitID = ""

    files = {}
    startTime = 0
    source = ""
    level = ""
    rootUID = ""
    disposition = ""
    submitID = ""

    @staticmethod
    def encode(scanresult):

        d = {}

        serialized_files = {}
        for f in scanresult.files:
            serialized_files[f] = scanresult.files[f].serialize()
        d["files"] = serialized_files
        d["startTime"] = scanresult.startTime
        d["source"] = scanresult.source
        d["level"] = scanresult.level
        d["rootUID"] = scanresult.rootUID
        d["disposition"] = scanresult.disposition
        d["submitID"] = scanresult.submitID

        try:
            d = convertToUTF8(d)
        except Exception as e:
            logging.exception("serialization error:")

        store_str = json.dumps(d, ensure_ascii=False)

        if not isinstance(store_str, bytes):
            store_str = store_str.encode("utf-8", errors="replace")

        return store_str

    @staticmethod
    def decode(buf):

        if not isinstance(buf, str):
            buf = buf.decode("utf-8", errors="replace")

        d = json.loads(buf)

        result = ScanResult(source=d.get('source', ""), level=d.get('level', 0), rootUID=d.get('rootUID',""), submitID=d.get('submitID', ""))
        result.startTime = d.get("startTime", 0)
        result.files = d.get("files",{})
        result.disposition = d.get("disposition",{})
        return result

class SI_Object(object):
    def __init__(self, buffer, externalVars):
        self.buffer = ensureBytes(buffer)
        self.externalVars = externalVars

    buffer = ""
    externalVars = None

class ModuleObject(SI_Object):
    pass


class ExternalObject(SI_Object):
    def __init__(self, buffer, externalVars, level=level_minimal):
        self.level = level

        if not isinstance(buffer, bytes):
            buffer = buffer.encode("utf-8", errors="replace")

        self.buffer = buffer
        self.externalVars = externalVars
        level = ""

    @staticmethod
    def encode(external_obj, ver=2):

        d = {}

        buf = external_obj.buffer

        if not isinstance(buf, bytes):
            buf = buf.encode("utf-8", errors="replace")

        d["buffer"] = base64.standard_b64encode(buf)
        d["level"] = external_obj.level
        d["externalVars"] = external_obj.externalVars.encode(as_dict=True)
        d["ver"] = ver

        try:
            d = convertToUTF8(d)
        except Exception as e:
            logging.exception("serialization error:")

        store_str = json.dumps(d, ensure_ascii=False)

        if not isinstance(store_str, bytes):
            store_str = store_str.encode("utf-8", errors="replace")

        return store_str

    @staticmethod
    def decode(encoded):

        try:
            d = json.loads(encoded)
        except Exception as e:
            logging.exception("decode error len= " + str(len(encoded)) + " encoded: '" + str(encoded[:100]) + "'")
            raise e

        # would we prefer unicode or utf-8 here? IDK
        try:
            d = convertToUTF8(d)
        except Exception as e:
            logging.exception("decode error convert to utf-8") 
            raise e

        buf = base64.standard_b64decode(d["buffer"])

        level = d.get("level", level_minimal)

        ext_vars_dict = d.get("externalVars")

        externalVars = ExternalVars(**ext_vars_dict)
        
        return ExternalObject(buf, externalVars, level=level)


class ExternalVars(object):
    def __init__(
        self,
        sourceModule="",
        parentModules="",
        contentType=[],
        charset="",
        filename="",
        ephID="",
        uniqID="",
        timestamp="",
        source="",
        flags="",
        parent="",
        parent_order=-1,
        depth=0,
        origRootUID="",
        comment="",
        submitter="",
        submitID="",
        extArgs={},
        extMetaData={},
        **kwargs
    ):

        self.sourceModule = sourceModule
        self.parentModules = parentModules
        self._contentType = []
        self.set_contentType(contentType)
        self.set_charset(charset)
        self.set_filename(filename)
        self.set_ephID(ephID)
        self.set_uniqID(uniqID)
        self.set_timestamp(timestamp)
        self.set_source(source)
        self.flags = flags
        self.parent = parent
        self.parent_order = parent_order
        self.depth = depth
        self.set_origRootUID(origRootUID)
        self.set_extMetaData(extMetaData)
        self.set_extArgs(extArgs)
        self.set_submitter(submitter)
        self.set_comment(comment)
        self.set_submitID(submitID)

    def encode(self, as_dict=False):

        d = {
            "sourceModule": self.sourceModule,
            "parentModules": self.parentModules,
            "contentType": self.get_contentType(),
            "charset": self.get_charset(),
            "filename": self.get_filename(),
            "ephID": self.get_ephID(),
            "uniqID": self.get_uniqID(),
            "timestamp": self.get_timestamp(),
            "source": self.get_source(),
            "flags": self.flags,
            "parent": self.parent,
            "parent_order": self.parent_order,
            "depth": self.depth,
            "origRootUID": self.get_origRootUID(),
            "comment": self.get_comment(),
            "submitter": self.get_submitter(),
            "submitID": self.get_submitID(),
            "extArgs": self.get_extArgs(),
            "extMetaData": self.get_extMetaData(),
        }

        if as_dict:
            return d

        store_str = json.dumps(d, ensure_ascii=False)

        try:
            submitID = d.get("submitID", "")
            store_str = convertToUTF8(store_str)
        except Exception as e:
            logging.exception("serialization error error:" + submitID)
            raise

        return store_str

    def get_contentType(self):
        return self._contentType

    def set_contentType(self, value):
        self._contentType = []
        if type(value) is list:
            self._contentType.extend(convertToUTF8(value))
        else:
            self._contentType.append(convertToUTF8(value))

    def get_charset(self):
        return self._charset

    def set_charset(self, value):
        self._charset = convertToUTF8(value)

    def get_filename(self):
        return self._filename

    def set_filename(self, filename):
        self._filename = convertToUTF8(filename)
        # Filenames must always be python native strings for compatibility
        if not isinstance(self._filename, str):
            self._filename = self._filename.encode("utf-8")

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

        try:
            extMetaData = json.loads(extMetaData)
        except ValueError:
            pass
        except TypeError:
            pass

        # in case someone sent an empty string or None
        if not extMetaData:
            extMetadata = {}

        self._extMetaData = convertToUTF8(extMetaData)

    def set_comment(self, comment):
        self._comment = convertToUTF8(comment)
        self._setMetaItem("laikaboss_ext", "comment", self._comment)

    def get_comment(self):
        return self._comment

    def set_submitter(self, submitter):
        self._submitter = convertToUTF8(submitter)
        self._setMetaItem("laikaboss_ext", "submitter", self._submitter)

    def get_submitter(self):
        return self._submitter

    def set_submitID(self, submitID):
        self._submitID = convertToUTF8(submitID)
        self._setMetaItem("laikaboss_ext", "submitID", self._submitID)

    def get_submitID(self):
        return self._submitID

    def set_extArgs(self, extArgs):

        try:
            extMetaData = json.loads(extArgs)
        except ValueError:
            pass
        except TypeError:
            pass

        # in case someone sent an empty string or None
        if not extArgs:
            extArgs = {}

        # put in a top level variable and in the extMetadata for now
        self._extArgs = convertToUTF8(extArgs)
        self._setMetaItem("args", value=self._extArgs)

    def get_extArgs(self):
        return self._extArgs

    def _setMetaItem(self, key1, key2=None, value=None):

        extMetaData = self._extMetaData

        if key2:
            m_ext = extMetaData.get(key1, {})
            m_ext[key2] = value
            extMetaData[key1] = m_ext
        elif value:
            try:
                extMetaData[key1] = value
            except Exception as e:
                err = " raise: '" + str(extMetaData) + "'"
                err += " type:" + str(type(extMetaData))
                err += " e:" + str(e)
                raise TypeError(err)

        self._extMetaData = extMetaData

    sourceModule = ""
    parentModules = ""
    _contentType = []
    contentType = property(get_contentType, set_contentType)
    charset = property(get_charset, set_charset)
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
    submitID = property(get_submitID, set_submitID)
    submitter = property(get_submitter, set_submitter)
    comment = property(get_comment, set_comment)
    extArgs = property(get_extArgs, set_extArgs)
