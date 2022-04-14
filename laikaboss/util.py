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
from future import standard_library
standard_library.install_aliases()
from past.builtins import basestring, unicode
from builtins import object
import yara
import random
import string
import hashlib
import logging
import syslog
import time
import os
import shutil
import tempfile
import datetime
import time
import socket
from minio import Minio
from contextlib import contextmanager
from laikaboss.objectmodel import QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError
from laikaboss import config

_environ_prefix = "LAIKA_"
_environ_custom_config = "LAIKA_CUSTOM_SITE_CONFIG"

#jinja substitutions may have substitutions - but limit recursiveness
_max_jinja_recursion = 5

# Set up logging variables
log_delimiter="|"
log_delimiter_replacement="_"
processID = os.getpid()

def init_logging():
    globals()['logFacility'] = getattr(syslog, config.logfacility)
    globals()['logIdentity'] = config.logidentity
    globals()['moduleLogLevel'] = getattr(syslog, config.moduleloglevel)
    globals()['scanLogLevel'] = getattr(syslog, config.scanloglevel)
    globals()['logResultFromSource'] = config.logresultfromsource
    syslog.openlog(str(logIdentity), 0, logFacility)

# Keeping this here for legacy purposes. It's now deprecated.
def init_yara():
    pass

# For random string generator
char_set = string.ascii_uppercase + string.digits + string.ascii_lowercase

# Set up lazy loading yara rules
yara_on_demand_rules = {}

# Top-level temporary directory (once found/created)
top_temp_dir = None

# How much of the file to rescan with yara if first scan had too many matches
yara_rescan_bytes = 1000000

def is_compiled(rule):
    '''
    Check to see if the yara signature is pre-compiled. 
    Compiled Yara has the file magic of 'YARA' starting at byte 0
    '''
    with open(rule, 'r') as f:
        if f.read(4) == 'YARA':
            return True
        else: 
            return False

def yara_on_demand(rule, theBuffer, externalVars={}, maxBytes=0):
    try:
        logging.debug("util: doing on demand yara scan with rule: %s" % rule)
        logging.debug("util: externalVars: %s" % str(externalVars))
        if rule not in yara_on_demand_rules:
            if not is_compiled(rule):
                logging.debug("util: compiling %s for lazy load" % rule)
                yara_on_demand_rules[rule] = yara.compile(rule, externals=externalVars)
            else:
                yara_on_demand_rules[rule] = yara.load(rule)
        if maxBytes and len(theBuffer) > maxBytes:
            matches = yara_on_demand_rules[rule].match(data=buffer(theBuffer, 0, maxBytes) or 'EMPTY', externals=externalVars)
        else:
            matches = yara_on_demand_rules[rule].match(data=theBuffer or 'EMPTY', externals=externalVars)
        return matches
    except (QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError):
        raise
    except Exception as e:
        if not maxBytes and "internal error: 30" in str(e):
            logging.warning("Yara scan had too many matches, re-running with first %s bytes of file" % yara_rescan_bytes)
            return yara_on_demand(rule, theBuffer, externalVars, maxBytes=yara_rescan_bytes)
        else:
            logging.exception("util: yara on demand scan failed with rule %s" % (rule))
            raise

def listToSSV(alist):
    '''
    Converts a list object to a space separated value.

    Arguments:
    alist --- a list object

    Returns:
    string with all object contains in the list separated by a space
    '''
    return ' '.join(alist)

def getObjectHash(buffer):
    '''
    Uses hashlib to get a hash of the raw object buffer

    Arguments:
    buffer -- raw object buffer

    Returns:
    string containing the hash digest of the buffer
    '''
    algorithms_list = []
    if hasattr(hashlib, 'algorithms_available'):
        algorithms_list = hashlib.algorithms_available
    elif hasattr(hashlib, 'algorithms'):
        algorithms_list = hashlib.algorithms
    if not hasattr(config, 'objecthashmethod'):
         config.objecthashmethod = 'md5'
    if config.objecthashmethod not in algorithms_list:
         logging.warn("Object hash method of '" + config.objecthashmethod + "' not supported, defaulting to 'md5'")
         config.objecthashmethod = 'md5'
    hasher = hashlib.new(config.objecthashmethod)
    hasher.update(buffer)
    return hasher.hexdigest()

def log_result(result, returnOutput=False):
    '''
    This function takes a fully populated scan result set and sends a syslog message for
    each object contained in the set.

    Arguments:
    result -- a fully populated scan result set

    Returns:
    Nothing.
    '''
    global log_delimiter
    global log_delimiter_replacement
    # check result.source (set by the caller) to see if its in our list of sources 
    # we should log from. this is to exclude logging from sources such as filescan.
    # this can be overridden using the 'all' keyword in the configuration.
    # module and error logging still occur regardless
    output = []
    if 'all' not in logResultFromSource and result.source not in logResultFromSource:
        logging.debug('skipping logging result from source %s not in %s' % (result.source, logResultFromSource))
        return
    try:
        rootObject = getRootObject(result)
        if result.startTime:
            scanTime = time.time() - result.startTime
            scanTime = str(scanTime)[:7]
        else:
            scanTime = 0
        for uid, scanObject in result.files.items():
            parentFilename = ""
            parentUID = ""
            if uid != result.rootUID:
                parentUID = scanObject.parent
                parentFilename = result.files[parentUID].filename
            log = "RESULT %s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s" % \
                   (
                       clean_field(processID),
                       clean_field(result.source),
                       clean_field(scanTime),
                       clean_field(get_scanObjectUID(rootObject)),
                       clean_field(rootObject.filename),
                       clean_field(rootObject.uniqID),
                       clean_field(rootObject.ephID),
                       clean_field(get_scanObjectUID(scanObject)),
                       clean_field(scanObject.filename),
                       clean_field(scanObject.contentType),
                       clean_field(scanObject.fileType),
                       clean_field(scanObject.objectHash),
                       clean_field(scanObject.objectSize),
                       clean_field(scanObject.flags),
                       clean_field(scanObject.scanModules),
                       clean_field(parentUID),
                       clean_field(parentFilename, last=True)
                   )
            if returnOutput:
                output.append(log)
            else:
                syslog.syslog(scanLogLevel, "%s"%(log))
            logging.debug("log entry: %s" % log)
    except (QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError):
        raise
    except Exception as e:
        logging.exception("result logging error for %s" % rootObject.filename)
    if returnOutput:
        return output
        
def clean_field(field, last=False):
    '''
    Cleans up a string to be inserted into a log entry. Ensures it is of type "str",
    replaces any pipe characters with an underscore, then adds a pipe to the end of
    the string.

    Arguments:
    field -- string or object to be inserted into the log
    *last -- boolean that determines if this is the last log entry (no pipe at end)

    Returns:
    A string ready for use in a log entry
    '''
    # Force field to native unicode type
    if isinstance(field, unicode):
        field = unicode(field)
    if not isinstance(field, (basestring, list)):
        field = str(field)
    elif isinstance(field, list):
        field = listToSSV(set(field))
    elif not isinstance(field, str):
        try:
            field = field.encode('ascii', 'backslashreplace')
        except (QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError):
            raise
        except:
            field = ''
    result = field.replace(log_delimiter,log_delimiter_replacement).strip()
    if not last:
        result = "%s%s" % (result, log_delimiter)
    return result.replace("\0", "_")

def getRootObject(result):
    '''
    Returns the ScanObject in a result set that contains no parent (making it the root).

    Arguments:
    result -- a fully populated scan result set

    Returns:
    The root ScanObject for the result set.
    '''
    return result.files[result.rootUID]

def getParentObject(result, scanObject):
    '''
    Returns the ScanObject in a result set that has the UID of the given scanObject's parent, thus making it the parent object.

    Arguments:
    result -- a fully populated scan result set
    scanObject -- the object that the module was run against

    Returns:
    The parent object for the result set. None is returned if there is no parent (root object).

    '''
    parent = scanObject.parent
    if parent:
        parentObj = result.files[parent]
    else:
        parentObj = None
    return parentObj

def log_module(module_status, module_name, module_time, scanObject, result, msg=''):
    '''
    Standard logging function for all scan modules.

    Arguments:
    module_state    -- the status of the module (START, MSG, END)
    module_name     -- the name of the module calling this function
    module_time     -- the elapsed time it took to run the module
    scanObject      -- the object that the module was run against
    result          -- the result of the module
    msg             -- message to add additional comments to log

    Returns:
    Nothing
    '''
    global log_delimiter
    global log_delimiter_replacement
    try:
        rootObject = getRootObject(result)
        parentFilename = ""
        parentUID = ""
        if scanObject.parent:
            parentUID = scanObject.parent
            if parentUID in result.files:
                parentFilename = result.files[parentUID].filename

        log = "MODULE %s%s%s%s%s%s%s%s%s%s%s%s" % \
               (
                   clean_field(module_status),
                   clean_field(processID),
                   clean_field(get_scanObjectUID(rootObject)),
                   clean_field(module_name),
                   clean_field(module_time),
                   clean_field(get_scanObjectUID(scanObject)),
                   clean_field(scanObject.objectSize),
                   clean_field(scanObject.filename),
                   clean_field(parentUID),
                   clean_field(parentFilename),
                   clean_field(result.source),
                   clean_field(msg, last=True)
               )
        syslog.syslog(moduleLogLevel, "%s"%(log))
    except (QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError):
        raise
    except Exception as e:
        logging.exception("log_module error, details below:")

def log_module_error(module_name, scanObject, result, error):
    '''
    Standard error logging function for all scan modules

    Arguments:
    module_name -- the name of the module calling this function
    scanObject  -- the object that the module was run against
    error       -- an error message (usually a stack trace)
    
    Returns:
    Nothing
    '''
    global log_delimiter
    global log_delimiter_replacement

    if scanObject is None:
        parentUID = ""
        UID = ""
    else:
        parentUID = scanObject.parent
        UID = get_scanObjectUID(scanObject)

    if result is None:
        parentFilename = ""
    else:
        parentFilename = result.files[parentUID].filename if parentUID in result.files else ""
        
    try:
        log = "ERROR %s%s%s%s%s%s%s" % \
               (
                   clean_field(processID),
                   clean_field(module_name),
                   clean_field(UID),
                   clean_field(parentUID),
                   clean_field(parentFilename),
                   clean_field(result.source),
                   clean_field(error, last=True)
               )
        syslog.syslog(moduleLogLevel, "%s"%(log))
    except (QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError):
        raise
    except Exception as e:
        logging.exception("module error logging error, details below:") 

def log_CEF(module_name, staticDict, extensionDict):
    '''
    Logging function for modules that need to log to ArcSight. 
    
    Using the ArcSight smart connector for Syslog, the data is
    formatted into ArcSight Common Event Format (CEF) and forwared
    to Syslog, where it will be forwared onto ArcSight.

    Arguments:
    staticDict  -- the dictionary of static objects that are 
                    required for every ArcSight entry. these
                    are defaulted if the are not included.
                    Available fields (see ArcSight documentation for more info):
                        - Version
                        - Device Vendor
                        - Device Product
                        - Device Version
                        - Signature ID
                        - Name
                        - Severity
    extensionDict   -- the dictionary of other objects that
                        are used in ArcSight, such as custom fields.
                        The keys available are specified in the 
                        ArcSight documentation. According to the 
                        docs, there are some fields that use short
                        names, some that use the full names, and
                        some fields that appear to be left out entirely.
                        As such, make sure to review the documentation
                        when using this function.

    '''
    CEF = "CEF:"
    
    version = "0"
    device_vendor = "ngIDS"
    device_product = "laika"
    device_version = "0.0"
    signatureID = "0"
    name = module_name
    severity = 5


    for key, value in staticDict.items():
        if key == "Version":
            version = value
        elif key == "Device Vendor":
            device_vendor = value
        elif key == "Device Product":
            device_product = value
        elif key == "Device Version":
            device_version = value
        elif key == "Signature ID":
            signatureKey = value
        elif key == "Name":
            name = value
        elif key == "Severity":
            severity = value

    staticString = "%s%s%s%s%s%s%s%s" % (CEF, clean_field(version), clean_field(device_vendor), clean_field(device_product), clean_field(device_version), clean_field(signatureID), clean_field(name), clean_field(severity))

    extensionString = ""

    if extensionDict:
        for key in extensionDict:
            extensionString += "%s=%s " % (key, CEFify(clean_field(extensionDict[key], True)))
        extensionString = extensionString[:-1]

    logText = "%s%s" % (staticString, extensionString)


    # Syslog has a character limitation of 1000 characters, so ensure that the message is shortened enough
    # To shorten, take the longest value in the dictionary and concatenate by 10%. Repeat until under the limit.
    while len(logText) > 1000:
        longest = 'not_set'
        extensionString = ""
        for key in extensionDict:
            if longest == 'not_set':
                longest = key
            elif len(extensionDict[key]) > len(extensionDict[longest]):
                longest = key
        shortString = extensionDict[longest]
        shortLength = int(len(shortString) * 0.9)
        extensionDict[longest] = shortString[:shortLength]

        for key in extensionDict:
            extensionString += "%s=%s " % (key, CEFify(clean_field(extensionDict[key], True)))
        extensionString = extensionString[:-1]
                
        logText = "%s%s" % (staticString, extensionString)

    syslog.syslog(syslog.LOG_CRIT,logText)

    return logText

def CEFify(input):
    ''' Returns a string that is valid for CEF Extension format. '''
    
    input = input.replace('\\','\\\\')
    input = input.replace('=','\\=').replace('|','\\|').replace('\n','').replace('\r','').replace('\t','')

    return input

def getRandFill():
    '''Returns 6 random characters. Used for creating temporary ID's'''
    return ''.join(random.sample(char_set,6))

def get_parentModules(result, scanObject):
    '''
    Returns a string containing the scan modules run against the parent of a 
    ScanObject instance. The parent is a tuple containing the UID and (optional) 
    ID
    '''
    if scanObject.parent:
        return result.files[scanObject.parent].scanModules
    else:
        return ''

def get_scanObjectUID(scanObject):
    '''
    Get the UID for a ScanObject instance.
    
    Arguments:
    scanObject -- a ScanObject instance

    Returns:
    A string containing the UID of the object
    '''
    return scanObject.uuid


def get_module_arguments(sm):
    '''
    Extracts arguments from scan module declarations inside the yara dispatcher.
    Format is:
    SCAN_MODULE(arg1=value1,arg2=value2, arg3=value3)
    
    Arguments:
    sm --- a string in the format above

    Returns:
    A tuple containing the module name and a dictionary containing key value pairs.
    '''
    # Set default values
    arg_dict = {}
    module = ""
    # Look for parentheses, indicating arguments exist
    open_paren = sm.find('(')
    try:
        if open_paren > 0:
            # Get the name of the module
            module = sm[:open_paren]
            logging.debug("si_dispatch,util - Attempting to extract arguments from %s" % sm)
            args_string = sm[open_paren + 1:len(sm) - 1]
            args_list = args_string.split(',')
            for arg in args_list:
                kvp = arg.split('=')
                arg_dict[kvp[0].strip()] = kvp[1].strip()
        else:
            module = sm
    except (QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError):
        raise
    except Exception as e:
        logging.exception("error parsing module arguments, details below: ")
    return module, arg_dict

def get_all_module_metadata(result, scanModule):
    '''
    Loop through all results currently in populated and extract metadata for a specific module.
    Since this function will probably be called directly from a module, it's possible the
    metadata being sought after will not be available depending on what sequence the modules are
    run in.
    
    Arguments:
    result     --- a partially populated ScanResult object.
    scanModule --- a string in the format above

    Returns:
    A dictionary where the key is the uid and the value is a dictionary containing the module
    metadata for the specified module. The dictionary will only contain results for objects
    which have metadata available.
    '''
    moduleMeta = {}
    for uid, scanObject in result.files.items():
        mm = scanObject.getMetadata(scanModule)
        if mm:
            moduleMeta[uid] = mm
    return moduleMeta

def get_parent_metadata(result, scanObject, scanModule=None):
    '''
    Get the module metadata for the parent of a given ScanObject. Optionally you may specifiy a 
    specific module to get metadata for. If no scan module name is given, all module metadata 
    will be returned.

    Arguments:
    result     --- a partially populated ScanResult object.
    scanObject --- a ScanObject for which the metadata of its direct parent is desired
    scanModule (optional) --- a specific module to get metadata for

    Returns:
    1. Without scanModule specified:
           All module metadata for the parent of scanObject in a dictionary.
                { EXPLODE_EMAIL : { sender : blah@foo.com,
                                    recipient: john.doe@example.com },
                  SCAN_HEADERS  : { upstream_ip : 192.168.1.2,
                                    downstream_ip : 127.0.0.1 }
                }
    2. With scanModule specified:
           All metadata for the specified module.
               e.g. scanModule = EXPLODE_EMAIL would return:
                 { sender : blah@foo.com,
                 recipient: john.doe@example.com }

    When there is no data present, an empty dictionary is returned.
    '''
    if scanObject.parent in result.files and scanModule is None:
        return result.files[scanObject.parent].moduleMetadata
    elif scanObject.parent in result.files and scanModule is not None:
        if scanModule in result.files[scanObject.parent].moduleMetadata:
            return result.files[scanObject.parent].moduleMetadata[scanModule]
        else:
            return {}
    else: 
        return {}

def get_root_metadata(result, scanModule=None):
    '''
    Get the module metadata for the root of a given ScanResult set. Optionally you may specifiy a 
    specific module to get metadata for. If no scan module name is given, all module metadata 
    will be returned.

    Arguments:
    result     --- a partially populated ScanResult object.
    scanModule (optional) --- a specific module to get metadata for

    Returns:
    1. Without scanModule specified:
           All module metadata for the parent of scanObject in a dictionary.
                { EXPLODE_EMAIL : { sender : blah@foo.com,
                                    recipient: john.doe@example.com },
                  SCAN_HEADERS  : { upstream_ip : 192.168.1.2,
                                    downstream_ip : 127.0.0.1 }
                }
    2. With scanModule specified:
           All metadata for the specified module.
               e.g. scanModule = EXPLODE_EMAIL would return:
                 { sender : blah@foo.com,
                 recipient: john.doe@example.com }

    When there is no data present, an empty dictionary is returned.
    '''
    rootObject = getRootObject(result)
    if scanModule is not None:
        if scanModule in rootObject.moduleMetadata:
            return rootObject.moduleMetadata[scanModule]
        else:
            return {}
    else: 
        return rootObject.moduleMetadata

@contextmanager
def laika_temp_dir(large=False):
    '''
    Returns a context manager which can be used to create temporary directories. This ensures
    that each module uses a separate, non-world-writeable temporary directory, but that all
    laikaboss users can use the same top-level temp directory.

    Returns:
    A context manager for a string containing a temporary directory name. This directory and 
    its children are deleted upon exiting the context manager.
    '''
    global top_temp_dir
    tmpDir = None
    if not top_temp_dir:
        if hasattr(config, 'tempdir'):
            top_temp_dir = config.tempdir
        elif hasattr(config, 'large_tempdir'):
            top_temp_dir = config.large_tempdir
        else:
            top_temp_dir = tempfile.mkdtemp(prefix='laika_tmp_')
        if not os.path.isdir(top_temp_dir):
            os.mkdir(top_temp_dir)
            os.chmod(top_temp_dir, 0o1777)
        tempfile.tempdir = top_temp_dir
    try:
        if large and hasattr(config, 'large_tempdir') and os.path.isdir(config.large_tempdir):
            tmpDir = tempfile.mkdtemp(prefix='laika_tmp_', dir=config.large_tempdir)
        else:
            tmpDir = tempfile.mkdtemp(prefix='laika_tmp_', dir=top_temp_dir)
        yield tmpDir
    finally:
        if tmpDir:
           shutil.rmtree(tmpDir)

def uniqueList(lst):
    '''
    
    This function is a generator function that takes in a list and returns a
    de-duplicated list with the contents in the same relative order. It 
    utilizes the yield operator to submit back the iteration location of each
    unique object in the list. The next iteration (next call to the function)
    will add the value to the set and only yield back a result when it has
    found the next unique item. It continues to do this until it has reached
    the end of the list.

    Arguments:
    list    --- list to be de-duplicated.

    Returns:
    The function returns a generator object that will need to be iterated 
    over to continue through the results. In most cases, it is easiest to
    wrap a container constructor, such as list, around the object so that
    it will iterate through the contents and return the full result.

    Example:
    l = ['A', 'B', 'A', 'D', 'C', 'C', 'D']
    print list(uniqueList(l))
    
    Example Output: ['A', 'B', 'D', 'C']


    '''
    seen = set()
    for i in lst:
        if i not in seen:
            yield i
            seen.add(i)

def get_option(args, argskey, configkey, default=None):
    """
    Get the user's preferred value for an option. The user may specify
    their preferred option's value as either an argument or a
    configuration option. This method will first attempt to parse out the
    value from the given arguments then from the configuration.

    Arguments:
    args        --  The arguments given from the Laika framework into the
                    module.
    argskey     --  The key for the option's value within the Laika
                    framework's arguments.
    configkey   --  The key for the option's value within the overall
                    configuration. If its a list, will be checked in order
    default     --  (Optional) The default value to return if the user-specified
                    value is not found. Default is None.

    Returns:
    The user-specified value if found, or the default value.

    """

    value = default

    if configkey and not isinstance(configkey, list):
       configkey = [configkey]

    if argskey in args:
       value = args[argskey]
    elif configkey:
      for key in configkey:
         if hasattr(config, key):
            value = getattr(config, key)
            break

    return value

class laika_submission_encoder(object):

    def __init__(self, submission_dir, queue, externalVars):

        self.submission_dir = submission_dir
        self.queue = queue
        self.externalVars = externalVars

    def get_output_filename(self, create_parent_dirs = True):

        dir_path = os.path.join(self.submission_dir, self.queue)

        if create_parent_dirs and not os.path.isdir(dir_path):
            os.makedirs(dir_path)

        now = datetime.datetime.utcnow()

        val = now.strftime("%Y-%m-%d_%H:%M:%SZ") + '-' + str(self.externalVars.get_submitID()) + ".submit"

        path = os.path.join(dir_path,val)

        return path

def toBool(v, default = None):

    if v is not None:
       if isinstance(v, bool):
          return v

       if isinstance(v, basestring):
           v = v.lower().strip()
           if v in ['yes', 'true', 'on', 'enabled', '1']:
              return True
           elif v in ['no', 'false', 'off', 'disabled', '0']:
              return False

    if default is None:
       raise ValueError("value is not a bool")

    return default


init_logging()
