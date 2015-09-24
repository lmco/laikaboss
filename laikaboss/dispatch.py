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
import time
import logging
import Queue
from util import get_scanObjectUID, listToSSV, yara_on_demand, \
                 log_module, log_module_error, getObjectHash, \
                 uniqueList, get_module_arguments, getRootObject
from objectmodel import ScanObject, QuitScanException, GlobalScanTimeoutError
from laikaboss import modules
import sys
import traceback
from laikaboss import config

from contextlib import contextmanager
from interruptingcow import timeout

module_pointers = {}

def _run_module(sm, scanObject, result, depth, args, earlyQuitTime=0):
    '''
    Description: The Dispatch function uses this private method to run a specific module against
                 an object. This method recursively calls the Dispatch method for any items
                 returned by a module.
     Arguments:
      - sm: a string containing the name of a scan module
      - scanObject: the current object being scanned
      - result: collects scan results of all objects being scanned in a dictionary
      - depth: every time dispatch is called, depth is increased by 1. may be used to limit recursion.
      - args: a dictionary containing arguments for a module provided by the Dispatcher
    '''
    logging.debug("si_dispatch - Attempting to run module %s against - uid: %s, filename %s with args %s" % 
                      (sm,get_scanObjectUID(scanObject),scanObject.filename,repr(args)))
    # Attempt the acquire the module given the name provided by the Dispatcher
    sm = sm.upper()
    if sm not in module_pointers:
        if hasattr(modules, sm):
            try:
                module_pointers[sm] = getattr(modules, sm)()
            except QuitScanException:
                raise
            except:
                error = traceback.format_exc().splitlines()[-1]
                errorText = "Module could not be initialized: %s Error: %s" % (sm, error)
                log_module_error("si_dispatch", 
                                  scanObject, 
                                  result,
                                  errorText)
                logging.debug(errorText)
                return
        else:
            logging.debug("module doesn't exist: %s" % sm)
            log_module_error("si_dispatch",
                             scanObject,
                             result,
                             "module not found: %s" % sm)
            return
    newscan = module_pointers[sm] 

    #  Add the current scan module to the list of scan modules run against this object
    scanObject.scanModules.append(sm)
    # Run the module
    moduleResult = newscan.run(scanObject, result, depth, args)
    if earlyQuitTime and earlyQuitTime < time.time():
        raise GlobalScanTimeoutError()
    # Perform a recursive scan for each item returned by the module (may be none)
    for moduleObject in moduleResult:
        moduleObject.externalVars.source = result.source
        moduleObject.externalVars.parent = get_scanObjectUID(scanObject) 
        moduleObject.externalVars.parentModules = scanObject.scanModules
        moduleObject.externalVars.sourceModule = sm
        moduleObject.externalVars.flags = scanObject.flags
        Dispatch(moduleObject.buffer, result, depth, externalVars=moduleObject.externalVars)

def _conditional_scan(scanObject, externalVars, result, depth):    
    '''
    Description: This function performs a second pass scan of an object based on the results of a 
                 previous scan only. The yara rules look at the flags applied to this object and 
                 determine any additional scanning that may need to be performed based on these 
                 flags.
    Arguments:
     - scanObject: the current object being scanned
     - result: collects scan results of all objects being scanned in a dictionary
     - depth: every time dispatch is called, depth is increased by 1. may be used to limit recursion.
    '''
    # Attempt to disposition based on flags from the first scan
    try:
        logging.debug("attempting conditional disposition on %s with %s uID: %s parent: %s" % (scanObject.filename, listToSSV(scanObject.flags), get_scanObjectUID(scanObject), scanObject.parent))
        externals = {
                        'ext_parentModules': listToSSV(externalVars.parentModules) or 'NONE',
                        'ext_sourceModule': externalVars.sourceModule or 'NONE',
                        'ext_contentType': listToSSV(scanObject.contentType) or 'NONE',
                        'ext_fileType': listToSSV(scanObject.fileType) or 'NONE',
                        'ext_filename': externalVars.filename or 'NONE',
                        'ext_timestamp': externalVars.timestamp or 'NONE',
                        'ext_source': externalVars.source or 'NONE',
                        'ext_size': scanObject.objectSize,
                        'ext_depth': depth or 0
                    }
        yresults = yara_on_demand(config.yaraconditionalrules, listToSSV(scanObject.flags), externals)
        moduleQueue = _get_module_queue(yresults, result, scanObject, "Conditional Rules")
    except (QuitScanException, GlobalScanTimeoutError):
        raise
    except Exception:
        logging.exception("si_dispatch: ERROR occured on conditional_scan on UID:%s Check your configuration!", get_scanObjectUID(scanObject))
        log_module_error("si_dispatch", scanObject, result, "error during conditional_scan: %s" % traceback.format_exc())
        return
    # Recusively call the Dispatcher if any conditional scans need to be performed.
    if not moduleQueue.empty():
        Dispatch(scanObject.buffer, result, depth, 
                    scanObject=scanObject, 
                    extScanModules=moduleQueue, 
                    conditional=True) 

def _addExtMetadata(scanObject, data):
    '''
    Description: Wrapper function around util function to facilitate adding external metadata.
    Arguments:
     - scanObject: the current object being scanned
     - data: Data to be appended to the scanObject
    '''

    # If the data is a string or list, add it as a single value to the 'data' key
    if isinstance(data, str) or isinstance(data, list):
        scanObject.addMetadata("EXTERNAL", "data", data)
    # If the data is a dict, loop through the dictionary and add each key, value
    elif isinstance(data, dict):
        for key, value in data.iteritems():
            scanObject.addMetadata("EXTERNAL", key, value)
    # If it is none of these, then add the repr() string to the 'object' key
    else:
        scanObject.addMetadata("EXTERNAL", "object", repr(data))
 
def _gather_metadata(buffer, externalVars, result, depth, maxBytes):
    '''
    Description: Helper function to set up a scanObject from various metadata sources.
    Arguments:  
     - buffer: the binary contents of the current object
     - externalVars: variables passed in from the caller or other modules
     - result: collects scan results of all objects being scanned in a dictionary
     - depth: every time dispatch is called, depth is increased by 1. may be used to limit recursion.
     - extMetaData: information provided externally that will be attached as metadata to the scanObject
    '''
    # Set up the object.

    contentType = externalVars.contentType if externalVars.contentType else []
    scanObject = ScanObject(parent=externalVars.parent,
                            buffer=buffer,
                            objectHash=getObjectHash(buffer),
                            objectSize=len(buffer),
                            filename=externalVars.filename,
                            contentType=contentType,
                            fileType=[],
                            uniqID=externalVars.uniqID,
                            ephID=externalVars.ephID,
                            origRootUID=externalVars.origRootUID,
                            sourceModule=externalVars.sourceModule,
                            source=result.source,
                            level=result.level,
                            depth=depth,
                            order=len(result.files))

    # Add the object to the scan result
    uid = get_scanObjectUID(scanObject)

    # Check to see if rootUID has been set, if it hasn't, then assume this is the root
    if not result.rootUID:
        result.rootUID = get_scanObjectUID(scanObject)

    # In order to ensure that all objects have a rootUID, set this after we have set the result.rootUID
    scanObject.rootUID = result.rootUID
    
    result.files[uid] = scanObject

    # If client provided metadata, append it to the scanObject
    if externalVars.extMetaData is not None and externalVars.extMetaData:
        _addExtMetadata(scanObject, externalVars.extMetaData)
    return scanObject

def _get_module_queue(yresults, result, scanObject, metaLabel):
    '''
    Description: Takes the results from a dispatch yara scan and creates a priority queue from them.
                 The function also adds dispatch flags if they exist in the rule.
    '''
    moduleQueue = Queue.PriorityQueue() 
    dispatchFlags = []
    parentDispatchFlags = []

    for yr in yresults:
        if 'scan_modules' in yr.meta:
            # Check to see if the rule has a priority, if not use the default
            if 'priority' in yr.meta:
                priority = int(yr.meta['priority'])
                logging.debug("Rule %s set priority %i" % (yr, priority))
            else:
                priority = int(config.defaultmodulepriority)
            scanObject.addMetadata("DISPATCH", metaLabel, "%s (%i)" % (str(yr), priority))
            moduleQueue.put((priority, uniqueList(yr.meta['scan_modules'].split())))
        if 'flags' in yr.meta:
            dispatchFlags.extend(yr.meta['flags'].split())
        if 'parent_flags' in yr.meta:
            parentDispatchFlags.extend(yr.meta['parent_flags'].split())
        if 'file_type' in yr.meta:
            scanObject.fileType.append(yr.meta['file_type'])
    dispatchFlags = set(dispatchFlags)
    for df in dispatchFlags:
        scanObject.addFlag("dispatch::%s" % (df))
    if scanObject.parent in result.files:
        for pdf in parentDispatchFlags:
            result.files[scanObject.parent].addFlag("dispatch::%s" % (pdf))

    return moduleQueue

def _process_module_queue(moduleQueue, result, depth, scanObject, earlyQuitTime=0):
    '''
    Description: Takes a priority module queue and runs each module in the appropriate order.
                 Each module is tracked for uniqueness to prevent redundancy.
    '''

    MAXDEPTH = 0
    if hasattr(config, 'maxdepth'):
        # If the depth limit has been exceeded, then don't run any modules
        MAXDEPTH = int(config.maxdepth)
        if MAXDEPTH < 0:
            MAXDEPTH = 0

    moduleSeen = []
    while True:
        if MAXDEPTH and depth > MAXDEPTH:
            errorText = "Depth has been exceeded. Only the dispatcher will be run on this object."
            logging.debug(errorText)
            log_module_error("si_dispatch",
                              scanObject,
                              result,
                              errorText)
            scanObject.addFlag("dispatch:nfo:max_depth_exceeded")
            break

        # Read until the queue is empty
        if moduleQueue.empty(): 
            logging.debug("Module run queue is empty") 
            break
        scanModules = moduleQueue.get()[1]
        for sm in scanModules:
            if sm in moduleSeen: 
                logging.debug("Already ran %s, continuing to the next module" % (sm))
                continue
            module, args = get_module_arguments(sm)
            _run_module(module, scanObject, result, depth, args, earlyQuitTime)
            moduleSeen.append(sm)

def close_modules():
    """
    Description: Module callback API caller to close down (destruct) each module safely.
    """
    for module_name, module_pointer in module_pointers.items():
        module_pointer.close()

@contextmanager
def _with_true():
    yield True

def _with_conditional(condition):
    if condition:
        return _with_true()
    return False

def Dispatch(buffer, result, depth, externalVars=None, 
                                       scanObject=None, 
                                       extScanModules=None, 
                                       conditional=False ):
    """
    Description: By default, this function uses yara to disposition a buffer and determine what scan modules
                 should be run against it. The function may be called recursively if a scan module returns 
                 additional buffers to scan. The function collects all results into the original result object
                 passed in by the caller for easy retrieval.
    Arguments: (* denotes OPTIONAL parameters):
     - buffer: the binary contents of the current object
     - result: collects scan results of all objects being scanned in a dictionary
     - depth: every time dispatch is called, depth is increased by 1. may be used to limit recursion.
     - *externalVars: variables passed in from the caller or other modules
     - *scanModules: this function may be called with predefined scan modules set (string, space delimited)
     - *conditional: determines whether this function has been called as the result of a conditional scan
     - *externalVars: these variables are passed to yara along with the current object to aid in disposition
    """ 

    skip_timeout = True
    if depth == 0 or (externalVars is not None and int(externalVars.depth) > 0):
        skip_timeout = False

    global_scan_timeout = 3600
    if hasattr(config, 'global_scan_timeout'):
        global_scan_timeout = int(config.global_scan_timeout)
    global_scan_timeout_endtime = result.startTime + global_scan_timeout

    if externalVars is not None and externalVars.depth:
        depth = externalVars.depth

    starttime = time.time()
    MAXBYTES = 0
    if hasattr(config, 'dispatchmaxbytes'):
        # If the depth limit has been exceeded, then don't run any modules
        MAXBYTES= int(config.dispatchmaxbytes)
        if MAXBYTES < 0:
            MAXBYTES = 0
        logging.debug('setting dispatch byte limit to %i' % (MAXBYTES))

    #
    #  This branch is designed for first-pass scanning where file type and scan modules are unknown
    #  Yara is used to disposition the file and determine which modules should be run against it
    #  Using the result of each module, it is determined (using a separate yara scan on the flags) 
    #  whether or not a conditional scan needs to be run. 
    if extScanModules is None:

        # Generate the scan object from the parameters
        scanObject = _gather_metadata(buffer, externalVars, result, depth, MAXBYTES)

        # Increase the depth only if it is the first time scanning an object
        depth += 1        

        logging.debug("si_dispatch - Attempting to dispatch - uid: %s, filename: %s, \
source module: %s" % (get_scanObjectUID(scanObject), 
                       externalVars.filename, 
                       externalVars.sourceModule))
        #  check to see if this object has a parent, get the modules run against the parent if it exists
        #
        externals = {
                        'ext_parentModules': listToSSV(externalVars.parentModules) or 'NONE',
                        'ext_sourceModule': externalVars.sourceModule or 'NONE',
                        'ext_contentType': listToSSV(scanObject.contentType) or 'NONE',
                        'ext_filename': externalVars.filename or 'NONE',
                        'ext_timestamp': externalVars.timestamp or 'NONE',
                        'ext_source': externalVars.source or 'NONE',
                        'ext_flags': listToSSV(externalVars.flags) or 'NONE',
                        'ext_size': scanObject.objectSize,
                        'ext_depth': int(depth) or 0
                    }

        dispatch_rule_start = time.time()
        yresults = yara_on_demand(config.yaradispatchrules, buffer, externals, MAXBYTES)
        if config.modulelogging:
            log_module("MSG", 'si_dispatch', time.time() - dispatch_rule_start, scanObject, result, "")
        moduleQueue = _get_module_queue(yresults, result, scanObject, "Rules")


        with _with_conditional(skip_timeout) or timeout(global_scan_timeout, exception=GlobalScanTimeoutError):
            try:
                _process_module_queue(moduleQueue, result, depth, scanObject, global_scan_timeout_endtime)
                _conditional_scan(scanObject, externalVars, result, depth)
            except GlobalScanTimeoutError:
                # If the scan times out, add a flag and continue as a normal error
                scanObject.addFlag("dispatch:err:scan_timeout")

                # If not the root object, raise the exception to halt the parent scan
                if depth > 0 and (externalVars is None or depth > int(externalVars.depth)):
                    raise

                exc_type, exc_value, exc_traceback = sys.exc_info()
                logging.exception("error on %s. exception details below: " % \
                    (get_scanObjectUID(getRootObject(result))))

                log_module_error("dispatch:",
                                 scanObject,
                                 result,
                                 repr(traceback.format_exception(exc_type,
                                                                 exc_value,
                                                                 exc_traceback)))


    #
    #  This branch is designed for externally specified scan modules to be run against a buffer.
    #  It is not necessary to disposition the file type with yara because we are trusting the caller.
    #  This branch differs from a conditional scan in that there is no metadata about the buffer already, 
    #  so it must be gathered before beginning the scan. It is also subject to conditional scanning. 
    elif extScanModules is not None and not conditional:
        scanObject = _gather_metadata(buffer, externalVars, result, depth, MAXBYTES)
        with _with_conditional(skip_timeout) or timeout(global_scan_timeout, exception=GlobalScanTimeoutError):
            try:
                for sm in extScanModules:
                    module, args = get_module_arguments(sm)
                    _run_module(module, scanObject, result, depth, args)
                    # Disable conditional scan
                    #_conditional_scan(scanObject, externalVars, result, depth)
            except GlobalScanTimeoutError:
                # If the scan times out, add a flag and continue as a normal error
                scanObject.addFlag("dispatch:err:scan_timeout")

                # If not the root object, raise the exception to halt the parent scan
                if depth > 0 and (externalVars is None or depth > int(externalVars.depth)):
                    raise

                exc_type, exc_value, exc_traceback = sys.exc_info()
                logging.exception("error on %s. exception details below: " % \
                    (get_scanObjectUID(getRootObject(result))))

                log_module_error("dispatch",
                                 scanObject,
                                 result,
                                 repr(traceback.format_exception(exc_type,
                                                                 exc_value,
                                                                 exc_traceback)))

    
    # 
    #  This branch is specifically for conditional scans kicked off by this function. Metadata about 
    #  the object has already been collected and all that needs to occur is scans by the specified modules. 
    else:
        _process_module_queue(extScanModules, result, depth, scanObject)

    logging.debug("si_dispatch - depth: %s, time: %s" % (depth, time.time() - starttime))

