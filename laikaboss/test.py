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
# library for creating and execting test cases
#
from __future__ import division
from builtins import str, range
import sys
import os
import logging
import time
import zlib
import json
import base64
import uuid 
import re
import difflib
import tempfile
from laikaboss.extras.dictParser import DictParser

def _summarize_scanObjects(files):

    if not files:
        return []

    result = []

    for _, scanObj in files.items():
        result.append({'filename': scanObj.filename, 'buffer': encode_file(scanObj.buffer).decode('utf-8')})

    return result

#put logging handler in place before laikaboss import to catch exceptions there
class CollectHandler(logging.Handler):
    '''
    collect logs for processing later
    '''
    def __init__(self):
        super(CollectHandler, self).__init__()
        self.entries = []
    
    def emit(self, record):
        self.entries.append(self.format(record))
    
    def reset(self):
        return_val = self.entries
        self.entries = []
        return return_val

logger = logging.getLogger()
error_handler = CollectHandler()
error_handler.setLevel(logging.ERROR)
error_handler.setFormatter(logging.Formatter('ERROR: %(message)s'))
logger.addHandler(error_handler)

import laikaboss
import laikaboss.objectmodel
import laikaboss.constants
import laikaboss.dispatch
import laikaboss.clientLib 

#laikaboss global config items used to override default
null_config = {
    'yaradispatchrules' : os.devnull,
    'yaraconditionalrules' : os.devnull,
    'modulelogging' : True,
    'logresultfromsource' : ''          
}

LBTEST_EXTENSION = "lbtest"
IGNORE_PATTERN = []
IGNORE_PATTERN.append('^\."scan_result"\[[0-9]+\]\.("uuid"|"rootUID"|"scanTime"|"parent"|"submitID")')
IGNORE_PATTERN.append('^\."scan_result"\[[0-9]+\]\."moduleMetadata"."EXTERNAL"."laikaboss_ext".*')

ERROR_VALIDATION = 1
RUNTIME_VALIDATION = 0.0

def setLoggingLevel(level):
   error_handler.setLevel(level)
   return

#ensure print is encoded correctly--always utf8
def print_stdout(message, newline=True, encoding="utf8"):
    if newline:
        nl = "\n"
    else:
        nl = ""
    out = message + nl
    sys.stdout.write(out.encode(encoding, errors="replace").decode(encoding))

def print_stderr(message, newline=True, encoding="utf8"):
    if newline:
        nl = "\n"
    else:
        nl = ""
    out = message + nl
    sys.stderr.write(out.encode(encoding, errors="replace").decode(encoding))
    
def reset_errorlog():
    '''
    reset error log, returning current entries
    '''
    return error_handler.reset()
        
def encode_file(data):
    '''
    encode file for storage in json
    '''
    return base64.b64encode(zlib.compress(data))

def decode_file(data):
    '''
    decode file from json
    '''
    return zlib.decompress(base64.b64decode(data))    

def init_config(config=None, config_path=None):
    '''
    set up laikaboss config
   
    config is dictionary of individual directives
    config_path is path of LB config file. If not specified, a minimal config is set up. 
    It is strongly recommended to not use this parameter as it makes test cases non-portable: config files are not stored in the test case (but the config parameter is stored)
    
    TODO: is it necessary to clear previous configs?
    
    '''
    
    if config_path:
        laikaboss.config.init(path=config_path)
    else:
        laikaboss.config.init(path=os.devnull)
        for name in null_config:
            setattr(laikaboss.config, name, null_config[name])
    if config:
        for key in config:
            setattr(laikaboss.config, key, config[key])

def list_files(filenames, recursive=False):
    '''
    find existant files, when recursing, traverse directories but only look for lbtest files
    '''
    filelist = []
    for file in filenames:
        if os.path.isdir(file):
            if recursive:
                for root, dirs, files in os.walk(file):
                    files = [f for f in files if not f[0] == '.']
                    dirs[:] = [d for d in dirs if not d[0] == '.']
                    for fname in files:
                        fullpath = os.path.join(root, fname)
                        if os.path.isfile(fullpath):
                            #if lbtest_only:
                            if fullpath[-len(LBTEST_EXTENSION):] == LBTEST_EXTENSION and fullpath[-len(LBTEST_EXTENSION) - 1] == ".":
                                filelist.append(fullpath)
                            #else:
                            #    filelist.append(fullpath)
        elif os.path.isfile(file):
            #if lbtest_only:
            #    if file[-len(LBTEST_EXTENSION):] == LBTEST_EXTENSION and file[-len(LBTEST_EXTENSION) - 1] == ".":
            filelist.append(file)
            #else:
            #    filelist.append(file)
    
    return filelist
            
def flatten(obj, path="", sort_lists=False):
        '''
        returns a list of key, value tuples representing flattened object with keys formatted for jq
        
        TODO: decide what to do with data that is not dict, list, or basestring? Ex. a set. Skip? raise execption?
        '''
        return_val = []
        
        if isinstance(obj, dict):
            for key in obj:
                return_val.extend(flatten(obj[key], path='%s."%s"' % (path,key), sort_lists=sort_lists))
        elif isinstance(obj, list):
            if sort_lists:
                # Dictionaries aren't sortable; sort by keys if list of dicts
                if all([isinstance(x, dict) for x in obj]):
                    obj = sorted(obj, key=lambda x:sorted(x.items()))
                # Try to sort, abort if mixed types in list
                else:
                    try:
                        obj = sorted(obj)
                    except TypeError:
                        pass
            for key in range(len(obj)):
                return_val.extend(flatten(obj[key], path='%s[%i]' % (path,key), sort_lists=sort_lists))
        #elif isinstance(obj, basestring):
        else:
            return_val.append((path, obj))
            
        return return_val

def filter_items(items, regex):

    if regex and not isinstance(regex, list):
       regex = [regex]

    ignore_regex = []

    if regex:
       for r in regex:
          ignore_regex.append(re.compile(r))

    for item in items:

        if not ignore_regex:
            yield item
        else:
            skip = False
            for x in ignore_regex:
                if x.search(item[0]):
                    skip = True
                    break

            if not skip:
                yield item

def create_test(data, filename="", ext_metadata=None, scan_modules=None, attachment_data=None, config=None, 
                config_path=None, name="", ignore_pattern=IGNORE_PATTERN, comment="", 
                error_validation=ERROR_VALIDATION, runtime_validation=RUNTIME_VALIDATION, ignore_list_ordering=False, source=None, query=None):
    '''
    returns a single test
    
    To store in .lbtest file, place in list and json dump to file
    '''
    
    #make sure ignore_pattern compiles
    if not isinstance(ignore_pattern, list):
      re.compile(ignore_pattern)
    
    test = scan(data=data, filename=filename, ext_metadata=ext_metadata, scan_modules=scan_modules, attachment_data=attachment_data, config=config, config_path=config_path, source=source, query=query)

    if query:
        test['query_match'] = run_query(test, query)
        test['query'] = query

    test['name'] = name + "-" + filename
    test['ignore_pattern'] = ignore_pattern
    test['comment'] = comment
    test['error_validation'] = error_validation
    test['runtime_validation'] = runtime_validation
    test['ignore_list_ordering'] = ignore_list_ordering

    return test

def diff_tests(stored_test, current_test, ignore_pattern, custom_diff=None):
    '''
    diff two tests, return result diff, error diff, and runtime ratio
    
    test should include keys of result, errors, and runtime
    '''
    if 'ignore_list_ordering' in stored_test:
        ignore_list_ordering = stored_test['ignore_list_ordering'] 
    else:
        ignore_list_ordering = False
    stored_results = dict(filter_items(flatten(stored_test['result'], sort_lists=ignore_list_ordering), ignore_pattern))
    current_results = dict(filter_items(flatten(current_test['result'], sort_lists=ignore_list_ordering), ignore_pattern))
        
    stored_flat_results = [u"%s: %s\n" % (x,stored_results[x]) for x in sorted(stored_results)]
    current_flat_results = [u"%s: %s\n" % (x,current_results[x]) for x in sorted(current_results)]
                    
    result_diff = list(difflib.context_diff(stored_flat_results, current_flat_results, fromfile="stored_results", tofile="current_results", n=0))
                
    # overwritten by custom tests
    if custom_diff:
       result_diff = custom_diff(result_diff, stored_test, current_test)

    errors_diff = list(difflib.context_diff(stored_test['errors'], current_test['errors'], fromfile="stored_errors", tofile="current_errors", n=0))
    
    runtime_ratio = current_test['runtime']/stored_test['runtime']
    
    return (result_diff, errors_diff, runtime_ratio)

def execute_test(test, verbose=True, custom_diff=None, config_path=None, source=None, test_file=None):
    '''
    execute specified test
    
    test: dictionary returned from create_test
    return True or False indicating success or failure
    '''
    test['test_file'] = test_file
    if source:
        test['source'] = source
    else:
        source = test.get("result", {}).get("source", {})
        if source:
           test['source'] = source
    current_test = scan_helper(test, config_path=config_path)
    return grade_scan(test, current_test, verbose=verbose, custom_diff=custom_diff)

def grade_scan(stored_test, current_test, verbose=False, custom_diff=None):

    test_passed = True
    runtime_ratio = 0
    result_diff = None
    errors_diff = None

    failed_queries = []
     
    # check if it used a query string
    if stored_test.get("query", None):

        test_passed = False

        if current_test["query_match"][0]:
            test_passed = True
        failed_queries = current_test["query_match"][1]

    else:

        ignore_pattern = IGNORE_PATTERN
        custom_ignore_pattern = stored_test['ignore_pattern']
        if custom_ignore_pattern and custom_ignore_pattern not in ignore_pattern:
            if isinstance(custom_ignore_pattern, list):
                ignore_pattern.extend(custom_ignore_pattern)
            else:
                ignore_pattern.append(custom_ignore_pattern)

        # we just updated the default ignore pattern to include
        # more items, make it apply retroactively if they used the old default 
        # to crete the  test

        (result_diff, errors_diff, runtime_ratio) = diff_tests(stored_test, current_test, ignore_pattern, custom_diff)
        
        if 'error_validation' in stored_test:
            if stored_test['error_validation'] > 0:
                if stored_test['error_validation'] == 1:
                    if len(stored_test['errors']) != len(current_test['errors']):
                        test_passed = False
                if stored_test['error_validation'] == 2:
                    if error_diff:
                        test_passed = False
        
        if 'runtime_validation' in stored_test:
            if stored_test['runtime_validation'] > 1:
                if runtime_ratio > stored_test['runtime_validation']:
                    test_passed = False
                if runtime_ratio < 1/stored_test['runtime_validation']:
                    test_passed = False
        
        if result_diff:
            test_passed = False
    
    if test_passed:
        if verbose:
           print_stdout("\nPASSED: %s - %s %s" % (str(stored_test['test_file']), stored_test['name'], stored_test['comment']))
    else:
        print_stdout("\nFAILED: %s - %s %s" % (str(stored_test['test_file']), stored_test['name'], stored_test['comment']))

    if verbose:
        print_stderr("runtime ratio: %f" % (runtime_ratio))
    if (result_diff):
        print_stderr("".join(result_diff))
    if (errors_diff):
        print_stderr("".join(errors_diff))
    if failed_queries:
        print_stderr("failed queries:" + str(failed_queries))
    
    return test_passed

def execute_tests(files=".", verbose=True, config_path=None, source=None):
    '''
    execute specified test files, recursively searching specified directory
    '''
    tests_passed = 0
    tests_failed = 0
        
    for file in list_files(files, recursive=True):
        with open(file, "r") as f:
            tests = json.load(f)
        
        for test in tests:            
            test_passed = execute_test(test, verbose=verbose, config_path=config_path, source=source, test_file=file)
                            
            if test_passed:
                tests_passed = tests_passed + 1
            else:
                tests_failed = tests_failed + 1
    if verbose:
       print_stdout("\n%i/%i PASSED" % (tests_passed, (tests_passed + tests_failed)))
    
    return tests_failed
    
def load_one_test(file):
    ''' 
    Load exactly 1 test from one test file 
    '''
    for file in list_files([file], recursive=True):
        with open(file, "rb") as f:
            tests = json.load(f)
            return tests[0]
    return None

def matcher(d, key, value):

    if key:
       query = key + '=' + value
       dict_val = d.eval(key).value()
       if not dict_val:
          return False, [(query, dict_val)]
       if isinstance(value, str):
          if re.fullmatch(value, dict_val):
             return True, []
          return False, [(query, dict_val)]
       elif isinstance(value, list):
            # at least one item in the list must match
            for v in value:
                if re.fullmatch(v, dict_val):
                   return True, []
            return False, [(query, dict_val)]
       else:
            for v in value:
                return matcher(d, key, v)
    elif isinstance(value, list):

       failed_queries = []

       #Top level list all items must match
       for v in value:
           query = v
           if isinstance(v, dict):
              # grab first k,v, only support one for now
              key, v = next(iter(v.items()))
           r, res = matcher(d, key, v)
           if not r:
              failed_queries.append((query,res[0][1]))
       if failed_queries:
          return False, failed_queries

    return True,[]

def run_query(test, query):
    #[{"key1":"value"}, {"key2": ["A", "B", "C"]}
    #[{"key1":"value"}, {"key2": ["A", "B", "C"]}
    # this means key must be equal to value 1, and key2 must be one of the values in in the list of key2:
    # if key1 must be equal to multiple values, just specify it again, with a new value in the list

   test_dict = DictParser(test)

   return matcher(test_dict, "", query)

def scan(data, filename="", ext_metadata=None, scan_modules=None, attachment_data=None, config=None, config_path=None, source="", query=None):
    '''
    run laikboss scan and return result as dictionary continaing result, errors, etc.
    '''
    test = {}

    init_config(config=config, config_path=config_path)

    if not ext_metadata:
        ext_metadata = {}
    if not scan_modules:
        scan_modules = ""

    attachment_filename = ""
    scan_modules_orig = scan_modules
    if attachment_data != None:
        attachment_basename = ".lbtest-" + str(uuid.uuid4()) + "-" + str(time.time())
        attachment_filename = os.path.join(tempfile.gettempdir(), attachment_basename)
        with open(attachment_filename, "wb") as f:
            f.write(attachment_data)
        scan_modules = scan_modules.replace("LBTEST_ATTACHMENT", attachment_filename)

    if scan_modules:
       scan_modules_list = scan_modules.split()
    else:
       scan_modules_list = None

    result = laikaboss.objectmodel.ScanResult()
    result.source = "test" 
    if source:
       result.source = source
    result.startTime = time.time()
    result.level = laikaboss.constants.level_metadata
    myexternalVars = laikaboss.objectmodel.ExternalVars(filename=filename,
                                     source=source,
                                     extMetaData=ext_metadata)
    start_time = time.time()


    laikaboss.dispatch.Dispatch(data, result, 0, externalVars=myexternalVars, extScanModules=scan_modules_list)
    end_time = time.time()

    if attachment_data != None:
        test['attachment'] = encode_file(attachment_data).decode('utf-8')

    if attachment_filename:
        os.remove(attachment_filename)
    test['result'] = json.loads(laikaboss.clientLib.getJSON(result))



    test['config'] = config
    test['ext_metadata'] = ext_metadata
    test['scan_modules'] = scan_modules_orig
    test['data'] = encode_file(data).decode('utf-8')
    test['filename'] = filename
    test['runtime'] = end_time - start_time
    test['errors'] = reset_errorlog()
    # the first file is the one submitted - skip it
    test['files'] = _summarize_scanObjects(result.files)

    if query:
        test['query'] = query
        test['summary'] = json.loads(test["result"]["scan_result"][0]['moduleMetadata']["SUBMIT_STORAGE_META"]["summary"])

        nonsummary = '[' + ",".join(test["result"]["scan_result"][0]['moduleMetadata']["SUBMIT_STORAGE_META"]["nonsummary"]) + ']'
        test['nonsummary'] = json.loads(nonsummary)
        test['query_match'] = run_query(test, query)

    return test

def scan_helper(test, config_path=None):
    '''
    execute specified test but don't grade it 
    
    test: dictionary returned from create_test
    return the executed test
    '''

    if 'attachment' in test:
        attachment_data = decode_file(test['attachment'])
    else:
        attachment_data = None

    current_test = scan(decode_file(test['data']), filename=os.path.basename(test['filename']), scan_modules=test['scan_modules'], ext_metadata=test['ext_metadata'], attachment_data=attachment_data, config=test['config'], config_path=config_path, source=test.get('source', ""), query=test.get("query", ""))

    return current_test
