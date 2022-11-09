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
# Sandia National Labs
#
# command line tool for creation and execution of LB module tests
#

from builtins import str
import sys
import os
import argparse
import logging
import json
import uuid
import tempfile
import random
import string

import laikaboss.test

def print_type(label, value):
    sys.stdout.write("label:" + str(label))
    if isinstance(value, dict):
        sys.stdout.write(":dict:")
        for key, val in value.items():
            print_type(key, val)

    elif isinstance(value, list):
        sys.stdout.write(":list:")
        for index, val in enumerate(value):
            print_type(str(index), val)

    else:
        sys.stdout.write(str(type(value)) + ":" + str(value) + "\n")

def main():
       
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter, description="""LaikaBOSS module test tool. 
    By default test cases are executed. Test cases consist of a sample and module(s) to run with arguments. 
    The scan result is compared against subsequent executions, differences resulting in test case failure. 
    The sample, parameters, and output is stored in a .lbtest file.
    
    """)

    parser.add_argument('files', nargs='*', help="files (test sample or test cases or test case dir)")
    
    
    
    parser.add_argument("-m", "--module",
                      action="store", type=str,
                      dest="scan_modules",
                      help="Specify individual module(s) to run and their arguments. If multiple, must be a space-separated list.",
                      default="")
    parser.add_argument("--edit",
                      action="store_true",
                      dest="edit",
                      help="Edit an existing test case in a temp directory",
                      default=False
                      )
    parser.add_argument("-c", "--create",
                      action="store_true",
                      dest="create",
                      help="create new test case. files indicates an input sample",
                      default=False
                      )
    parser.add_argument("-r", "--refresh",
                      action="store_true",
                      dest="refresh",
                      help="update test results, possibly overriding parameters",
                      default=False
                      )                      

    parser.add_argument("-d", "--dump",
                      action="store_true",
                      dest="dump",
                      help="dump scan results",
                      default=False
                      )

    parser.add_argument("-v", "--debug",
                      action="store_true",
                      dest="debug",
                      help="print debug to stderr",
                      default=False
                      )                            
                      
    parser.add_argument("-f", "--flatten",
                      action="store_true",
                      dest="flatten",
                      help="filter and flatten dumped scan results, aids in testing ignore pattern - it assumed --debug:  you must use the same syntax as create - hint you can get the previous create syntax from an existing test using --edit",
                      default=False
                      )
                      
    parser.add_argument("-n", "--name",
                      action="store", type=str,
                      dest="name",
                      help="name for new test case, if not specified, automatically generated",
                      default=""
                      )                      
    parser.add_argument("-s", "--source",
                      action="store", type=str,
                      dest="source",
                      help="source for new test case",
                      default=""
                      )                      
    
    parser.add_argument("-o", "--outdir",
                      action="store", type=str,
                      dest="outdir",
                      help="output directory for new test cases",
                      default=os.getcwd()
                      )
    
    parser.add_argument("-i", "--ignore-pattern",
                      action="store", type=str,
                      dest="ignore_pattern",
                      help="regular expression which is applied to field names of results to identify fields that should be ignored. Field names are in jq format with all strings quoted. Tip use the --flatten command help on how to see the intermediate fields and fieldnames - you may wish to ignore",
                      default=laikaboss.test.IGNORE_PATTERN
                      )
  
    parser.add_argument("--external-metadata",
                      action="store",
                      dest="ext_metadata",
                      help="Define metadata to add to the scan or specify a file containing the metadata.",
                      default="{}")
    parser.add_argument("--query",
                      action="store",
                      dest="query",
                      help="query of result metadata instead of match",
                      default="")
    
    parser.add_argument("--config-file",
                      action="store", type=str,
                      dest="config_path",
                      help="path to config file to override default testing minimal config. Recommend against use as this makes test cases less portable: config files aren't store in test case",
                      default="")
    parser.add_argument("-C","--config",
                      action="store", type=str,
                      dest="config",
                      help="JSON encoded dictionary of global configuration items",
                      default="{}")
    parser.add_argument("-t","--comment",
                      action="store", type=str,
                      dest="comment",
                      help="optional comment stored with test case",
                      default="")
    parser.add_argument("--extract-samples",
                      action="store_true",
                      dest="extract",
                      help="extract sample(s) from test cases",
                      default=False
                      )
    parser.add_argument("-H","--hash",
                      action="store_true",
                      dest="hash_filename",
                      help="use sha256 of file as filename",
                      default=False
                      )
    parser.add_argument("-E","--error-validation",
                      action="store", type=int,
                      dest="error_validation",
                      help="level of validation to perform on module errors: 0 is disabled, 1 is count, 2 is body",
                      default=laikaboss.test.ERROR_VALIDATION
                      )
    parser.add_argument("-R","--runtime-validation",
                      action="store", type=float,
                      dest="runtime_validation",
                      help="runtime difference ratio to allow, 0 to disable. Ex. 3: if runtime < 1/3 or > 3x of stored runtime, fail ",
                      default=laikaboss.test.RUNTIME_VALIDATION
                      )
    parser.add_argument("-a","--attachment",
                      action="store", type=str,
                      dest="attachment",
                      help="file to load as attachment which is stored with test, available in module arguments as LBTEST_ATTACHMENT",
                      default="")
    parser.add_argument("-A","--extract-attachment",
                      action="store_true",
                      dest="extract_attachment",
                      help="extract an attachment from the test saving it on disk",
                      default=False)
    parser.add_argument("-I", "--ignore-list-ordering",
                      action="store_true",
                      dest="ignore_list_ordering",
                      help="ignore the ordering of lists when computing test results",
                      default=False)
    parser.add_argument("-l","--list",
                      action="store_true",
                      dest="list",
                      help="list test cases",
                      default=False)
                      
                      
    options = parser.parse_args()
    
    logger = logging.getLogger()

    name = options.name
    
    if options.debug:
        stderr_handler = logging.StreamHandler(sys.stderr)
        stderr_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
        stderr_handler.setFormatter(formatter)
        logger.addHandler(stderr_handler)
        logger.setLevel(logging.DEBUG)
        fileHandler = logging.FileHandler('laikatest-debug.log', 'w')
        fileHandler.setFormatter(formatter)
        logger.addHandler(fileHandler)
    
    try:
       os.mkdir(options.outdir)
    except FileExistsError:
       pass
    
    if os.path.exists(options.ext_metadata):
        with open(options.ext_metadata) as metafile:
            ext_metadata = json.loads(metafile.read())
    else:
        ext_metadata = json.loads(options.ext_metadata)
    
    if options.attachment:
        with open(options.attachment, "rb") as f:
            attachment_data = f.read()
    else:
        attachment_data = None
    
    if options.query:
       options.query = json.loads(options.query)

    #setup config
    config = json.loads(options.config)

    if options.flatten:
        options.dump = True
        
    if options.dump:
        for file in laikaboss.test.list_files(options.files):
            with open (file, "rb") as f:
                data = f.read()
            if options.hash_filename:
                filename = hashlib.sha256(data).hexdigest()
            else:
                filename = os.path.basename(file)
                
            test = laikaboss.test.create_test(data, filename=filename, scan_modules=options.scan_modules, ext_metadata=ext_metadata, attachment_data=attachment_data, config_path=options.config_path, config=config, ignore_pattern=options.ignore_pattern, comment=options.comment, ignore_list_ordering=options.ignore_list_ordering, source=options.source, query=options.query)
            if options.flatten:
                flat_result = dict(laikaboss.test.filter_items(laikaboss.test.flatten(test['result']), options.ignore_pattern))
                for key in sorted(flat_result):
                    laikaboss.test.print_stdout(u"%s: %s" % (key,flat_result[key]))
            else:
                laikaboss.test.print_stdout(json.dumps(test['result']))
            for error in test['errors']:
                laikaboss.test.print_stderr(error)
        return 0
    elif options.create:
        test_cases = []
        error_count = 0        
        found = True
        if options.files:
           found = False
                
        for file in laikaboss.test.list_files(options.files):
            found = True
            with open (file, "rb") as f:
                data = f.read()
            if options.hash_filename:
                filename = hashlib.sha256(data).hexdigest()
            else:
                filename = os.path.basename(file)
            
            name = options.name
            if not name:
                if options.scan_modules:
                    name = options.scan_modules.split()[0].split("(")[0].strip() + "-" + str(uuid.uuid4())[0:8]
                else:
                    name = str(uuid.uuid4())[0:8]
             

            test = laikaboss.test.create_test(data, filename=filename, scan_modules=options.scan_modules, ext_metadata=ext_metadata, attachment_data=attachment_data, config_path=options.config_path, config=config, ignore_pattern=options.ignore_pattern, comment=options.comment, name=name, error_validation=options.error_validation, runtime_validation=options.runtime_validation, ignore_list_ordering=options.ignore_list_ordering, source=options.source, query=options.query)

            if 'errors' in test:
                error_count = error_count + len(test['errors'])
                for error in test['errors']:
                    laikaboss.test.print_stderr(error)
            
            test_cases.append(test)
       
        if not found:
           laikaboss.test.print_stderr("Input files could not be located on filesystem. exit 1")
           return 1

        outfilename = os.path.join(options.outdir, name + "." + laikaboss.test.LBTEST_EXTENSION)
        #print_type("test_cases", test_cases)
        with open(outfilename, "w") as f:
            json.dump(test_cases, f, sort_keys=True, indent=4, separators=(',', ': '))
        
        laikaboss.test.print_stdout(outfilename)
        
        if error_count:
            laikaboss.test.print_stderr("Warning: %i errors" % (error_count))
        return error_count
        
    elif options.refresh:
        error_count = 0
        
        for file in laikaboss.test.list_files(options.files, recursive=True):
            test_cases = []
            with open(file, "r") as f:
                tests = json.load(f)
            for test in tests:
        
                local_data = laikaboss.test.decode_file(test['data'])
                local_filename = test['filename']
                if options.hash_filename:
                    local_filename = hashlib.sha256(data).hexdigest()
                local_name = test['name'].rsplit("-",1)[0]
                if options.name:
                    local_name = options.name
                local_scan_modules = test['scan_modules']
                if options.scan_modules:
                    local_scan_modules = options.scan_modules
                local_ext_metadata = test['ext_metadata']
                if ext_metadata:
                    local_ext_metadata = ext_metadata                
                local_attachment_data = None
                if 'attachment' in test:
                    local_attachment_data = laikaboss.test.decode_file(test['attachment'])
                #override attachment_data?
                local_config = test['config']
                if config:
                    local_config = config
                local_comment = test['comment']
                if options.comment:
                    local_comment = options.comment
                #can only change options with default if options is set to non-default value (can't reset back to default)
                local_ignore_pattern = test['ignore_pattern']
                if options.ignore_pattern != laikaboss.test.IGNORE_PATTERN:
                    local_ignore_pattern = options.ignore_pattern
                error_validation = laikaboss.test.ERROR_VALIDATION
                if 'error_validation' in test:
                    error_validation = test['error_validation']
                if options.error_validation != laikaboss.test.ERROR_VALIDATION:
                    error_validation = options.error_validation
                runtime_validation = laikaboss.test.RUNTIME_VALIDATION
                if 'runtime_validation' in test:
                    runtime_validation = test['runtime_validation']
                if options.runtime_validation != laikaboss.test.RUNTIME_VALIDATION:
                    runtime_validation = options.runtime_validation
                
                test = laikaboss.test.create_test(local_data, filename=local_filename, scan_modules=local_scan_modules, ext_metadata=local_ext_metadata, attachment_data=local_attachment_data, config_path=options.config_path, config=local_config, ignore_pattern=local_ignore_pattern, comment=local_comment, name=local_name, runtime_validation=runtime_validation, error_validation=error_validation, ignore_list_ordering=options.ignore_list_ordering, source=options.source, query=options.query)

                if 'errors' in test:
                    error_count = error_count + len(test['errors'])
                    for error in test['errors']:
                        laikaboss.test.print_stderr(error)
            
                test_cases.append(test)

            if len(tests) > 1: 
               laikaboss.test.print_stderr("Warning multiple tests in a single file splits files into multiple files on refresh - and isn't supported")
               sys.exit(1)
            else:
               outfilename = os.path.join(options.outdir, os.path.basename(file))

            with open(outfilename, "w") as f:
                json.dump(test_cases, f, sort_keys=True, indent=4, separators=(',', ': '))
            laikaboss.test.print_stdout(outfilename)
        
        if error_count:
            laikaboss.test.print_stderr("Warning: %i errors" % (error_count))
        return error_count
    elif options.edit:
        files = options.files
        if not files:
            files = ["."]

        extract_prefix = ''.join(random.choice(string.ascii_letters) for x in range(8))
        
        for file in laikaboss.test.list_files(files, recursive=True):

            with open(file, "rb") as f:
                tests = json.load(f)

            short_filename =  file.rsplit(os.path.sep, 1)[-1]

            for test in tests:
                dirpath = tempfile.mkdtemp(prefix=('tests-' + extract_prefix + '-' + short_filename), dir=options.outdir)
                local_scan_modules = test['scan_modules']
                command = os.path.realpath(__file__) + " -c -m '" + local_scan_modules + "'"

                if 'filename' in test:
                    outfilename = os.path.join(dirpath, test['filename'])
                    with open(outfilename, "wb") as f:
                        f.write(laikaboss.test.decode_file(test['data']))

                if 'attachment' in test:
                    data = laikaboss.test.decode_file(test['attachment'])
                    outfilename = os.path.join(dirpath, "LBTEST_ATTACHMENT")
                    with open(outfilename, "wb") as f:
                        f.write(data)
                        command = command + " -a LBTEST_ATTACHMENT"

                if 'ignore_pattern' in test and test["ignore_pattern"] != laikaboss.test.IGNORE_PATTERN:
                    command = command + " -i '" + test['ignore_pattern'] + "'"

                if 'external_metadata' in test and test["external_metadata"]:
                    command = command + " --external-metadata '" + test['external_metadata'] + "'"

                if 'config_file' in test and test["config_file"]:
                    command = command + " --config-file '" + test['config_file'] + "'"

                if 'error_validation' in test and test["error_validation"]!=laikaboss.test.ERROR_VALIDATION:
                    command = command + " -E '" + str(test['error_validation']) + "'"

                if 'runtime_validation' in test and test["runtime_validation"] != laikaboss.test.RUNTIME_VALIDATION:
                    command = command + " -R '" + str(test['runtime_validation']) + "'"

                if 'comment' in test and test["comment"]:
                    command = command + " -t '" + test['comment'] + "'"

                if 'name' in test and test["name"]:
                    command = command + " -n '" + test['name'] + "'"
                    command = command + " -o '" + dirpath + "'"

                if 'filename' in test:
                    command = command + " '" + test['filename'] + "'"

                laikaboss.test.print_stdout("\nTo recreate this this test:\n\n1) cd into "+ dirpath + "\n2) run command\n   " + command )

        return 0
        
         
    elif options.extract:
        files = options.files
        if not files:
            files = ["."]
        
        for file in laikaboss.test.list_files(files, recursive=True):
            with open(file, "rb") as f:
                tests = json.load(f)
            
            for test in tests:
                if 'filename' in test:
                    outfilename = os.path.join(options.outdir, os.path.abspath(file).replace(os.sep, '%') + "_" + test['filename'])
                    with open(outfilename, "wb") as f:
                        f.write(laikaboss.test.decode_file(test['data']))
                    laikaboss.test.print_stdout(outfilename)
        return 0
        
    elif options.extract_attachment:
        files = options.files
        if not files:
            files = ["."]
        
        for file in laikaboss.test.list_files(files, recursive=True):
            with open(file, "rb") as f:
                tests = json.load(f)
            
            for test in tests:
                if 'attachment' in test:
                    data = laikaboss.test.decode_file(test['attachment'])
                    outfilename = os.path.join(options.outdir, os.path.abspath(file).replace(os.sep, '%') + "_" + "LBTEST_ATTACHMENT-" + test['name'] )
                    with open(outfilename, "wb") as f:
                        f.write(data)
                    laikaboss.test.print_stdout(outfilename)
        return 0
        
    elif options.list:
        files = options.files
        if not files:
            files = ["."]
        for file in laikaboss.test.list_files(files, recursive=True):
            with open(file, "rb") as f:
                tests = json.load(f)
            
            for test in tests:
                listing = {}
                listing['testfile'] = file
                listing['name'] = test['name']
                listing['config'] = test['config']
                listing['ext_metadata'] = test['ext_metadata']
                listing['scan_modules'] = test['scan_modules']
                listing['filename'] = test['filename']
                listing['comment'] = test['comment']
                if 'attachment' in test:
                    listing['attachment'] = True
                else:
                    listing['attachment'] = False
                laikaboss.test.print_stdout("\t".join([listing['name'], listing['scan_modules'], listing['comment']]))
        return 0        

    else:
        #default is run tests
        tests_passed = 0
        tests_failed = 0
        
        files = options.files
        if not files:
            files = ["."]

        return laikaboss.test.execute_tests(files, config_path=options.config_path)


if __name__ == "__main__":
    sys.exit(main())
