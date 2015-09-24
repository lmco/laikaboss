#!/usr/bin/python
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
from __future__ import print_function

import sys, traceback
import os
import multiprocessing
from optparse import OptionParser
import logging, time
from laikaboss.objectmodel import ExternalVars, ScanResult
from laikaboss.constants import level_minimal, level_metadata, level_full
from laikaboss.dispatch import Dispatch, close_modules
from laikaboss import config
from laikaboss.util import init_yara, init_logging, log_result
from laikaboss.clientLib import getJSON, getRootObject, get_scanObjectUID
from ast import literal_eval
from distutils.util import strtobool
import zlib
import json


# Variable to store configs from file
configs = {}

# Defaults for all available configurations
# To be used if not specified on command line or config file
default_configs = {
    'num_procs' : '8',
    'max_bytes' : '10485760',
    'max_files' : '0',
    'progress_bar' : 'true',
    'save_path' : '',
    'scan_modules' : None,
    'source' : 'CLI',
    'ext_metadata' : {},
    'log_result' : 'false',
    'log_json' : '',
    'ephID' : '',
    'dev_config_path' : 'etc/framework/laikaboss.conf',
    'sys_config_path' : '/usr/local/laikaboss/etc/laikaboss.conf'
}

def warning(*objs):
    print("WARNING: ", *objs, file=sys.stderr)

def error(*objs):
    print("ERROR: ", *objs, file=sys.stderr)

def getConfig(option):
    value = ''
    if option in configs:
        value = configs[option]
    else:
        value = default_configs[option]
    return value

def main():
    # Define default configuration location

    parser = OptionParser(usage="usage: %prog [options] /path/to/file")
    parser.add_option("-d", "--debug",
                      action="store_true",
                      dest="debug",
                      help="enable debug messages to the console.")
    parser.add_option("-c", "--config-path",
                      action="store", type="string",
                      dest="config_path",
                      help="path to configuration for laikaboss framework.")
    parser.add_option("-o", "--out-path",
                      action="store", type="string",
                      dest="save_path",
                      help="Write all results to the specified path")
    parser.add_option("-s", "--source",
                      action="store", type="string",
                      dest="source",
                      help="Set the source (may affect dispatching) [default:laika]")
    parser.add_option("-p", "--num_procs",
                      action="store", type="int",
                      dest="num_procs",
                      default=8,
                      help="Specify the number of CPU's to use for a recursive scan. [default:8]")
    parser.add_option("-l", "--log",
                      action="store_true",
                      dest="log_result",
                      help="enable logging to syslog")
    parser.add_option("-j", "--log-json",
                      action="store", type="string",
                      dest="log_json",
                      help="enable logging JSON results to file")
    parser.add_option("-m", "--module",
                      action="store", type="string",
                      dest="scan_modules",
                      help="Specify individual module(s) to run and their arguments. If multiple, must be a space-separated list.")
    parser.add_option("--parent",
                      action="store", type="string",
                      dest="parent", default="",
                      help="Define the parent of the root object")
    parser.add_option("-e", "--ephID",
                      action="store", type="string",
                      dest="ephID", default="",
                      help="Specify an ephemeralID to send with the object")
    parser.add_option("--metadata",
                      action="store",
                      dest="ext_metadata",
                      help="Define metadata to add to the scan or specify a file containing the metadata.")
    parser.add_option("--size-limit",
                      action="store", type="int", default=10,
                      dest="sizeLimit",
                      help="Specify a size limit in MB (default: 10)")
    parser.add_option("--file-limit",
                      action="store", type="int", default=0,
                      dest="fileLimit",
                      help="Specify a limited number of files to scan (default: off)")
    parser.add_option("--no-progress",
                      action="store_true",
                      dest="no_progress",
                      help="disable the progress bar")
    (options, args) = parser.parse_args()
    
    logger = logging.getLogger()

    if options.debug:
        # stdout is added by default, we'll capture this object here
        #lhStdout = logger.handlers[0]
        fileHandler = logging.FileHandler('laika-debug.log', 'w')
        formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
        fileHandler.setFormatter(formatter)
        logger.addHandler(fileHandler)
        # remove stdout from handlers so that debug info is only written to the file
        #logger.removeHandler(lhStdout)
        logging.basicConfig(level=logging.DEBUG)
        logger.setLevel(logging.DEBUG)

    global EXT_METADATA
    if options.ext_metadata:
        if os.path.exists(options.ext_metadata):
            with open(options.ext_metadata) as metafile:
                EXT_METADATA = json.loads(metafile.read())
        else:
            EXT_METADATA = json.loads(options.ext_metadata)
    else:
        EXT_METADATA = getConfig("ext_metadata")
    
    global EPHID
    if options.ephID:
        EPHID = options.ephID
    else:
        EPHID = getConfig("ephID")

    global SCAN_MODULES
    if options.scan_modules:
        SCAN_MODULES = options.scan_modules.split()
    else:
        SCAN_MODULES = None
    logging.debug("SCAN_MODULES: %s"  % (SCAN_MODULES))

    global PROGRESS_BAR
    if options.no_progress:
        PROGRESS_BAR = 0
    else:
        PROGRESS_BAR = strtobool(getConfig('progress_bar'))
    logging.debug("PROGRESS_BAR: %s"  % (PROGRESS_BAR))

    global LOG_RESULT
    if options.log_result:
        LOG_RESULT = 1
    else:
        LOG_RESULT = strtobool(getConfig('log_result'))
    logging.debug("LOG_RESULT: %s" % (LOG_RESULT))

    global LOG_JSON
    if options.log_json:
        LOG_JSON = options.log_json
    else:
        LOG_JSON = getConfig('log_json')

    global NUM_PROCS
    if options.num_procs:
        NUM_PROCS = options.num_procs
    else:
        NUM_PROCS = int(getConfig('num_procs'))
    logging.debug("NUM_PROCS: %s"  % (NUM_PROCS))

    global MAX_BYTES
    if options.sizeLimit:
        MAX_BYTES = options.sizeLimit * 1024 * 1024
    else:
        MAX_BYTES = int(getConfig('max_bytes'))
    logging.debug("MAX_BYTES: %s"  % (MAX_BYTES))

    global MAX_FILES
    if options.fileLimit:
        MAX_FILES = options.fileLimit
    else:
        MAX_FILES = int(getConfig('max_files'))
    logging.debug("MAX_FILES: %s"  % (MAX_FILES))

    global SOURCE
    if options.source:
        SOURCE = options.source
    else:
        SOURCE = getConfig('source')

    global SAVE_PATH
    if options.save_path:
        SAVE_PATH = options.save_path
    else:
        SAVE_PATH = getConfig('save_path')

    global CONFIG_PATH
    # Highest priority configuration is via argument
    if options.config_path:
        CONFIG_PATH = options.config_path
        logging.debug("using alternative config path: %s" % options.config_path)
        if not os.path.exists(options.config_path):
            error("the provided config path is not valid, exiting")
            return 1
    # Next, check to see if we're in the top level source directory (dev environment)
    elif os.path.exists(default_configs['dev_config_path']):
        CONFIG_PATH = default_configs['dev_config_path']
    # Next, check for an installed copy of the default configuration
    elif os.path.exists(default_configs['sys_config_path']):
        CONFIG_PATH = default_configs['sys_config_path']
    # Exit
    else:
        error('A valid framework configuration was not found in either of the following locations:\
\n%s\n%s' % (default_configs['dev_config_path'],default_configs['sys_config_path']))
        return 1
       

    # Check for stdin in no arguments were provided
    if len(args) == 0:

        DATA_PATH = []

        if not sys.stdin.isatty():
            while True:
                f = sys.stdin.readline().strip()
                if not f:
                    break
                else:
                    if not os.path.isfile(f):
                        error("One of the specified files does not exist: %s" % (f))
                        return 1
                    if os.path.isdir(f):
                        error("One of the files you specified is actually a directory: %s" % (f))
                        return 1
                    DATA_PATH.append(f)

        if not DATA_PATH:
            error("You must provide files via stdin when no arguments are provided")
            return 1
        logging.debug("Loaded %s files from stdin" % (len(DATA_PATH)))
    elif len(args) == 1:
        if os.path.isdir(args[0]):
            DATA_PATH = args[0]
        elif os.path.isfile(args[0]):
            DATA_PATH = [args[0]]
        else:
            error("File or directory does not exist: %s" % (args[0]))
            return 1
    else:
        for f in args:
            if not os.path.isfile(f):
                error("One of the specified files does not exist: %s" % (f))
                return 1
            if os.path.isdir(f):
                error("One of the files you specified is actually a directory: %s" % (f))
                return 1
        
        DATA_PATH = args

   
    tasks = multiprocessing.JoinableQueue()
    results = multiprocessing.Queue()
    
    fileList = []
    if type(DATA_PATH) is str:
        for root, dirs, files in os.walk(DATA_PATH):
            files = [f for f in files if not f[0] == '.']
            dirs[:] = [d for d in dirs if not d[0] == '.']
            for fname in files:
                fullpath = os.path.join(root, fname)
                if not os.path.islink(fullpath) and os.path.isfile(fullpath):
                    fileList.append(fullpath)
    else:
        fileList = DATA_PATH

    if MAX_FILES:
        fileList = fileList[:MAX_FILES]

    num_jobs = len(fileList)
    logging.debug("Loaded %s files for scanning" % (num_jobs))
    
    # Start consumers
    # If there's less files to process than processes, reduce the number of processes
    if num_jobs < NUM_PROCS:
        NUM_PROCS = num_jobs
    logging.debug("Starting %s processes" % (NUM_PROCS))
    consumers = [ Consumer(tasks, results)
                  for i in xrange(NUM_PROCS) ]
    try:
        
        for w in consumers:
            w.start()

        # Enqueue jobs
        for fname in fileList:
            tasks.put(fname)
        
        # Add a poison pill for each consumer
        for i in xrange(NUM_PROCS):
            tasks.put(None)

        if PROGRESS_BAR:
            monitor = QueueMonitor(tasks, num_jobs)
            monitor.start()

        # Wait for all of the tasks to finish
        tasks.join()
        if PROGRESS_BAR:
            monitor.join()

        while num_jobs:
            answer = zlib.decompress(results.get())
            print(answer)
            num_jobs -= 1

    except KeyboardInterrupt:
        error("Cancelled by user.. Shutting down.")
        for w in consumers:
            w.terminate()
            w.join()
        return None
    except:
        raise

class QueueMonitor(multiprocessing.Process):
    def __init__(self, task_queue, task_count):
        multiprocessing.Process.__init__(self)
        self.task_queue = task_queue
        self.task_count = task_count
    def run(self):
        from progressbar import ProgressBar, Bar, Counter, Timer, ETA, Percentage, RotatingMarker
        try:
            widgets = [Percentage(), Bar(left='[', right=']'), ' Processed: ', Counter(), '/', "%s" % self.task_count, ' total files (', Timer(), ') ', ETA()]
            pb = ProgressBar(widgets=widgets, maxval=self.task_count).start()
            while self.task_queue.qsize():
                pb.update(self.task_count - self.task_queue.qsize())
                
                time.sleep(0.5)
            pb.finish()

        except KeyboardInterrupt:
            print("\n")
            return 1

        return 0

class Consumer(multiprocessing.Process):

    def __init__(self, task_queue, result_queue):
        self.task_queue = task_queue
        self.result_queue = result_queue
        multiprocessing.Process.__init__(self)

    def run(self):
        global CONFIG_PATH
        config.init(path=CONFIG_PATH)
        init_logging()
        ret_value = 0

        # Loop and accept messages from both channels, acting accordingly
        while True:
            next_task = self.task_queue.get()
            if next_task is None:
                # Poison pill means shutdown
                self.task_queue.task_done()
                logging.debug("%s Got poison pill" % (os.getpid()))
                break
            try:
                with open(next_task) as nextfile:
                    file_buffer = nextfile.read()
            except IOError:
                logging.debug("Error opening: %s" % (next_task))
                self.task_queue.task_done()
                self.result_queue.put(answer)
                continue

            resultJSON = ""
            try:
                # perform the work
                result = ScanResult()
                result.source = SOURCE 
                result.startTime = time.time()
                result.level = level_metadata
                myexternalVars = ExternalVars(filename=next_task,
                                             source=SOURCE,
                                             ephID=EPHID,
                                             extMetaData=EXT_METADATA)

                Dispatch(file_buffer, result, 0, externalVars=myexternalVars, extScanModules=SCAN_MODULES)

                resultJSON = getJSON(result)
                if SAVE_PATH:
                    rootObject = getRootObject(result)
                    UID_SAVE_PATH = "%s/%s" % (SAVE_PATH, get_scanObjectUID(rootObject))
                    if not os.path.exists(UID_SAVE_PATH):
                        try:
                            os.makedirs(UID_SAVE_PATH)
                        except (OSError, IOError) as e:
                            error("\nERROR: unable to write to %s...\n" % (UID_SAVE_PATH))
                            raise
                    for uid, scanObject in result.files.iteritems():
                        with open("%s/%s" % (UID_SAVE_PATH, uid), "wb") as f:
                            f.write(scanObject.buffer)
                        if scanObject.filename and scanObject.depth != 0:
                            linkPath = "%s/%s" % (UID_SAVE_PATH, scanObject.filename.replace("/","_"))
                            if not os.path.lexists(linkPath):
                                os.symlink("%s" % (uid), linkPath)
                        elif scanObject.filename:
                            filenameParts = scanObject.filename.split("/")
                            os.symlink("%s" % (uid), "%s/%s" % (UID_SAVE_PATH, filenameParts[-1]))
                    with open("%s/%s" % (UID_SAVE_PATH, "result.json"), "wb") as f: 
                        f.write(resultJSON)
                
                if LOG_RESULT:
                    log_result(result)   
                    
                if LOG_JSON:
                    LOCAL_PATH = LOG_JSON
                    with open(LOCAL_PATH, "ab") as f:
                        f.write(resultJSON + "\n")
            except:
                logging.exception("Scan worker died, shutting down")
                ret_value = 1
                break
            finally:
                self.task_queue.task_done()
                self.result_queue.put(zlib.compress(resultJSON))

        close_modules()
        return ret_value


if __name__ == "__main__":
    sys.exit(main())
