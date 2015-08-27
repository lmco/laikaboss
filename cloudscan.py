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
#
#  Copyright Lockheed Martin 2015
#
#  A networked client for the laikaboss framework.
#  Must have an instance of laikad running locally or on a server
#  accessible by this client over ssh.
#  
#  This client is based on the ZeroMQ Lazy Pirate pattern
#

from multiprocessing import Process, Queue
import os, sys, time, logging, select
import getpass
from socket import gethostname
from optparse import OptionParser
import ConfigParser
import zlib, cPickle as pickle
from laikaboss.objectmodel import ExternalObject, ExternalVars
from laikaboss.constants import level_minimal, level_metadata, level_full
from laikaboss.clientLib import Client, getRootObject, get_scanObjectUID, \
                              getJSON
from random import randint
import json
from copy import deepcopy as clone_object
from distutils.util import strtobool

job_queue = Queue()
result_queue = Queue()
failed_queue = Queue()

# Variable to store configs from file
configs = {}

# Defaults for all available configurations
# To be used if not specified on command line or config file
default_configs = {
    'use_ssh': 'False',
    'broker_host': 'tcp://localhost:5558',
    'ssh_host': 'localhost',
    'request_timeout': '600000',
    'request_retries': '1',
    'return_level': 'metadata',
    'num_procs': '8',
}


def getConfig(option):
    value = ''
    if option in configs:
        value = configs[option]
    else:
        value = default_configs[option]
    return value

def main():

    parser = OptionParser(usage="usage: %prog [options] (/path/to/file | stdin)")
    parser.add_option("-d", "--debug",
                      action="store_true",
                      dest="debug",
                      help="enable debug messages to the console.")
    parser.add_option("-r", "--remove-limit",
                      action="store_true",
                      dest="nolimit",
                      help="disable 20mb size limit (be careful!)")
    parser.add_option("-t", "--timeout",
                      action="store", type="int",
                      dest="timeout",
                      help="adjust request timeout period (in seconds)")
    parser.add_option("-c", "--config-path",
                      action="store", type="string",
                      dest="config_path",
                      help="specify a path to si-cloudscan.conf.")
    parser.add_option("-a", "--address",
                      action="store", type="string",
                      dest="broker_host",
                      help="specify an IP and port to connect to the broker")
    parser.add_option("-f", "--file-list",
                      action="store", type="string",
                      dest="file_list",
                      help="Specify a list of files to scan")
    parser.add_option("-s", "--ssh-host",
                      action="store", type="string",
                      dest="ssh_host",
                      help="specify a host for the SSH tunnel")
    parser.add_option("-p", "--num-procs",
                      action="store", type="int", default=6,
                      dest="num_procs",
                      help="Specify the number of processors to use for recursion")
    parser.add_option("-u", "--source",
                      action="store", type="string",
                      dest="source",
                      help="specify a custom source")
    parser.add_option("--ssh",
                      action="store_true",
                      default=False,
                      dest="use_ssh",
                      help="Use SSH tunneling")
    parser.add_option("-l", "--level",
                      action="store", type="string",
                      dest="return_level",
                      help="Return Level: minimal, metadata, full [default: metadata]")
    parser.add_option("-o", "--out-path",
                      action="store", type="string",
                      dest="save_path",
                      help="If Return Level Full has been specified, provide a path to "
                            "save the results to [default: current directory]")
    parser.add_option("-b", "--buffer",
                      action="store_true",
                      dest="stdin_buffer",
                      help="Specify to allow a buffer to be collected by stdin.")
    parser.add_option("-e", "--ephID",
                      action="store", type="string",
                      dest="ephID", default="",
                      help="Specify an ephID to send to Laika.")
    parser.add_option("-m", "--ext-metadata",
                      action="store",
                      dest="ext_metadata",
                      help="Specify external metadata to be passed into the scanner.")
    parser.add_option("-z", "--log",
                      action="store_true",
                      dest="log_db",
                      help="Specify to turn on logging results.")
    parser.add_option("-R", "--recursive",
                      action="store_true",
                      default=False,
                      dest="recursive",
                      help="Enable recursive directory scanning. If enabled, all files "
                            "in the specified directory will be scanned. Results will "
                            "be output to si-cloudscan.log in the current directory.")
    (options, args) = parser.parse_args()


    # Define default configuration location
    CONFIG_PATH = "/etc/si-cloudscan/si-cloudscan.conf"

    if options.config_path:
        CONFIG_PATH = options.config_path
    
    Config = ConfigParser.ConfigParser()
    Config.read(CONFIG_PATH)

    # Parse through the config file and append each section to a single dictionary
    global configs
    for section in Config.sections():
        configs.update(dict(Config.items(section)))

    # Set the working path, this will be used for file ouput if another
    # path is not specified
    WORKING_PATH = os.getcwd()

    if options.use_ssh:
        USE_SSH = True
    else: 
        if strtobool(getConfig('use_ssh')):
            USE_SSH = True
        else:
            USE_SSH = False

    if options.ssh_host:
        SSH_HOST = options.ssh_host
    else:
        SSH_HOST = getConfig('ssh_host')
        
    if options.broker_host:
        BROKER_HOST = options.broker_host
    else:
        BROKER_HOST = getConfig('broker_host')
 
    if options.debug:
        logging.basicConfig(level=logging.DEBUG)

    logging.debug("Host: %s" % BROKER_HOST)

    if options.return_level:
        RETURN_LEVEL = options.return_level
    else:
        RETURN_LEVEL = getConfig('return_level')

    if options.source:
        SOURCE = options.source
    else:
        SOURCE = "si-cloudscan"

    if not options.log_db:
        SOURCE += "-nolog"
     
    if options.save_path:
        SAVE_PATH = options.save_path
    else:
        SAVE_PATH = WORKING_PATH
    
    if options.num_procs:
        num_procs = int(options.num_procs)
    else:
        num_procs = int(getConfig('num_procs'))

    if options.timeout:
        logging.debug("default timeout changed to %i" % options.timeout)
        REQUEST_TIMEOUT = options.timeout * 1000
    else:
        REQUEST_TIMEOUT = int(getConfig('request_timeout'))

    if options.ext_metadata:
        try:
            if os.path.exists(options.ext_metadata):
                with open(options.ext_metadata) as metafile:
                    ext_metadata = json.loads(metafile.read())
            else:
                ext_metadata = json.loads(options.ext_metadata)
            assert isinstance(ext_metadata, dict)
        except:
            print "External Metadata must be a dictionary!"
            sys.exit(0)
    else:
        ext_metadata = dict()

    REQUEST_RETRIES = int(getConfig('request_retries'))
    
    # Attempt to get the hostname
    try:
        hostname = gethostname().split('.')[0] 
    except:
        hostname = "none"

    
    # Attempt to set the return level, throw an error if it doesn't exist.
    try:
        return_level = globals()["level_%s" % RETURN_LEVEL]
    except KeyError as e:
        print "Please specify a valid return level: minimal, metadata or full"
        sys.exit(1)

    if not options.recursive:
        try:
            file_buffer = ''
            # Try to read the file

            if len(args) > 0:
                file_buffer = open(args[0], 'rb').read()
                file_len = len(file_buffer)
                logging.debug("opened file %s with len %i" % (args[0], file_len))
            else:
                while sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
                    line = sys.stdin.readline()
                    if not line:
                        break
                    else:
                        file_buffer += line

                if not file_buffer:
                    parser.print_usage()
                    sys.exit(1)
                
                file_len = len(file_buffer)

            if file_len > 20971520 and not options.nolimit:
                print "You're trying to scan a file larger than 20mb.. Are you sure?"
                print "Use the --remove-limit flag if you really want to do this."
                sys.exit(1)
        except IOError as e:
            print "\nERROR: The file does not exist: %s\n" % (args[0],)
            sys.exit(1)
    else:
        try:
            fileList = []
            if options.file_list:
                fileList = open(options.file_list).read().splitlines()
            else:
                if len(args) > 0:
                    rootdir = args[0]
                    for root, subFolders, files in os.walk(rootdir):
                        for fname in files:
                            fileList.append(os.path.join(root, fname))
                else:
                    while sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
                        line = sys.stdin.readline()
                        if not line:
                            break
                        else:
                            fileList.append(line)
                    if not fileList:
                        parser.print_usage()
                        sys.exit(1)

            
            if len(fileList) > 1000 and not options.nolimit:
                print "You're trying to scan over 1000 files... Are you sure?"
                print "Use the --remove-limit flag if you really want to do this."
                sys.exit(1)

        except IOError as e:
            print "\nERROR: Directory does not exist: %s\n" % (args[0],)
            sys.exit(1)


   
    if not options.recursive: 
        # Construct the object to be sent for scanning
        if args:
            filename = args[0]
        else:
            filename = "stdin"

        ext_metadata['server'] = hostname
        ext_metadata['user'] = getpass.getuser()
        externalObject = ExternalObject(buffer=file_buffer, 
                                        externalVars=ExternalVars(filename=filename, 
                                                                  ephID=options.ephID,
                                                                  extMetaData=ext_metadata,
                                                                  source="%s-%s-%s" % (SOURCE,
                                                                         hostname,
                                                                         getpass.getuser())),
                                        level=return_level)
    try:
        if not options.recursive:
            # Set up ZMQ context 
            if USE_SSH:
                try:
                    logging.debug("attempting to connect to broker at %s and SSH host %s" % (BROKER_HOST, SSH_HOST))
                    client = Client(BROKER_HOST, useSSH=True, sshHost=SSH_HOST, useGevent=True)
                except RuntimeError as e:
                    logging.exception("could not set up SSH tunnel to %s" % SSH_HOST)
                    sys.exit(1)
            else:
                logging.debug("SSH has been disabled.")
                client = Client(BROKER_HOST, useGevent=True)

            starttime = time.time()
            result = client.send(externalObject, retry=REQUEST_RETRIES, timeout=REQUEST_TIMEOUT)
            logging.debug("got reply in %s seconds" % str(time.time() - starttime))
            rootObject = getRootObject(result)
            try:
                jsonResult = getJSON(result)
                print jsonResult
            except:
                logging.exception("error occured collecting results")
                return
            if return_level == level_full:
                SAVE_PATH = "%s/%s" % (SAVE_PATH, get_scanObjectUID(rootObject))
                if not os.path.exists(SAVE_PATH):
                    try:
                        os.makedirs(SAVE_PATH)
                        print "\nWriting results to %s...\n" % SAVE_PATH
                    except (OSError, IOError) as e:
                        print "\nERROR: unable to write to %s...\n" % SAVE_PATH
                        return
                else:
                    print "\nOutput folder already exists! Skipping results output...\n"
                    return
                for uid, scanObject in result.files.iteritems():
                    f = open("%s/%s" % (SAVE_PATH, uid), "wb")
                    f.write(scanObject.buffer)
                    f.close()
                    try:
                        if scanObject.filename and scanObject.parent:
                            linkPath = "%s/%s" % (SAVE_PATH, scanObject.filename.replace("/","_"))
                            if not os.path.lexists(linkPath):
                                os.symlink("%s" % (uid), linkPath)
                        elif scanObject.filename:
                            filenameParts = scanObject.filename.split("/")
                            os.symlink("%s" % (uid), "%s/%s" % (SAVE_PATH, filenameParts[-1]))
                    except:
                        print "Unable to create symlink for %s" % (uid)

                f = open("%s/%s" % (SAVE_PATH, "results.log"), "wb")
                f.write(jsonResult)
                f.close()
                sys.exit(1)
        else:
            try:
                fh = open('si-cloudscan.log', 'w')
                fh.close()
            except:
                pass

            for fname in fileList:
                job_queue.put(fname)

            for i in range(num_procs):
                job_queue.put("STOP")

            print "File list length: %s" % len(fileList)

            for i in range(num_procs):
                Process(target=worker, args=(options.nolimit, REQUEST_RETRIES, REQUEST_TIMEOUT, SAVE_PATH, SOURCE, return_level, hostname, USE_SSH, BROKER_HOST, SSH_HOST,ext_metadata,options.ephID,)).start()
   
            results_processed = 0
            while results_processed < len(fileList):
                logging.debug("Files left: %s" % ((len(fileList) - results_processed)))
                resultText = result_queue.get()
                try:
                    # Process results
                    fh = open('si-cloudscan.log', 'ab')
                    fh.write('%s\n' % resultText)
                    fh.close()
                    results_processed += 1
                except Exception as e:
                    raise

            print 'Wrote results to si-cloudscan.log'

    except KeyboardInterrupt:
        print "Interrupted by user, exiting..."
        sys.exit(1)

def worker(nolimit, REQUEST_RETRIES, REQUEST_TIMEOUT, SAVE_PATH, SOURCE, return_level, hostname, USE_SSH, BROKER_HOST, SSH_HOST, ext_metadata, ephID):
    # Set up ZMQ context 
    if USE_SSH:
        try:
            logging.debug("attempting to connect to broker at %s and SSH host %s" % (BROKER_HOST, SSH_HOST))
            client = Client(BROKER_HOST, useSSH=True, sshHost=SSH_HOST)
        except RuntimeError as e:
            logging.exception("could not set up SSH tunnel to %s" % SSH_HOST)
            sys.exit(1)
    else:
        logging.debug("SSH has been disabled.")
        client = Client(BROKER_HOST)

    
    randNum = randint(1, 10000)
    
    for fname in iter(job_queue.get, 'STOP'):
        print "Worker %s: Starting new request" % randNum
        try:
            # Try to read the file
            file_buffer = open(fname, 'rb').read()
            file_len = len(file_buffer)
            logging.debug("opened file %s with len %i" % (fname, file_len))
            if file_len > 20971520 and not nolimit:
                print "You're trying to scan a file larger than 20mb.. Are you sure?"
                print "Use the --remove-limit flag if you really want to do this."
                print "File has not been scanned: %s" % fname
                result_queue.put("~~~~~~~~~~~~~~~~~~~~\nFile has not been scanned due to size: %s\n~~~~~~~~~~~~~~~~~~~~" % fname)
                continue
        except IOError as e:
            print "\nERROR: The file does not exist: %s\n" % (fname,)
            print "Moving to next file..."
            result_queue.put("~~~~~~~~~~~~~~~~~~~~\nFile has not been scanned due to an IO Error: %s\n~~~~~~~~~~~~~~~~~~~~" % fname)
            continue

        try:
            # Construct the object to be sent for scanning
            externalObject = ExternalObject(buffer=file_buffer,
                                            externalVars=ExternalVars(filename=fname,
                                                                      ephID=ephID,
                                                                      extMetaData=ext_metadata,
                                                                      source="%s-%s-%s" % (SOURCE,
                                                                                           hostname,
                                                                                           getpass.getuser())),
                                        level=return_level)

            starttime = time.time()
            result = client.send(externalObject, retry=REQUEST_RETRIES, timeout=REQUEST_TIMEOUT)
            if not result:
                result_queue.put("~~~~~~~~~~~~~~~~~~~~\nFile timed out in the scanner: %s\n~~~~~~~~~~~~~~~~~~~~" % fname)
                continue

            logging.debug("got reply in %s seconds" % str(time.time() - starttime))
            rootObject = getRootObject(result)

            jsonResult = getJSON(result)
            resultText = '%s\n' % jsonResult

            if return_level == level_full:
                FILE_SAVE_PATH = "%s/%s" % (SAVE_PATH, get_scanObjectUID(rootObject))
                if not os.path.exists(FILE_SAVE_PATH):
                    try:
                        os.makedirs(FILE_SAVE_PATH)
                        print "Writing results to %s..." % FILE_SAVE_PATH
                    except (OSError, IOError) as e:
                        print "\nERROR: unable to write to %s...\n" % FILE_SAVE_PATH
                        return
                else:
                    print "\nOutput folder already exists! Skipping results output...\n"
                    return
                for uid, scanObject in result.files.iteritems():
                    f = open("%s/%s" % (FILE_SAVE_PATH, uid), "wb")
                    f.write(scanObject.buffer)
                    f.close()
                    if scanObject.filename and scanObject.depth != 0:
                        linkPath = "%s/%s" % (FILE_SAVE_PATH, scanObject.filename.replace("/","_"))
                        if not os.path.lexists(linkPath):
                            os.symlink("%s" % (uid), linkPath)
                    elif scanObject.filename:
                        filenameParts = scanObject.filename.split("/")
                        linkPath = "%s/%s" % (FILE_SAVE_PATH, filenameParts[-1])
                        if not os.path.lexists(linkPath):
                            os.symlink("%s" % (uid), linkPath)
                f = open("%s/%s" % (FILE_SAVE_PATH, "results.json"), "wb")
                f.write(jsonResult)
                f.close()
            
            result_queue.put(resultText)
        except:
            #logging.exception("error occured collecting results")
            result_queue.put("~~~~~~~~~~~~~~~~~~~~\nUNKNOWN ERROR OCCURRED: %s\n~~~~~~~~~~~~~~~~~~~~" % fname)
            continue

if __name__ == "__main__":
    main()
