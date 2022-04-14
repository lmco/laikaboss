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
Delayed submit to storage daemon for things that don't make it to storage on first pass through SUBMIT_STORAGE module. Uses Watchdog to monitor a given directory for any new files to submit to storage.

Dependencies: watchdog (0.8.3) (API: http://pythonhosted.org/watchdog/api.html#module-watchdog.observers.api)

Sandia National Labs
"""

from future import standard_library
standard_library.install_aliases()
from builtins import str
from multiprocessing import Process, JoinableQueue
from optparse import OptionParser
from laikaboss.lbconfigparser import LBConfigParser
import logging
import sys
import time
import os
import requests
import json
import base64

from laikaboss.extras.extra_util import id_lookup_details, storage_server_lookup_from_name
from laikaboss.storage_utils import write_to_minio, generate_minio_handlers
from laikaboss import config
from laikaboss.util import get_option

# Third-party library imports
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler

""" CONFIG SETTINGS """
CONFIGS = {"storage_queue_dir":"/var/laikaboss/storage-queue",
          "storage_failed_dir":"/var/laikaboss/storage-error"
          }

""" Global Queues """
job_queue = JoinableQueue()  # Thread-safe queue to tell workers what files need to be processed

# Watchdog handler to observe for file changes in designated directory
class NewFileHandler(PatternMatchingEventHandler):
    def process(self, event):

        logging.debug("Event Src (%s), Event Type (%s)" % (event.src_path, event.event_type))

        # Only add to job queue if this is a file (not a directory) and has right extension
        if os.path.isfile(event.src_path) and event.src_path.endswith(".submit"):
            job_queue.put(event.src_path)

    # We only care about when new files are created or moved
    def on_created(self, event):
        self.process(event)

    def on_moved(self, event):
        self.process(event)

# Checks that required arguments have been specified
def check_required_args():
    global CONFIGS

    # TODO
    required = []
    missing = []

    for param in required:
        if param not in CONFIGS:
            missing.append(param)

    # TODO: Check that directories exist and are writable?

    if missing:
        logging.error("Missing required params: %s" % (", ".join(missing)))
        sys.exit(3)


# Parse options from config file and from commandline
def parse_opts():
    global CONFIGS

    parser = OptionParser(
        usage="%prog [options] [files ...]\n\nIf [files ...] is given, process just those files. Otherwise, process files in the directory given by the config file at -c or through -f.",
        version="%prog 1.0",
    )
    parser.add_option(
        "-d",
        "--debug",
        action="store_true",
        dest="debug",
        help="enable debugging messages to the console",
    )
    parser.add_option(
        "-c",
        "--config-path",
        action="store",
        type="string",
        dest="config_path",
        help="specify path to submit storage config file",
    )
    parser.add_option(
        "-l",
        "--laika-config-path",
        action="store",
        type="string",
        dest="laika_config_path",
        help="specify path to the laikaboss configuration file",
    )
    parser.add_option(
        "-n",
        "--num-workers",
        action="store",
        type="int",
        dest="num_workers",
        help="specify the number of workers to use",
    )
    parser.add_option(
        "-i",
        "--storage-queue-dir",
        action="store",
        type="string",
        dest="storage_queue_dir",
        help="specify an input directory of files",
    )
    parser.add_option(
        "-f",
        "--storage-failed-dir",
        action="store",
        type="string",
        dest="storage_failed_dir",
        help="specify a directory to place files which have failed to submit after num_retries retries",
    )
    parser.add_option(
        "-s",
        "--seconds-delay",
        action="store",
        type="int",
        dest="seconds_delay",
        help="specify the delay between failed submissions",
    )
    parser.add_option(
        "-r",
        "--retries",
        action="store",
        type="int",
        dest="num_retries",
        help="specify the number of retries per file",
    )

    (options, args) = parser.parse_args()

    if options.debug:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s - %(levelname)s - PID: %(process)d - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S%Z"
        )

    LAIKA_CONFIG_PATH = "/etc/laikaboss/laikaboss.conf"
    CONFIG_PATH = "/etc/laikaboss/submitstorage.conf"
    MINIOSECRETFILE = "/etc/laikaboss/secrets/s3_secret_key"
    MINIOACCESSFILE = "/etc/laikaboss/secrets/s3_access_key"

    # CONFIG_PATH = "etc/submitstorage/submitstorage.conf" # TESTING PURPOSES ONLY

    if options.config_path:
        CONFIG_PATH = options.config_path

    if options.laika_config_path:
        LAIKA_CONFIG_PATH = options.laika_config_path

    Config = LBConfigParser()
    # Parse Laikaboss config
    config.init(path=LAIKA_CONFIG_PATH)

    # LBConfig = ConfigParser.ConfigParser()
    if LAIKA_CONFIG_PATH not in Config.read([LAIKA_CONFIG_PATH, CONFIG_PATH]):
        logging.error("Error reading config file. Please specify a config file.")
        sys.exit(1)

    CONFIGS["storage_url"] = str(get_option(args, "url", "storage_url", None))
    if CONFIGS["storage_url"] == None:
        logging.error("The storage url was not set in the Laikaboss config.")
        sys.exit(1)

    d = dict(Config.items("submitstorage"))
    for key in d:
        if key in ["num_workers", "seconds_delay", "num_retries"]:
           CONFIGS[key] = int(d[key])
        else:
           CONFIGS[key] = d[key]

    if options.num_workers:
        CONFIGS["num_workers"] = int(options.num_workers)

    if options.storage_queue_dir:
        CONFIGS["storage_queue_dir"] = options.storage_queue_dir

    if options.seconds_delay:
        CONFIGS["seconds_delay"] = options.seconds_delay
    elif "seconds_delay" in CONFIGS:
        CONFIGS["seconds_delay"] = int(CONFIGS["seconds_delay"])

    if options.storage_failed_dir:
        CONFIGS["storage_failed_dir"] = options.storage_failed_dir

    if "storage_s3_secret_file" not in CONFIGS:
        CONFIGS["storage_s3_secret_file"] = MINIOSECRETFILE

    if "storage_s3_access_file" not in CONFIGS:
        CONFIGS["storage_s3_access_file"] = MINIOACCESSFILE

    storage_secret_file = CONFIGS["storage_s3_secret_file"]
    storage_access_file = CONFIGS["storage_s3_access_file"]

    if os.path.exists(storage_secret_file):
        with open(storage_secret_file, 'r') as f:
            buf = f.read().strip()
            CONFIGS["secret"] = buf

    if os.path.exists(storage_access_file):
        with open(storage_access_file, 'r') as f:
            buf = f.read().strip()
            CONFIGS["access"] = buf

    # Check for required arguments in CONFIGS
    check_required_args()

    return args


def main():
    # Main program logic

    global CONFIGS

    files = parse_opts()

    minio_auth = None

    if "access" in CONFIGS and "secret" in CONFIGS:
        minio_auth = (CONFIGS["access"], CONFIGS["secret"])

    if files:
        for file in files:
            logging.debug("main: Processing file %s" % (os.path.abspath(file)))
            job_queue.put(file)
        init_workers(
            CONFIGS["num_workers"],
            CONFIGS["seconds_delay"],
            CONFIGS["num_retries"],
            CONFIGS["storage_failed_dir"],
            CONFIGS["storage_url"],
            minio_auth,
            False,
        )
    else:
        init_workers(
            CONFIGS["num_workers"],
            CONFIGS["seconds_delay"],
            CONFIGS["num_retries"],
            CONFIGS["storage_failed_dir"],
            CONFIGS["storage_url"],
            minio_auth,
            True,
        )
        # Add files already in directory to queue
        existing_files = []
        for (dirpath, dirnames, filenames) in os.walk(CONFIGS["storage_queue_dir"]):
            existing_files.extend([os.path.abspath(os.path.join(dirpath, f)) for f in filenames])

        for file in existing_files:
            if file.endswith(".submit"):
                job_queue.put(file)

        observe(CONFIGS["storage_queue_dir"])


# Initialize workers to do file processing
def init_workers(
    num_workers,
    seconds_delay,
    num_retries,
    storage_failed_dir,
    storage_urls,
    minio_auth,
    daemon_mode,
):
    logging.debug("Initializing workers...")

    workers = []

    # Create number of submit processes.
    worker_id = 0

    for i in range(num_workers):
        workers.append(
            SyncWorker(
                worker_id,
                seconds_delay,
                num_retries,
                storage_failed_dir,
                storage_urls,
                minio_auth,
            )
        )
        worker_id += 1

    for worker in workers:
        worker.start()

    if not daemon_mode:
        job_queue.join()
        for worker in workers:
            worker.terminate()


# Observe files in the input directory
def observe(storage_queue_dir):
    observer = Observer()

    # Format input directory as absolute path for easier handling of files
    if not storage_queue_dir.startswith("/"):
        storage_queue_dir = os.path.abspath(storage_queue_dir)

    logging.info("Observing directory: %s" % storage_queue_dir)

    # Only watch for on_created (this handler is fired on every filesystem change)
    observer.schedule(NewFileHandler(), path=storage_queue_dir, recursive=True)  # Plug queue into here?

    try:
        observer.start()
    except Exception as e:
        logging.exception("Unable to start observer on dir (%s) : (%s)" % (storage_queue_dir, e))

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.debug("Observer caught KeyboardInterrupt. Exiting.")
        observer.stop()

    observer.join()


class SyncWorker(Process):
    def __init__(
        self, w_id, seconds_delay, num_retries, storage_failed_dir, storage_urls, minio_auth
    ):
        super(SyncWorker, self).__init__()
        self.id = "%d-%d" % (os.getpid(), w_id)
        self.seconds_delay = seconds_delay
        self.last_host_index = 0
        self.session = requests.Session()
        self.num_retries = num_retries
        self.storage_failed_dir = storage_failed_dir
        self.storage_urls = storage_urls

        if minio_auth:
            self.minio_auth = minio_auth

        self.senders_dict = {}
        self.sender_last_index = {}
        self.sender = {}

    def shutdown(self):
        pass

    def valid_keys_v4(self, store_dict, filename):
        """ Checks that the JSON dump of a failed file submission
            contains all the necessary keys to be a version 4
            submission file.

        Args:
            store_dict (dict): A dictionary representing the contents
                of the JSON file.
            filename (str): The full path to the file.
        
        Returns:
            (boolean): Indicating True if the file contains all necessary 
                keys, False otherwise.
        """
        keys = ["buffer", "bucket_name", "operation", "filename"]
        missing = []
        for key in keys:
            if key not in store_dict:
                missing.append(key)

        if missing:
            logging.error(
                "V4 Error in stored JSON dictionary (Missing %s) filename=%s"
                % (",".join(missing), filename)
            )
            return False

        return True

    def move_to_failed_dir(self, file_path):
        logging.warn("Moving to failed directory: %s" % file_path)
        try:
            dst_path = os.path.join(self.storage_failed_dir, os.path.split(file_path)[1])
            os.rename(file_path, dst_path)
        except Exception as e:
            logging.exception(e)

    def decode_files(self, files):
        if files:
            buf = files.get("file", None)
            if buf:
                dbuf = base64.b64decode(buf)
                return {"file": dbuf}
        return files

    def decode_buffer(self, buf):
        dbuf = base64.b64decode(buf)
        return dbuf

    def submit_v4_6(self, store_dict, retries_left, file_path):
        """ Submit a version 4 and 6 type JSON file. Version 6 format 
            doesn't change the format itself it was upped when using 
            submit_storage_s3 but no handling instructions changed. Version 4 
            differs From version 3 by not storing 'storage_urls' in the file.
            Instead v4 files read from the LB config to determine the set
            of URLs that should be used for file storage. The exact same
            submission logic as submit_storage_minio should be in use
            with v4.

        Args:
            store_dict (dict): The dictionary representing the JSON file
            retries_left (number): How many tries are left
            file_path (str): The path to the JSON file including name

        Returns:
            (bool): Indicating success (True) or failure (False)
        """
        bucket_name = store_dict["bucket_name"]
        minio_path = store_dict["filename"]
        file_name = minio_path.split('/')[-1]
        ver = store_dict["ver"]
        rootUID = store_dict.get("rootUID", "None")
        operation = store_dict['operation'] # buffer, cache, json

        self.senders_dict, self.senders = generate_minio_handlers(
            self.storage_urls, self.senders_dict, self.minio_auth[0], self.minio_auth[1]
        )
        
        senders = None
        if operation == 'json':
            id_details = id_lookup_details(list(self.senders.keys()), rootUID)

            if id_details:
                storage_server = id_details.server
                senders = self.senders[storage_server]
            else:
                # get the key of the first time in the orderedDict
                storage_server = list(self.senders.items())[0][0]
                # get the ([strs][minio_handles]) array of the first time in the orderedDict
                senders = list(self.senders.items())[0][1]
        elif operation in ["buffer", "cache_file"]:
            storage_server = storage_server_lookup_from_name(list(self.senders.keys()), file_name)
            senders = self.senders[storage_server]
        else:
            logging.error('Invalid operation type: %s for file: %s' % (operation, minio_path))

        sender_strs = senders[0]
        sender_handles = senders[1]

        # This section uses the same logic as the submit_storage_minio
        for idx, sender in enumerate(sender_handles):
            try:
                msg = write_to_minio(sender, sender_strs[idx], bucket_name, minio_path, store_dict["buffer-decoded"])
            except Exception as e:
                logging.exception("Problem writing to minio server: [%s]"%(sender_strs[idx]))
                msg = "Problem writing to minio server: %s\n"%(sender_strs[idx]), 500

            if msg[1] in [200, 409]:
                return True
            else:
                text_status = msg[0]
                status = msg[1]

                if retries_left > 0:
                    logging.warn(
                        "Error sending ver:%d url:%s file_path:%s rootUID:%s status:%d Will retry err:%s"
                        % (ver, sender_strs[idx], file_path, rootUID, status, text_status)
                    )
                else:
                    logging.error(
                        "Error sending ver:%d url:%s file_path:%s rootUID:%s status:%d giving up err:%s"
                        % (ver, sender_strs[idx], file_path, rootUID, status, text_status)
                    )
        return False


    # Attempt to submit to storage
    def submit(self, store_dict, retries_left, file_path):
        success = False
        ver = store_dict.get("ver", 1)
        rootUID = ""

        if "buffer-decoded" not in store_dict:
            store_dict["buffer-decoded"] = self.decode_buffer(store_dict["buffer"])

        if ver in [4, 6]:
            return self.submit_v4_6(store_dict, retries_left, file_path)

        else:
            logging.error("Submitstoraged: Unsuported version: %d in file: %s" % (ver, file_path))
            # TODO not sure how to handle this?
            # return True to delete the file?

    # Main worker logic
    def run(self):

        # Loop forever for items to send to storage
        while True:

            # Block and wait for items in queue
            try:
                file_path = job_queue.get()
            except KeyboardInterrupt:
                logging.debug("Caught KeyboardInterrupt. Exiting.")
                break

            if not file_path.endswith(".submit"):
                logging.debug("Picked up file that does not end with '.submit'. Ignoring.")
                job_queue.task_done()
                continue

            logging.info("Worker: Processing file (%s)" % (file_path))

            file_buffer = None
            try:
                fh = open(file_path, "rb")
                file_buffer = fh.read()
                fh.close()
            except Exception as e:
                logging.debug("Error opening and reading file (%s)" % (file_path))
                job_queue.task_done()

            if file_buffer:
                try:
                    store_dict = json.loads(file_buffer)

                    ver = store_dict.get("ver", 1)

                    # Check for valid dictionary keys in json saved blob
                    if ver == 4 and not self.valid_keys_v4(store_dict, file_path):
                        job_queue.task_done()
                        continue

                    keep_submitting = True
                    retries_left = self.num_retries

                    # Continually submit until success or retries runout
                    while keep_submitting:
                        submitted = False
                        try:
                            submitted = self.submit(store_dict, retries_left, file_path)
                        except Exception as e:
                            logging.exception("Exception submitting file (%s)" % (file_path))

                        if submitted:
                            keep_submitting = False
                            # File submitted successfully, remove from disk
                            logging.info("Successfully submitted (%s)" % file_path)
                            if os.path.exists(file_path):
                                logging.debug("Removing from disk (%s)" % file_path)
                                os.remove(file_path)
                            job_queue.task_done()
                        else:
                            if retries_left == 0:
                                logging.warn(
                                    "Failed submission, no more retries (%s)" % (file_path)
                                )
                                # No more submission retries left for this file
                                # Stop attempting & move file to a directory to be manually checked by a user
                                keep_submitting = False
                                self.move_to_failed_dir(file_path)
                                job_queue.task_done()
                            else:
                                logging.info(
                                    "Failed submission, retrying in %d seconds (%s)"
                                    % (self.seconds_delay, file_path)
                                )
                                # Failed to submit, delay until next submission attempt.
                                time.sleep(self.seconds_delay)
                                retries_left -= 1

                except Exception as e:
                    logging.exception(e)
                    job_queue.task_done()


# Necessary for multiprocessing to work
if __name__ == "__main__":
    main()
