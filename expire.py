#!/usr/bin/env python
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
import os
import re
import time
import logging
import datetime
from collections import defaultdict

from laikaboss.lbconfigparser import LBConfigParser
from laikarest.storage.storage_helper import StorageHelper

def setup_logger(expiration_config):
    logFormatter = logging.Formatter("%(asctime)s - %(process)d [%(levelname)-5.5s]  %(message)s")
    rootLogger = logging.getLogger()

    log_file_path = expiration_config["log_file"]
    fileHandler = logging.FileHandler(log_file_path)
    fileHandler.setFormatter(logFormatter)
    rootLogger.addHandler(fileHandler)

    consoleHandler = logging.StreamHandler()
    consoleHandler.setFormatter(logFormatter)
    rootLogger.addHandler(consoleHandler)

    log_verbosity = expiration_config['log_level'].upper()
    rootLogger.setLevel(logging.__dict__[log_verbosity])

    logging.debug(f"Logging to file {log_file_path} with verbosity {log_verbosity}")

def expire(storage_helper):
    today = datetime.datetime.utcnow()

    delete_bucket_policies = defaultdict(dict)
    for bucket_name, bucket_policy in storage_helper.custom_index_parser.get_index_expiration_by_host().items():
        logging.info(bucket_name)
        expiration_action = bucket_policy[0]
        logging.info(bucket_policy)
        if expiration_action.lower() == 'delete':
            final_bucket_name = re.sub('-storage(-json)?','', bucket_name)
            if final_bucket_name == 'storage' or final_bucket_name == 'storage-json' or final_bucket_name == 'cached-files':
                final_bucket_name = 'email'

            if 'old-formats' not in delete_bucket_policies[final_bucket_name]:
                delete_bucket_policies[final_bucket_name]['old-formats'] = []
            
            delete_bucket_policies[final_bucket_name]['old-formats'].append(bucket_name)

            if bucket_name.endswith('-json'):
                delete_bucket_policies[final_bucket_name]['json'] = bucket_policy
            else:
                delete_bucket_policies[final_bucket_name]['buffer'] = bucket_policy
        # TODO handle other expiration action


    # handle the delete action
    for bucket_name, delete_bucket_policies in delete_bucket_policies.items():
        json_policy = delete_bucket_policies['json']
        buffer_policy = delete_bucket_policies['buffer']

        delete_json_before_date = today - datetime.timedelta(days=int(json_policy[1]))
        delete_buffer_before_date = today - datetime.timedelta(days=int(buffer_policy[1]))
        logging.info(delete_json_before_date.strftime("%Y-%m-%d"))

        # try to delete from storage format 1 (e.g. netapp)
        logging.info(f"searching bucket {bucket_name}")
        try:
            bucket_files = storage_helper.storage_operator.list_objects(bucket_name)
        except Exception as e:
            logging.exception(e)
            continue

        for s3_file in bucket_files:
            # ['bucket_name', 'content_type', 'delete_marker', 'etag', 'is_dir', 'is_latest', 'last_modified', 'metadata', 'object_name', 'owner_id', 'owner_name', 'size']
            s3_file_name = s3_file.object_name
            date_of_objects = datetime.datetime.strptime(s3_file_name[:-1], "%Y-%m-%d")

            if date_of_objects < delete_json_before_date and date_of_objects < delete_buffer_before_date:
                logging.info(f"deleting everything in {s3_file_name}")
                try:
                    all_files = storage_helper.storage_operator.list_objects(bucket_name, search_prefix=s3_file_name, recursive=True)
                    all_files = [ o.object_name for o in all_files]
                    logging.info(f"deleting {len(all_files)} objects")
                    if not storage_helper.storage_operator.remove_objects(bucket_name, all_files):
                        raise Exception
                except Exception as e:
                    logging.exception(e)
                    logging.info(f"Failed to delete object {s3_file_name} from {bucket_name}")
            elif date_of_objects < delete_json_before_date:
                logging.info(f"deleting json in {s3_file_name}")
                try:
                    all_files = storage_helper.storage_operator.list_objects(bucket_name, search_prefix=s3_file_name + 'json', recursive=True)
                    all_files = [ o.object_name for o in all_files]
                    logging.info(f"deleting {len(all_files)} objects")
                    if not storage_helper.storage_operator.remove_objects(bucket_name, all_files):
                        raise Exception
                except Exception as e:
                    logging.exception(e)
                    logging.info(f"Failed to delete object {s3_file_name}/json from {bucket_name}")
            elif date_of_objects < delete_buffer_before_date:
                logging.info(f"deleting buffer in {s3_file_name}")
                try:
                    all_files = storage_helper.storage_operator.list_objects(bucket_name, search_prefix=s3_file_name + 'buffer', recursive=True)
                    all_files = [ o.object_name for o in all_files]
                    logging.info(f"deleting {len(all_files)} objects")
                    if not storage_helper.storage_operator.remove_objects(bucket_name, all_files):
                        raise Exception
                except Exception as e:
                    logging.exception(e)
                    logging.info(f"Failed to delete object {s3_file_name}/json from {bucket_name}")
            else:
                logging.info(f"Nothing to delete, object {s3_file_name} is not stale")

                
if __name__ == '__main__':

    # path to config
    config_file = os.getenv("CONFIG_FILE", "/etc/laikaboss/laikarestd.conf")

    default_config = {
        "log_file": "/var/log/laikaboss/expiration.log",
    }

    # Read config file into a dict
    config = LBConfigParser(defaults=default_config)

    config.read(config_file)

    general = dict(config.items("General"))

    expiration_config = general.copy()

    expiration_config.update(dict(config.items("expiration")))

    storage_config = general.copy()

    storage_config.update(dict(config.items("storage-gui")))

    setup_logger(expiration_config)

    while True:
        storage_helper = StorageHelper(storage_config)
        expire(storage_helper)

        time.sleep(60 * 60 * 24) # sleep for a day
