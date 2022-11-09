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
import os
import time
import json
import pprint
import snappy
import logging
import tempfile

from minio import Minio
from minio.error import InvalidResponseError, S3Error

from laikaboss.storage_utils import minioclient_from_url

from backports import lzma
from urllib.parse import urlparse
from laikarest.storage import storage_config_parser
from laikarest.storage.minio_operator import MinioOperator
import urllib.parse


from future.standard_library import install_aliases
install_aliases()
from urllib.parse import quote_plus

class StorageHelper:
    def __init__(self, storage_gui_config):
        self._init_cluster_info(storage_gui_config)
        self._parse_storage_info(storage_gui_config)
        self._init_bucket_lists(storage_gui_config)
        self.storage_handlers = []
        self._init_storage_handlers()
        self._init_storage_operator()
        self.memorialized_bucket_name = storage_gui_config["memorialized_bucket_name"]
        self._create_memorialization_bucket_if_not_exists()

    def _init_cluster_info(self, storage_gui_config):
        """ What host are we running on? What cluster? """
        self.cluster = storage_gui_config.get('cluster', 'default')
        self.hostname = storage_gui_config.get('hostname_short', 'lb')

    def _parse_storage_info(self, storage_gui_config):
        """ Reads storage configuration file"""

        laikastorage_index_config = storage_gui_config['storage_index']
        self.custom_index_parser = storage_config_parser.Parser(laikastorage_index_config, self.hostname, self.cluster)

    def _init_bucket_lists(self, storage_gui_config):
        """ Initialize list of available buckets """

        bucket_list_all = self.custom_index_parser.get_indexes_by_host()

        logging.info("Storage buckets loaded: {}".format(bucket_list_all))
        self.bucket_list_with_rootUIDs = []
        self.bucket_list_without_rootUIDs = []

        for bucket in bucket_list_all:
            if '-json' in bucket:
                self.bucket_list_with_rootUIDs.append(bucket)
            else:
                self.bucket_list_without_rootUIDs.append(bucket)

        if not bucket_list_all:
            logging.error("no buckets found for this cluster/host combination - is this the correct cluster and host for storage index file {}".format(self.cluster)) 
            raise ValueError("no buckets found for cluster/host combo in storage index cluster:{} ".format(self.cluster))

    def _init_storage_handlers(self):
        """ Based on the configuration file and the host/cluster, initiate storage handlers
        """
        endpoint_list = self.custom_index_parser.get_url_index_by_cluster()
        logging.info("List of s3/minio endpoints for {}".format(endpoint_list))
        for url in endpoint_list:
            logging.debug("initializing storage handler for {}".format(url))
            minio_client = minioclient_from_url(url)
            self.storage_handlers.append(minio_client)

    def _init_storage_operator(self):
        """ Creates the abstraction layer to deal with the the storage handlers 
        """
        self.storage_operator = MinioOperator(self.storage_handlers)

    def query_bucket_for_object(self, bucket_name, sub_path, storage_format=1):
        """ Attempt to extract object content from a provided bucket.

        raises:
            (ValueError) if the bucket does not exist or some other error was encountered

        Returns: 
            object_content (str): if rootUID was found in the bucket
            False (bool): if rootUID was not found in bucket

        """

        try:
            zipped_obj = self.storage_operator.get_object(bucket_name, sub_path)
            temp_zipped_file = tempfile.NamedTemporaryFile(delete=False)

            with open(temp_zipped_file.name, 'wb') as f:
                for d in zipped_obj.stream(32 * 1024):
                    f.write(d)
            temp_zipped_file.flush()
            temp_zipped_file.seek(0)
            temp_unzipped_filename = ''
            obj_content = None
            try:
                with open(temp_zipped_file.name, 'rb') as compressed_f:
                    compressed_data = compressed_f.read()
                obj_content = snappy.StreamDecompressor().decompress(compressed_data)
            except Exception as e:
                logging.exception(e)

            if obj_content is None:
                with open(temp_zipped_file.name, 'rb') as f:
                    obj_content = f.read()
            return obj_content
        except S3Error as e:
            if e.code == "NoSuchKey":
               return False
            elif e.code == "NoSuchBucket":
               raise ValueError("bucket {} does not exist".format(bucket_name))
        except Exception as e:
            raise

    def is_memorialized(self, sub_path):
        """ Stats the sub_path in the specified bucket

        Raises:
            Any exception

        Returns:
            (bool): True if exists False otherwise
        """
        reply = self.storage_operator.object_exists(self.memorialized_bucket_name, sub_path)
        return reply


    def get_json_from_text(self, object_content):
        """ JSON serializes provided content

        Args:
            object_content(str): scan content in JSON format

        Raises:
            ValueError: if the provided object is not JSON serializable.

        Returns:
            dict()
        """
        return json.loads(object_content)

    def create_temp_file(self, obj_content):
        """ Given some content, write a temporary file to disk """
        if not isinstance(obj_content, bytes):
            obj_content = obj_content.encode('utf-8')
        obj_content_file = tempfile.NamedTemporaryFile(delete=False)
        obj_content_file.write(obj_content)
        obj_content_file.flush()
        obj_content_file.seek(0)

        return obj_content_file

    def get_metadata(self, scan_results, storage_format=1):

        if storage_format != 1:
           raise ValueError("unknown storage_format %d" %(storage_format))

        complete_log = scan_results["log_complete"]
        metadata = complete_log[0]
        return metadata

    def get_external_metadata(self, scan_results, storage_format=1):
        """ Attempts to extract the metadata from a scan result 

        Args:
            scan_results (dict or list)
            storage_format (int): scan result format

        Raises:
            KeyError: When failing to extract external metadata via
                a known method

        Returns:
            ext_metadata (dict)
        """
        metadata = self.get_metadata(scan_results, storage_format)
        ext_metadata = metadata['moduleMetadata'].get('EXTERNAL')
        return ext_metadata

    def get_interesting_attachments(self, scan_results, storage_format=1):
        """ Enumerates attachments in provided object and gets their names and locations.

        Args:
            scan_results (dict): scan results

        Raises:
            Any exception

        returns:
            attachments(list): the list of attachment names where each
                item: (tuple): (file_name, file_bucket, file_sha256_hash)
        """
        attachments = []

        scan_obj = None
        if 'log_complete' in scan_results:
            scan_obj = scan_results['log_complete']
        else:
            raise ValueError("Retrieved a weird scan/JSON storage format")

        assert isinstance(scan_obj, list)

        for scan_result in scan_obj[1:]: #skips top level object
            if "filename" not in scan_result:
                logging.warn("filename was not found in scan_result")
                continue
            file_name = scan_result["filename"]
            if "moduleMetadata" not in scan_result:
                logging.warn("module metadata was not found in scan result for file: {}".format(file_name))
                continue
            # get s3 storage info (if any)
            submit_storage_s3 = scan_result['moduleMetadata'].get('SUBMIT_STORAGE_S3')
            # get minio storage info (if any)
            submit_storage_minio = scan_result['moduleMetadata'].get('SUBMIT_STORAGE_MINIO')

            file_bucket = None
            sub_path = None
            if submit_storage_s3:
                version = submit_storage_s3["ver"]
                if isinstance(version, list):
                    version = version[0]
                file_bucket = submit_storage_s3["bucket"]
                if isinstance(file_bucket, list):
                    file_bucket = file_bucket[0]
                sub_path = submit_storage_s3["subpath"]
                logging.info(sub_path)
                if isinstance(sub_path, list):
                    sub_path = sub_path[0]
            else:
                try:
                    logging.warn('could not determine attachment location for file: {}'.format(file_name))
                except UnicodeEncodeError:
                    logging.warn('non unicode filename!')
                continue

            # Get the file hash
            try:
                file_hash = scan_result["moduleMetadata"]["META_HASH"]["HASHES"]["SHA256"]
            except:
                logging.warn("failed to retrieve sha256 hash for file: {}".format(file_name))
                continue

            if not sub_path:
                # If subpath was not included, it is probably using storage_method=2
                sub_path = "{}/{}/{}".format(file_hash[:2], file_hash[2:4], file_hash)

            attachments.append({
                "file_name": file_name,
                "file_bucket": file_bucket,
                "file_hash": file_hash,
                "sub_path": sub_path
            })


        return attachments

    def _create_memorialization_bucket_if_not_exists(self):
        try:
            self.storage_operator.make_bucket(self.memorialized_bucket_name)
        except BucketAlreadyOwnedByYou as e:
            pass
        except BucketAlreadyExists as e:
            pass
        except Exception as e:
            logging.exception(e)

    def memorialize(self, scan_results, found_in_bucket, sub_path, rootUID):
        self._create_memorialization_bucket_if_not_exists()
        children_objects_to_copy = self._embedded_object_hashes(scan_results, found_in_bucket.replace('-json', ''))

        # Move each of the children objects
        for child in children_objects_to_copy:
            logging.info(child)
            file_bucket = child["file_bucket"] 
            child_sub_path = child["sub_path"]
            file_hash = child["file_hash"]
            if not file_bucket or not child_sub_path:
                logging.warn("unable to create path in s3 for child {}, for rootUID: {}".format(json.dumps(child, rootUID)))
                continue
            current_child_path = "{}/{}".format(file_bucket, child_sub_path)
            new_child_sub_path = "{}/{}/{}/{}".format(file_hash[:2], file_hash[2:4], file_hash[4:6], file_hash)
            memorialized_path = "{}/{}".format(self.memorialized_bucket_name, new_child_sub_path)
            logging.info("current child object path {}".format(current_child_path))
            logging.info("moving to memorialized path {}".format(memorialized_path))
            try:
                self.storage_operator.copy_object(self.memorialized_bucket_name, new_child_sub_path, current_child_path)
            except Exception as e:
                logging.exception(e)
                pass

        # Move json scan object
        current_full_storage_path = "{}/{}".format(found_in_bucket, urllib.parse.quote(sub_path))
        scan_sub_path = "{}/{}/{}/{}".format(rootUID[:2], rootUID[2:4], rootUID[4:6], rootUID)
        memorialized_scan_path = "{}/{}".format(self.memorialized_bucket_name, scan_sub_path)
        self.storage_operator.copy_object(self.memorialized_bucket_name, scan_sub_path, current_full_storage_path)


    def _embedded_object_hashes(self, scan_results, bucket=None, storage_format=1):
        """ Enumerates embedded objects in provided scan and gets their names and locations.

        Args:
            scan_results (dict): scan results

        Raises:
            Any exception

        returns:
            embedded_objects(list): the list of objects
        """
        embedded_objects = []

        scan_obj = None
        if 'log_complete' in scan_results:
            scan_obj = scan_results['log_complete']
        else:
            raise ValueError("Retrieved a weird scan/JSON storage format")

        assert isinstance(scan_obj, list)

        for scan_result in scan_obj:
            if "filename" not in scan_result:
                logging.warn("filename was not found in scan_result")
                continue
            file_name = scan_result["filename"]
            if "moduleMetadata" not in scan_result:
                logging.warn("module metadata was not found in scan result for file: {}".format(file_name))
                continue
            # get s3 storage info (if any)
            submit_storage_s3 = scan_result['moduleMetadata'].get('SUBMIT_STORAGE_S3')
            # get minio storage info (if any)
            submit_storage_minio = scan_result['moduleMetadata'].get('SUBMIT_STORAGE_MINIO')

            file_bucket = None
            sub_path = None
            if submit_storage_s3:
                version = submit_storage_s3["ver"]
                if isinstance(version, list):
                    version = version[0]
                file_bucket = submit_storage_s3["bucket"]
                if isinstance(file_bucket, list):
                    file_bucket = file_bucket[0]
                sub_path = submit_storage_s3["subpath"]

            else:
                logging.warn('could not determine attachment location for file: {}'.format(file_name))
                continue

            # Get the file hash
            try:
                file_hash = scan_result["moduleMetadata"]["META_HASH"]["HASHES"]["SHA256"]
            except:
                logging.warn("failed to retrieve sha256 hash for file: {}".format(file_name))
                continue

            if not sub_path:
                # If subpath was not included, it is probably using storage_method=2
                sub_path = "{}/{}/{}".format(file_hash[:2], file_hash[2:4], file_hash)

            if isinstance(sub_path, list):
                for spath in sub_path:
                    embedded_objects.append({
                        "file_name": file_name,
                        "file_bucket": file_bucket,
                        "file_hash": file_hash,
                        "sub_path": spath
                    })
            else:
                embedded_objects.append({
                    "file_name": file_name,
                    "file_bucket": file_bucket,
                    "file_hash": file_hash,
                    "sub_path": sub_path
                })


        return embedded_objects

    def _bucket_and_subpath(self, scan_results, submit_storage_s3, submit_storage_minio, fallback_bucket_type):
        storage_bucket = None
        sub_path = None
        if not submit_storage_s3:
            # Version 5?
            if submit_storage_minio and "minio_bucket" in submit_storage_minio:
                logging.info("submit storage minio with bucket info storage format")
                storage_bucket = submit_storage_minio["minio_bucket"]
                filename = submit_storage_minio["minio_filename"]
                sub_path = "{}/{}/{}".format(filename[:2], filename[2:4], filename)
            else:
                logging.info("oldest storage format")
                date_of_bucket = scan_results["datetime"].split()[0]
                filename = scan_results['scan-hash']
                storage_bucket = date_of_bucket + '-' + fallback_bucket_type
                sub_path = "{}/{}/{}".format(filename[:2], filename[2:4], filename)
        else:
            # S3 format

            logging.info('Submit Storage S3 storage format')
            version = submit_storage_s3["ver"]
            if isinstance(version, list):
                version = version[0]
            storage_bucket = submit_storage_s3["bucket"]
            if isinstance(storage_bucket, list):
                storage_bucket = storage_bucket[0]
            sub_path = submit_storage_s3["subpath"]
            if isinstance(sub_path, list):
                sub_path = sub_path[0]

        return storage_bucket, sub_path

    def storage_bucket_info(self, scan_results, fallback_bucket_type, storage_format=1):
        """ Enumerates the provided scan results to determine which bucket to query.
            new versions of SUBMIT_STORAGE_MINIO keep references to the original file
            within the moduleMetadata. Older versions are harder.
        Args:
            scan_results (dict): scan results

        Raises:
            Any exception (especially KeyErrors)

        Returns: 
            (tuple): (storage_bucket, bucket_subpath)
        """

        scan_obj = None
        if 'log_complete' in scan_results:
            scan_obj = scan_results['log_complete']
        else:
            raise ValueError("Retrieved an unknown scan/JSON storage format")

        assert isinstance(scan_obj, list)

        # get filename according to META_HASH (sha256 is filename)
        file_hash = scan_obj[0]['moduleMetadata']['META_HASH']['HASHES']['SHA256']
        # get date 
        first_date = scan_results['datetime'].split()[0]

        # get s3 storage info (if any)
        submit_storage_s3 = scan_obj[0]['moduleMetadata'].get('SUBMIT_STORAGE_S3')

        # get minio storage info (if any)
        submit_storage_minio = scan_obj[0]['moduleMetadata'].get('SUBMIT_STORAGE_MINIO')

        storage_bucket, sub_path = self._bucket_and_subpath(scan_results, submit_storage_s3, submit_storage_minio, fallback_bucket_type)

        logging.info("using bucket {} {}".format(storage_bucket, sub_path))

        # return bucket_name, filename, file_hash
        return storage_bucket, sub_path
