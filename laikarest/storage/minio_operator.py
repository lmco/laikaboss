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
import logging
import minio
from minio.error import InvalidResponseError, S3Error

class MinioOperator:
    """ Custom wrapper for Minio storage """ 
    def __init__(self, minio_clients):
        self.minio_clients = minio_clients

    def get_object(self, bucket_name, object_name):
        error = 'Unable to get the object'
        # go through each of the clients
        for minio_client in self.minio_clients:
            try:
                # can we find the object? If it's not there, it throws an error
                bucket_prefix = minio_client.lb_get_bucket_prefix() if minio_client.lb_get_bucket_prefix() else ""
                bucket = bucket_prefix + bucket_name
                msg = 'client:[%s]: bucket_name: [%s]. object_name: [%s]' % (str(minio_client), bucket_name, object_name)
                res = minio_client.get_object( bucket, object_name)
                # if we found the object, return it
                return res
            except Exception as e:
                error = 'error: [%s] %s' % (e, msg)

        raise Exception(error)

    def object_exists(self, bucket_name, object_name):
        """ Check if an object exists a specified bucket.

        Raises:
            minio.error.NoSuchBucket: if the specified bucket does not exist
            minio.error.ResponseError: Minio client deemed response invalid?
        Returns:
            returns (bool): True if exists, False otherwise
        """
        for minio_client in self.minio_clients:
            bucket_prefix = minio_client.lb_get_bucket_prefix() if minio_client.lb_get_bucket_prefix() else ""
            try:
                res = minio_client.stat_object(bucket_prefix + bucket_name, object_name)
                if isinstance(res, minio.definitions.Object):
                    return True
                return "size" in res and res.size > 0
            except S3Error as e:
                if e.code == "NoSuchKey":
                   continue
                elif e.code == "NoSuchBucket":
                   error = 'error: [%s]. bucket_name: [%s] does not exist' % (e, bucket_name)
                   logging.error(error)
                   raise
            except InvalidResponseError as e:
                error = 'error: [%s]. bucket_name: [%s]. object_name: [%s]' % (e, bucket_name, object_name)
                logging.error(error)
                raise
        return False

    def bucket_exists(self, bucket_name):
        error = 'Unable to find the bucket'
        # go through each of the clients
        for minio_client in self.minio_clients:
            bucket_prefix = minio_client.lb_get_bucket_prefix() if minio_client.lb_get_bucket_prefix() else ""
            try:
                minio_client.bucket_exists(bucket_prefix + bucket_name)
                return minio_client
            except Exception as e:
                error = e

        raise Exception(error)

    def _bucket_exists(self, bucket_name, minio_client):
        try:
            if minio_client.bucket_exists(bucket_name):
                return True
            return False
        except Exception as e:
            raise

    def make_bucket(self, bucket_name):
        # go through each of the clients
        for minio_client in self.minio_clients:
            bucket_prefix = minio_client.lb_get_bucket_prefix() if minio_client.lb_get_bucket_prefix() else ""
            try:
                if not self._bucket_exists(bucket_prefix + bucket_name, minio_client):
                    logging.info("creating bucket {}".format(bucket_prefix + bucket_name))
                    minio_client.make_bucket(bucket_prefix + bucket_name)
            except Exception as e:
                raise
        
    def copy_object(self, new_bucket, new_object, old_object):
        error = 'Unable to copy the object'
        for minio_client in self.minio_clients:
            bucket_prefix = minio_client.lb_get_bucket_prefix() if minio_client.lb_get_bucket_prefix() else ""
            try:
                # logging.debug("copying to bucket [{}] new_object [{}] from [{}]".format(bucket_prefix + new_bucket, new_object, bucket_prefix + old_object))
                minio_client.copy_object(bucket_prefix + new_bucket, new_object, bucket_prefix + old_object)
                return True
            except Exception as e:
                # logging.exception(e)
                error = e

        raise Exception(error)

    def remove_objects(self, bucket_name, object_list):
        error = 'Unable to remove the objects'
        for minio_client in self.minio_clients:
            bucket_prefix = minio_client.lb_get_bucket_prefix() if minio_client.lb_get_bucket_prefix() else ""
            try:
                errors = minio_client.remove_objects(bucket_prefix + bucket_name, object_list)
                if len(list(errors)) != 0:
                    logging.error(errors)
                    return False
                return True
            except Exception as e:
                # logging.exception(e)
                error = e

        raise Exception(error)

    def list_objects(self, bucket_name, search_prefix='', recursive=False):
        objects_in_buckets = []
        for minio_client in self.minio_clients:
            bucket_prefix = minio_client.lb_get_bucket_prefix() if minio_client.lb_get_bucket_prefix() else ""
            try:
                if not self._bucket_exists(bucket_prefix + bucket_name, minio_client):
                    continue
                objects_in_buckets.extend(minio_client.list_objects(bucket_prefix + bucket_name, prefix=search_prefix, recursive=recursive))
            except Exception as e:
                raise
        return objects_in_buckets

