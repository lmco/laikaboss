# Copyright 2020 National Technology & Engineering Solutions of Sandia, LLC 
# (NTESS). Under the terms of Contract DE-NA0003525 with NTESS, the U.S. 
# Government retains certain rights in this software.
#
'''
This module logs to a file in a laikastorage friendly format and/or to a socket on a laikastorage forwarder.
'''
from __future__ import absolute_import

from builtins import next
from builtins import str
from past.builtins import basestring
from past.builtins import unicode
from future import standard_library
standard_library.install_aliases()

import copy
from copy import deepcopy as clone_object
from math import isnan, isinf
from laikaboss.si_module import SI_MODULE
from laikaboss.util import get_option, log_module_error
from laikaboss.extras.extra_util import config_path, safe_filename, parse_log_record, parse_log_record_nonsummary, Lock
from distutils.util import strtobool
from laikaboss.objectmodel import QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError
import hashlib
import fnmatch
import os
import random
import subprocess
import base64
import json
import shutil
import binascii
import logging
import requests
import snappy
from urllib.parse import quote

import laikaboss
from laikaboss.storage_utils import write_to_minio, generate_minio_handlers
from laikaboss.extras.text_util import convert_to_unicode

from uuid import UUID
import time,socket,datetime
import json as json_module
from collections import OrderedDict

_module_name = "SUBMIT_STORAGE_S3"
_max_text_size = 8000
_min_text_size = 3
_submitstorage_version = 6

def get_date_from_uuid(uuid_string):

   epoch = datetime.datetime(1582, 10, 15)
   uuid_obj = UUID(uuid_string)

   if uuid_obj.version == 1:
      timestamp = epoch + datetime.timedelta(microseconds = uuid_obj.time//10)
      return timestamp
   else:
      return None

def encode_buf(buf):
    if buf:
        bbuf =  base64.b64encode(buf)
        return bbuf
    return buf

class SUBMIT_STORAGE_S3(SI_MODULE):
    '''Laika module for submitting files and results to laikastorage.'''

    def __init__(self,):
        '''Main constructor'''

        self.module_name = _module_name
        self.hostname = socket.gethostname()
        self.save_only = False
        self.senders_dict = {}
        self.senders = None
        self.urls_str = None
        self.storage_type = None
        self.storage_interval = None
        self.log_path = None
        self.log = None

    def _run(self, scanObject, result, depth, args):
        """Main module execution. Logs the scan result to laikastorage."""

        # workaround that test class re-uses modules and doesn't reset them between tests
        init = strtobool(str(get_option(args, "reinit", "storage_reinit", "False")))

        if init:
           self.__init__()

        rootUID = result.rootUID
        scanhash = None

        self.error_queue_dir = get_option(args, "queue_dir", "storage_queue_dir", "/var/laikaboss/storage-queue")
        self.save_only = strtobool(str(get_option(args, "save_only", "storage_save_only", "false")))
        self.base_bucket = str(get_option(args, "bucket", "storage_bucket", "storage"))
        self.clear_log_data = strtobool(get_option(args, "clear_log_data", "clear_log_data", "false"))

        self.log_path = get_option(args, "log_file", "storage_log_file", "/var/log/laikaboss/submit_storage_s3.log")

        self.dir_levels = int(get_option(args, "dir_levels", "storage_dir_levels", "3"))

        if not self.log:
           self.log = open(self.log_path, "ab", 0)

        self.storage_type = get_option(args, "type", "storage_type", "json")
        self.storage_interval = int(get_option(args, "interval", "storage_interval", "1"))

        # gets list of storage servers with their failoverservers still ';' seperated
        self.urls_str = str(get_option(args, "url", "storage_url", None))

        fileType  = scanObject.fileType

        if not self.urls_str:
            logging.error("Minio - No url or storage_url defined - exiting: s3:%s rootUID:%s storage_type:%s fileType:%s" % (self.urls_str, rootUID, self.storage_type, fileType))
            return []

        self.senders_dict, self.senders = generate_minio_handlers(self.urls_str, self.senders_dict)

        scanhash = hashlib.sha256(scanObject.buffer).hexdigest()
        filename = scanObject.filename
        size = len(scanObject.buffer)

        orig_dt, bucket, sub_path = gen_storage_details(rootUID, self.base_bucket, self.storage_type, scanhash, interval=self.storage_interval, levels=self.dir_levels)

        buf = None
        if self.storage_type == "json":

            logs = self._json_storage_details(scanObject, result, rootUID, scanhash, orig_dt, self.storage_type, fileType)
            buf = json.dumps(logs, ensure_ascii=False)
            if not isinstance(buf, bytes):
                buf = buf.encode('utf-8', errors='replace')

        elif self.storage_type in ["buffer", "cache_file"]:

            buf = scanObject.buffer
        else:
            err = 'Invalid storage_type: %s' % self.storage_type
            logging.error(err)
            raise ValueError(err)

        scanObject.addMetadata(_module_name, "filename", filename, unique=True)
        scanObject.addMetadata(_module_name, "size", size, unique=True)
        scanObject.addMetadata(_module_name, "subpath", sub_path, unique=True)
        scanObject.addMetadata(_module_name, "bucket", bucket, unique=True)
        scanObject.addMetadata(_module_name, "type", self.storage_type, unique=True)
        scanObject.addMetadata(_module_name, "ver", _submitstorage_version, unique=True)


        try:
            # get the first item
            senders = self.senders[next(iter(self.senders))]

            resp = self.submitFile(senders, rootUID, bucket, self.storage_type, sub_path, buf, filename)
        except (QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError):
            raise
        except Exception as e:
            logging.exception("Minio - Unable to send file to storage at s3:%s rootUID:%s storage_type:%s sub_path:%s" % (self.urls_str, rootUID, self.storage_type, sub_path))

        return []

    def _extract_email_text_from_html(self, result, log_record):
        """ Extract an emails text from the HTML.

        Args:
            result (ScanResult): the finalized results of the scan
            log_record (dict): The current dictionary representing
                what will be logged.

        Returns:
            log_record (dict): The modified log record with a base64
                encoded email_text_from_html
        """
        files = result.files
        text_from_html_files = self.find_files(files, ["text_from_html"])
        if text_from_html_files:
            # grab the first obj
            text = text_from_html_files[0].buffer
            if text and len(text) > _min_text_size:
                text_utf8_1 = text

                if isinstance(text, str):
                    text_utf8_1 = text.encode('utf-8')

                log_record["email_text_from_html"] = base64.b64encode(text_utf8_1[:_max_text_size]).decode('utf-8')

        return log_record

    def _json_storage_details(self, scanObject, result, rootUID, scanhash, orig_dt, storage_type, fileType):
        """ Prepare data for Minio storage in json format - including a summary of scan results after being
            processed by Laikaboss modules

        Args:
            scanObject (ScanObject):
            result (ScanResult): the finalized results of the LB scan
            rootUID (str): The unique identifier
            scanhash (str): A hash of the file buffer
            orig_dt (datetime): the datetime object from when the rootUID was created
            storage_type (str): values such as 'json' or 'buffer' or 'cache'
            fileType (str []): values such as 'eml' for email

        Returns:
            a dictionary containing the following items:
                senders: A list of endpoint urls to submit data to,
                buffer: The buffer of the file that s3 should write to disk,

        """
        summary = ""
        nonsummary = ""

        log_record = {}

        try:
           summary = scanObject.moduleMetadata["SUBMIT_STORAGE_META"]["summary"]
           if isinstance(summary, str):
              summary = json.loads(summary)
           if self.clear_log_data:
              del scanObject.moduleMetadata["SUBMIT_STORAGE_META"]["summary"]
        except KeyError as e:
           pass

        try:
            nonsummary = scanObject.moduleMetadata["SUBMIT_STORAGE_META"]["nonsummary"]
            if self.clear_log_data:
                del scanObject.moduleMetadata["SUBMIT_STORAGE_META"]["nonsummary"]
        except KeyError as e:
            headers = {}
            #If no nonsummary, construct it before storing
            try:
                headers = json.loads(laikaboss.config.splunkcommonheaders)
            except (ValueError, AttributeError) as e:
                logging.debug('%s: Error parsing common Splunk headers in laikaboss.conf' % self.module_name)

            #split_log is assumed to be true; this is mostly cosmetic since we're not actually logging
            nonsummary = parse_log_record_nonsummary(result, split_log=True, headers=headers)

        # why are these strings?  FIX upstream
        if nonsummary and isinstance(nonsummary, str):
            nonsummary = json.loads(nonsummary)

        if isinstance(nonsummary, list):
            tmp = []
            for item in nonsummary:
                # FIX upstream why is this a list of strings?
                if isinstance(item, str):
                   item = json.loads(item)
                tmp.append(item)
            nonsummary = tmp

        log_record["log_summary"] = summary
        log_record["log_complete"] = nonsummary
        log_record["datetime"] = orig_dt.strftime("%Y-%m-%d %H:%M:%SZ")
        log_record["rootUID"] = rootUID
        log_record["source"] = result.source
        log_record["scanhost"] = self.hostname
        log_record["scanhash"] = scanhash

        if fileType and "eml" in fileType:
            log_record = self._extract_email_text_from_html(result, log_record)

            msg_text_files = self.find_files(result.files, ["e_email_text/plain_*"])

            if msg_text_files:
                text = b""
                for text_file in (sorted(msg_text_files, key=lambda x: x.filename)):
                    if hasattr(text_file, "buffer"):
                        # grab the first obj
                        buf = text_file.buffer
                        if buf and len(buf) > _min_text_size:
                            if text:
                                text = text + b"\n=====" + unicode(text_file.filename).encode('utf-8') + b"=====\n"
                            text = text + buf

                if text:
                    if len(text) > _max_text_size:
                        text = text[:_max_text_size] + b"\n===MSG TRUNCATED FOR VIEWER===\n"
                    log_record["email_text_plain"] = base64.b64encode(text).decode('utf-8')


        filename = rootUID
        return log_record


    def find_files(self, match_obj, match_list = None, max_depth = None):
        """ 
            Return a list of files within the match_obj dict that have a filename
            that matches any of the patterns in match_list.
        """
        result = []

        for obj in match_obj.values():
            if max_depth is not None and obj.depth > max_depth:
                continue
            if match_list:
                for match in match_list:
                    if fnmatch.fnmatchcase(obj.filename, match):
                        result.append(obj)
                        break
            else:
                result.append(obj)

        return result

    def submitFile(self, senders, rootUID, bucket, storage_type, sub_path, buf, filename):

       logging.debug("Minio - Attempting to send to storage at s3:%s rootUID:%s storage_type:%s, bucket:%s subpath:%s filename:%s" % (self.urls_str, rootUID, storage_type, bucket, sub_path, filename))

       msg = "Unknown problem occured", 500

       try:
          compressed_buf = snappy.StreamCompressor().compress(buf)
       except (QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError):
          raise
       except Exception as e:
           if isinstance(e, QuitScanException):
             raise
           logging.exception("Error compressing file with rootUID: [%s] filename: [%s] storage_type: [%s] bucket: [%s] leaving uncompressed"%(rootUID, sub_path, storage_type, bucket))
           compressed_buf = buf

       sender_strs = senders[0]
       sender_handles = senders[1]

       for idx, sender in enumerate(sender_handles):
            try:
                msg = write_to_minio(sender, sender_strs[idx], bucket, sub_path, compressed_buf)

            except (QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError):
               raise
            except Exception as e:
                logging.exception("Problem writing to s3 server: [%s]"%(sender_strs[idx]))
                msg = "Problem writing to s3 server: %s\n"%(sender_strs[idx]), 500

            self.log_entry(rootUID, sender_strs[idx], bucket, storage_type, sub_path, len(buf), len(compressed_buf), str(msg[1]), filename)

            if msg[1] in [200, 409]:
                break

       if msg[1] not in [200, 409]:
           logging.error("Minio - Error writing to any s3 server - giving up and writing to disk: [%s]"%(msg[0]))

           store = {"bucket_name":bucket, "operation": storage_type, "filename": sub_path, "ver": _submitstorage_version, "rootUID": rootUID}

           store["buffer"] = encode_buf(compressed_buf).decode('utf-8')
           store_str = json.dumps(store, ensure_ascii=False)

           if not isinstance(store_str, bytes):
              store_str = store_str.encode('utf-8', errors='replace')

           # make sure its unique because it could be cached files from the same rootUid
           randstr = binascii.hexlify(os.urandom(5))
           val = datetime.datetime.utcnow().strftime("%Y-%m-%d_%H:%M:%SZ") + '-' + str(rootUID) + '-' + str(storage_type) + '-' + str(randstr) + ".submit"
           path = os.path.join(self.error_queue_dir,val)
           logging.warn("Minio - Storing op:%s id:%s which couldn't be pushed.  Saved as file:%s" % (storage_type, rootUID, path))

           tmpfile = path + ".partial"

           # make sure we don't accidently push partial files
           with open(tmpfile, 'wb') as f:
               f.write(store_str)

           os.rename(tmpfile, path)

       return msg

    def log_entry(self, rootUID, url, bucket, storage_type, sub_path, uncompressed_bytes, compressed_bytes, resp_code, filename):
        lock_filename = self.log_path + ".lock"

        with open(lock_filename, 'w') as lock_fh:
          try:
            lock = Lock(lock_fh)
          except Exception as e:
            logging.error("Could not open lock file, %s: %s" % (lock_filename, str(e)))
            raise RuntimeError("Could not lock/unlock log file for logging", lock_filename, ':', str(e))

          lock.acquire()

          today = datetime.datetime.utcnow()

          filename = filename.encode('utf-8')

          # removes special characters which break prometheus monitoring scripts (mostly newlines)
          filename = quote(filename, safe='/:')

          try:
            entries = [today.strftime("%Y-%m-%d %H:%M:%SZ"), url, rootUID, bucket, storage_type, sub_path, str(uncompressed_bytes), str(compressed_bytes), str(resp_code), str(filename)]
            entry = str('\t'.join(entries)).encode('utf-8')
            self.log.write(entry + b"\r\n")
          except Exception as e:
            logging.exception('Failed to write to logfile')

          lock.release()

def gen_storage_details(rootUID, bucket, storage_type, hash_str, interval=1, levels=3):

    orig_dt = get_date_from_uuid(rootUID)
    cache_dt = orig_dt

    filename = hash_str

    if storage_type == 'json':
       filename = rootUID

    if interval > 1:

       today = datetime.datetime.now()
       day_of_year = (orig_dt - datetime.datetime(orig_dt.year, 1, 1)).days
       day_of_year_cache = int(day_of_year / interval) * interval
       cache_dt = datetime.timedelta(days=day_of_year_cache) + datetime.datetime(orig_dt.year, 1, 1)

    cache_dt_str  = cache_dt.strftime("%Y-%m-%d")

    sub_path = "%s/%s/" % (cache_dt_str, storage_type)

    for x in range(0, levels*2, 2):
       sub_path += (filename[x:x+2] + "/")

    sub_path += filename

    return orig_dt, bucket, sub_path
