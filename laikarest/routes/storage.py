from builtins import str
import os
import re
import json
import time
import uuid
import shutil
import logging
import tempfile
import datetime
import collections
import binascii

import pyminizip

from flask import g
from flask import url_for
from flask import request
from flask import redirect
from flask import Response
from flask import after_this_request
from flask import send_from_directory

from natsort import natsorted

from laikaboss.postgres_adapter import postgres
from laikarest.authentication.decorators import enforce_auth
from laikarest.utils import generate_uuid_date
from laikarest.storage import storage_config_parser
from laikarest.storage.storage_helper import StorageHelper

from laikarest.routes.scan import scan

from future.standard_library import install_aliases
install_aliases()
from urllib.parse import unquote_plus, quote_plus

def _construct_key(previous_key, separator, new_key):
    """
    MIT License
    Copyright (c) 2016 Amir Ziai

    Returns the new_key if no previous key exists, otherwise concatenates previous key, separator, and new_key
    :param previous_key:
    :param separator:
    :param new_key:
    :return: a string if previous_key exists and simply passes through the new_key otherwise
    """
    if previous_key:
        return u"{}{}{}".format(previous_key, separator, new_key)
    else:
        return new_key


def flatten(nested_dict, separator=".", root_keys_to_ignore=set()):
    """
    MIT License
    Copyright (c) 2016 Amir Ziai

    Flattens a dictionary with nested structure to a dictionary with no hierarchy
    Consider ignoring keys that you are not interested in to prevent unnecessary processing
    This is specially true for very deep objects
    :param nested_dict: dictionary we want to flatten
    :param separator: string to separate dictionary keys by
    :param root_keys_to_ignore: set of root keys to ignore from flattening
    :return: flattened dictionary
    """
    assert isinstance(nested_dict, dict), "flatten requires a dictionary input"
    assert isinstance(separator.decode('utf-8'), str), "separator must be a string"

    # This global dictionary stores the flattened keys and values and is ultimately returned
    flattened_dict = dict()

    def _flatten(object_, key):
        """
        MIT License
        Copyright (c) 2016 Amir Ziai

        For dict, list and set objects_ calls itself on the elements and for other types assigns the object_ to
        the corresponding key in the global flattened_dict
        :param object_: object to flatten
        :param key: carries the concatenated key for the object_
        :return: None
        """
        if isinstance(object_, dict):
            for object_key in object_:
                if not (not key and object_key in root_keys_to_ignore):
                    _flatten(object_[object_key], _construct_key(key, separator, object_key))
        elif isinstance(object_, list) or isinstance(object_, set):
            #all_strings ensures that lists that don't have any additional JSON objects don't get split out
            all_strings = True
            for index, item in enumerate(object_):
                if isinstance(item, dict) or isinstance(item, list):
                    all_strings = False

            # get all the values in the list and keep them in a list
            if all_strings:
                strings_val_list = []
                for index, item in enumerate(object_):
                    strings_val_list.append(item)
                flattened_dict[key+ '{}'] = strings_val_list
                #the below will make the values a long string rather than a list
                #flattened_dict[key+ '{}'] = ", ".join(strings_val_list)

            else:
                for index, item in enumerate(object_):
                    _flatten(item, _construct_key(key, separator, index))
        else:
            flattened_dict[key] = object_

    _flatten(nested_dict, None)

    #my_fun = lambda k,v: [k, int(v)]
    #d2 = collections.OrderedDict(sorted(flattened_dict.items(), key=lambda t: my_fun(*re.match(r'([a-zA-Z]+)(\d+)',t[0]).groups())))
    sorted_flat_dict = collections.OrderedDict(natsorted(list(flattened_dict.items())))
    #logger.log.exception(sorted_flat_dic)

    return sorted_flat_dict


def flatten_scan_result(scan_result, storage_format=1):
    """ Flatten a typical LB scan result for viewing ease.

    Raises:
        ValueError: If scan_result couldn't be flattened
    Returns:
        flattened (dict): "restructured dictionary"
    """
    scan_summary_obj = None
    scan_complete_obj = None
    if storage_format == 1:
        if "log_complete" not in scan_result:
            return flatten(scan_result)

        scan_summary_obj = scan_result.get("log_summary")
        scan_complete_obj = scan_result['log_complete']
    else:
       raise ValueError("Unknown storage format")

    scan_summary_obj = scan_result.get("log_summary")
    scan_complete_obj = scan_result['log_complete']
    flattened = {}
    try:
        if isinstance(scan_result, list):
            # laikaboss scan_results include embedded json strings
            # That is why json.loads is required again
            flattened['splunk_summary'] = scan_summary_obj[0]
        else:
            flattened['splunk_summary'] = scan_summary_obj
    except ValueError as e:
        return flatten(scan_result)
    flattened['splunk_nonsummary'] = [ item for item in scan_complete_obj ]

    if 'email_text_plain' in scan_result:
        flattened['email_text_plain'] = scan_result['email_text_plain']

    if 'email_text_from_html' in scan_result:
        flattened['email_text_from_html'] = scan_result['email_text_from_html']

    flattened["is_email"] = 'email_text_plain' in scan_result or 'email_text_from_html' in scan_result or (
        isinstance(flattened.get('splunk_summary'), dict) and \
        'eml' in flattened['splunk_summary'].get('fileType', '')
    ) or ( 
        isinstance(flattened.get('splunk_nonsummary'), list) and \
        len(flattened.get('splunk_nonsummary')) > 0 and \
        'eml' in flattened.get('splunk_nonsummary')[0].get('fileType', '')
    )

    return flattened

def slugify(value):
    """
        Normalizes string, converts to lowercase, removes non-alpha characters,
        and converts spaces to hyphens.
    """
    import unicodedata
    value = unicodedata.normalize('NFKD', value).encode('ascii', 'ignore')
    value = re.sub(b'[^.\w\s-]', b'', value.strip().lower())
    value = re.sub(b'[-\s]+', b'-', value)
    return value.decode('ascii')

def storage_routes(app, config, storage_gui_config, laika_auth, redis_client):
    """Setup all routes related to using our s3 type stores

    Args:
        app (flask.Flask) flask web server
        config (dict): A dictionary containing all the items
            specified in the config file/environment vars.

    """

    storage_helper = StorageHelper(storage_gui_config)
    hostname = storage_gui_config['hostname']
    attachment_zip_password = storage_gui_config.get("attachment_zip_password", "infected")
    default_source = "webUI-{}".format(hostname)

    def search_json_buckets(uuid_date, rootUID):
        sub_path_format_1 = "{}/{}/{}/{}".format(rootUID[:2], rootUID[2:4], rootUID[4:6], rootUID)
        found_in_bucket = None
        object_content = ''
        method_that_succeeded = None
        for bucket_name in storage_helper.bucket_list_with_rootUIDs:
            try: 
                b_name ='email' if bucket_name == 'storage-json' else bucket_name.split('-')[0]
                s_path = uuid_date[:-1] + "/json/" + sub_path_format_1
                logging.info("bucket: {}, subpath: {}".format(b_name, s_path))
                object_content = storage_helper.query_bucket_for_object(b_name, s_path, storage_format=1)
                if object_content is not None and len(object_content) > 0:
                    # we got a result from minio
                    method_that_succeeded = 1
                    found_in_bucket = b_name
                    logging.info('Succeeded with s3 storage format 1')
                    break
                raise ValueError
            except:
                logging.error('Did not find the rootUID: [{}] in bucket [{}].'.format(rootUID, s_path))
                continue

        sub_path = sub_path_format_1


        return found_in_bucket, object_content, method_that_succeeded, sub_path

    def send_invalid_rootUID():
        return Response(
            json.dumps({"error": "RootUID is not valid!"}), 
            status=400
        )

    def send_no_results_found():
        return Response(
            json.dumps({'message': "No results found"}),
            status=404
        )

    def send_check_input_error_message(param):
        return Response(
            json.dumps({'error': "Check param [{}]".format(param)}),
            status=400
        )

    def generic_server_failure_message():
        return Response(
            json.dumps({'message': "Check server logs", "error": True}),
            status=500
        )

    @app.route("/laika/oauth/rescan", methods=["POST"])
    @app.route("/oauth/rescan", methods=["POST"])
    @app.route("/rescan", methods=["POST"])
    @enforce_auth(laika_auth=laika_auth)
    def rescan():
        req_data = request.get_json()
        if req_data == None or "rootuids" not in req_data:
            return Response(json.dumps({"errmsg": "atleast 1 rootUID must be provided"}), status=400)
        if not isinstance(req_data["rootuids"], list):
            return Response(json.dumps({"errmsg": "list of rescans must be a list"}), status=400)

        args = {}
        submit_to_splunk = req_data.get('submit_to_splunk', False)
        if isinstance(submit_to_splunk, bool):
            args['submit_to_splunk'] = submit_to_splunk
        else:
            return send_check_input_error_message('submit_to_splunk')

        submit_to_storage = req_data.get('submit_to_storage', False) 
        if isinstance(submit_to_storage, bool):
            args['submit_to_storage'] = submit_to_storage
        else:
            return send_check_input_error_message('submit_to_storage')

        save_all_subfiles = req_data.get('save_all_subfiles', False)
        if isinstance(save_all_subfiles, bool):
            args['save_all_subfiles'] = save_all_subfiles
        else:
            return send_check_input_error_message('save_all_subfiles')

        source = req_data.get("source")
        content_type = req_data.get("content_type")
        ephid = req_data.get("ephid")
        uniqid = req_data.get("uniqid")
        external_metadata = {'args': args}
        if 'external_metadata' in req_data:
            external_metadata_json = req_data.get('external_metadata')
            external_metadata.update(external_metadata_json)
        external_metadata = json.dumps(external_metadata)

        def rootUIDResult(rootUID, value):
            """ Helper function to populate per-rootUID scan results"""
            result = {}
            result[rootUID] = value
            return result

        results = []

        # Who is submitting this anyway?
        submitter = request.environ.get("REMOTE_USER", "-")

        # make sure all the rootUIDs are valid
        for rootUID in req_data["rootuids"]:
            if not rootUID:
                continue
            try:
                uuid_date = generate_uuid_date(rootUID)
            except Exception as e:
                logging.exception(e)
                results.append(rootUIDResult(rootUID, "Not a valid rootUID"))
                continue

            found_in_bucket, object_content, method_that_succeeded, sub_path = search_json_buckets(uuid_date, rootUID)

            if object_content is None or len(object_content) == 0:
                results.append(rootUIDResult(rootUID, "No content in scan result"))
                continue

            logging.info("JSON {} found in bucket {}".format(rootUID, found_in_bucket))
            logging.info("{} was found with method {}".format(rootUID, method_that_succeeded))
            try:
                # convert to dict
                scan_result = storage_helper.get_json_from_text(object_content)
            except Exception as e:
                logging.exception(e)
                results.append(rootUIDResult(rootUID, "Could not parse retrieved scan as JSON"))
                continue

            # Get top-level information
            try:
                fallback_bucket_type = found_in_bucket[11:-5] # For legacy api
                root_bucket_name, root_subpath = storage_helper.storage_bucket_info(scan_result, fallback_bucket_type, storage_format=method_that_succeeded)
                storage_filename = root_subpath.split('/')[-1:][0]
            except Exception as e:
                logging.exception(e)
                results.append(rootUIDResult(rootUID, "Failed to retrieve raw file location"))
                continue

            # Get raw content
            try:
                root_object_content = storage_helper.query_bucket_for_object(root_bucket_name, root_subpath, storage_format=method_that_succeeded)
                if root_object_content is None:
                    raise ValueError("Got an empty file")
            except Exception as e:
                logging.exception(e)
                results.append(rootUIDResult(rootUID, "Could not retrieve raw file from storage."))
                continue

            # Get scan metadata
            try:
                metadata = storage_helper.get_metadata(scan_result, storage_format=method_that_succeeded)
                if not external_metadata:
                    external_metadata = storage_helper.get_external_metadata(scan_result, storage_format=method_that_succeeded)
                    external_metadata = json.dumps(external_metadata)
            except Exception as e:
                logging.exception(e)
                results.append(rootUIDResult(rootUID, "Failed to pull metadata"))
                continue

            # Use old original rootUID if present (for rescans of rescans)
            orig_root_uid = metadata.get("origRootUID", rootUID)
            if orig_root_uid == 'None' or orig_root_uid == '':
                orig_root_uid = rootUID
            if not ephid:
                ephid = metadata.get('ephID')
            if not content_type:
                content_type = metadata.get('contentType')
            if not uniqid:
                uniqid = metadata.get('uniqID')
            if not source or source == 'email-laikarest-1':
                prev_source = scan_result.get("source")
                if not prev_source:
                    prev_source = default_source
                if not "-rescan" in prev_source:
                    prev_source += '-rescan'
                source = prev_source

            filename = metadata.get('filename')
            submitID = binascii.hexlify(os.urandom(10)).decode('ascii')

            logging.info("Rescan INFO: {}, {}, {}, contentType:{}, filename: {}, source: {}".format(
                    orig_root_uid,
                    ephid,
                    uniqid,
                    content_type,
                    filename,
                    source
                )
            )

            try:
                store = {
                    "submitter": submitter,
                    "comment": "",
                    "queue": "WebUI",
                    "filename": filename,
                    "ephID": ephid,
                    "uniqID": uniqid,
                    "extMetaData": external_metadata,
                    "source": source,
                    "contentType": content_type,
                    "origRootUID": orig_root_uid,
                    'submitID': submitID,
                    'extArgs': {}, # legacy args
                    "ver": config.get("version", "unknown"),
                }

                scan(root_object_content, store, submitID, config.get("submission_dir"), redis_client)

                # if we made it this far, the rescan for this rootuid is submitted successfully
                results.append(rootUIDResult(rootUID, { "scanID": submitID })) 
            except Exception as e:
                logging.exception(e)
                results.append(rootUIDResult(rootUID, "Failed to submit scan"))
                continue

        return Response(
            json.dumps(results),
            status=200
        )

    @app.route('/laika/oauth/sample/<bucket_name>/<path:subpath>', methods=['GET'])
    @app.route('/oauth/sample/<bucket_name>/<path:subpath>', methods=['GET'])
    @app.route('/sample/<bucket_name>/<path:subpath>', methods=['GET'])
    @enforce_auth(laika_auth=laika_auth)
    def get_file(bucket_name, subpath):

        original_filename = request.args.get('original_filename', None)
        storage_format=1

        if not re.search(r"\d{4}-\d{2}-\d{2}", subpath[:11]):
           raise ValueError("subpath does not match needed format %s" % (subpath[:11]))

        object_content=None
        try:
            object_content = storage_helper.query_bucket_for_object(bucket_name, subpath, storage_format=storage_format)
            if object_content is None:
                raise ValueError
        except Exception as e:
            logging.exception(e)
            logging.error("Failed to get subpath {} via bucket {}".format(subpath, bucket_name))

        if object_content is None:
            return send_no_results_found()

        try:
            # Write file content to disk
            json_content_file = storage_helper.create_temp_file(object_content)
            temp_filename = json_content_file.name.split('/')[2]
            attachment_filename = temp_filename
            if original_filename:
                attachment_filename = slugify(original_filename)

            # Replace newlines
            # throws [ValueError: Detected newline in header value. This is a potential security problem] when newlines are present
            attachment_filename = attachment_filename.replace('\n','')
            attachment_filename = u''.join([attachment_filename, '.txt']).strip()
        except Exception as e:
            logging.exception(e)
            logging.error("Failed to serialize returned object as JSON")
            return generic_server_failure_message()

        @after_this_request
        def remove_file(response):
            try:
                os.unlink(json_content_file.name)
            except Exception as e:
                logging.exception(e)
            return response

        try:
            return send_from_directory('/tmp/', temp_filename, as_attachment=True, attachment_filename=attachment_filename)
        except Exception as e:
            logging.exception(e)
            return generic_server_failure_message()


    @app.route("/laika/oauth/json/<rootUID>", methods=["GET"])
    @app.route("/oauth/json/<rootUID>", methods=["GET"])
    @app.route("/json/<rootUID>", methods=["GET"])
    @enforce_auth(laika_auth=laika_auth)
    def download_json(rootUID):
        logging.info("Received request to download JSON rootUID: {}".format(rootUID))
        try:
            uuid_date = generate_uuid_date(rootUID)
        except Exception as e:
            logging.info('[-] rootUID: [{}]. e: [{}]'.format(rootUID, e))
            return send_invalid_rootUID()

        found_in_bucket, object_content, method_that_succeeded, sub_path = search_json_buckets(uuid_date, rootUID)

        if object_content is None or len(object_content) == 0:
            return send_no_results_found()

        # write the json data to a file so that we can return it
        try:
            temp_json_file = tempfile.NamedTemporaryFile(delete=False)
            return_dir = "/tmp/"
            return_name = temp_json_file.name.split("/")[2]

            # write the file stream to a temp file
            with open(temp_json_file.name, 'wb') as json_data:
                json_data.write(object_content)
        except Exception as e:
            logging.exception(e)
            logging.error("rootUID {} json failed to write to temporary file. Error: {}".format(rootUID, e))
            return Response(
                json.dumps({"error": "Failure loading JSON file"}), 
                status=500
            )

        # when the request is finished, remove the files
        @after_this_request
        def remove_file(response):
            try:
                os.unlink(temp_json_file.name)
            except Exception as e:
                logging.exception(e)
                logging.error("rootUID json temporary file failed to be deleted. Error: {}".format(rootUID, e))
            return response

        try:
            return send_from_directory(return_dir, return_name, as_attachment=True, attachment_filename=u''.join((rootUID,"_JSON.txt")).strip())
        except Exception as e:
            logging.exception(e)
        return generic_server_failure_message()


    @app.route("/laika/oauth/zipattachments/<rootUID>", methods=["GET"])
    @app.route("/oauth/zipattachments/<rootUID>", methods=["GET"])
    @app.route("/zipattachments/<rootUID>", methods=["GET"])
    @enforce_auth(laika_auth=laika_auth)
    def download_attachment_zip(rootUID):
        logging.info("Received request to download zip of rootUID: {}".format(rootUID))
        try:
            uuid_date = generate_uuid_date(rootUID)
        except Exception as e:
            logging.info('[-] rootUID: [{}]. e: [{}]'.format(rootUID, e))
            return send_invalid_rootUID()

        found_in_bucket, object_content, method_that_succeeded, sub_path = search_json_buckets(uuid_date, rootUID)

        if object_content is None:
            return send_no_results_found()

        # Try to the object that was found as JSON
        try:
            scan_result = storage_helper.get_json_from_text(object_content)
        except Exception as e:
            logging.exception(e)
            return Response(
                json.dumps({"error": "object content pulled from bucket {} was not valid JSON!".format(found_in_bucket)}),
                status=500
            )

        # Get the interesting attachments
        try:
            attachments = storage_helper.get_interesting_attachments(scan_result, storage_format=method_that_succeeded)
        except Exception as e:
            logging.exception(e)
            logging.error("rootUID: {} could not get attachement names. Error: {}".format(rootUID, e))
            return Response(
                json.dumps({"error": "Could not get the names of interesting attachments"}),
                status=500
            )

        final_dir_name = str(uuid.uuid4())
        final_zip_path = "/tmp/" + final_dir_name
        logging.info('Creating temporary folder {}'.format(final_zip_path))
        try:
            os.mkdir(final_zip_path)
        except Exception as e:
            logging.exception(e)
            return Response(
                json.dumps({"error": "Failed to create zip"}),
                status=500
            )

        # Iterate through the list of attachments, pull each object
        # then proceed to create a new temporary file for each object
        compress_files = []
        try:
            for attachment in attachments:
                object_content=None
                attachment_name = slugify(attachment["file_name"])
                sub_path = attachment["sub_path"]
                file_bucket = attachment["file_bucket"]
                try:
                    object_content = storage_helper.query_bucket_for_object(file_bucket, sub_path)
                    if object_content is None:
                        raise ValueError
                except Exception as e:
                    logging.exception(e)
                    logging.error("Failed to get subpath {} via bucket {}".format(sub_path, file_bucket))

                if not object_content:
                    logging.warn("attachment: {}, for rootUID: {}, was empty".format(attachment_name, rootUID))
                    continue

                with open(final_zip_path + "/" + attachment_name, 'wb') as file_obj:
                    file_obj.write(object_content)
                    compress_files.append(final_zip_path + "/" + attachment_name)
        except Exception as e:
            logging.exception(e)
            return generic_server_failure_message()

        # create the zip file
        try:
            pyminizip.compress_multiple(compress_files, [], final_zip_path + ".zip", attachment_zip_password, 4)
        except Exception as e:
            logging.exception(e)
            return generic_server_failure_message()

        # Once this request is complete delete the zip file and folder
        @after_this_request
        def remove_file(response):
            try:
                shutil.rmtree(final_zip_path)
                logging.info('deleting temporary folder {}'.format(final_zip_path))
                os.unlink(final_zip_path + ".zip")
            except Exception as e:
                logging.exception(e)
                logging.error("rootUID attachment files failed to be deleted. Error: {}".format(rootUID, e))
            return response

        # send the downloaded zip file
        try:
            return send_from_directory("/tmp/", final_dir_name + ".zip", as_attachment=True, attachment_filename=u''.join((rootUID,".zip")).strip())
        except Exception as e:
            logging.exception(e)
            return generic_server_failure_message()


    @app.route("/laika/oauth/get/object/<rootUID>", methods=["GET"])
    @app.route("/oauth/get/object/<rootUID>", methods=["GET"])
    @app.route("/get/object/<rootUID>", methods=["GET"])
    @enforce_auth(laika_auth=laika_auth)
    def download_root_object(rootUID):
        logging.info("Received request to download root buffer of rootUID: {}".format(rootUID))
        try:
            uuid_date = generate_uuid_date(rootUID)
        except Exception as e:
            logging.info('[-] rootUID: [{}]. e: [{}]'.format(rootUID, e))
            return send_invalid_rootUID()

        found_in_bucket, object_content, method_that_succeeded, sub_path = search_json_buckets(uuid_date, rootUID)

        if object_content is None:
            return send_no_results_found()

        # Try to find the object that was found as JSON
        try:
            scan_result = storage_helper.get_json_from_text(object_content)
        except Exception as e:
            logging.exception(e)
            return Response(
                json.dumps({"error": "object content pulled from bucket {} was not valid JSON!".format(found_in_bucket)}), 
                status=500
            )

        # Get top-level information
        try:
            fallback_bucket_type = found_in_bucket[11:-5] # For legacy api
            root_bucket_name, root_subpath = storage_helper.storage_bucket_info(scan_result, fallback_bucket_type, storage_format=method_that_succeeded)
            storage_filename = root_subpath.split('/')[-1:][0]
        except Exception as e:
            logging.exception(e)
            logging.error("rootUID: {} could not get top level file info. Error: {}".format(rootUID, e))
            return Response(
                json.dumps({"error": "Could not get file top-level file info"}), 
                status=500
            )

        redirect_url = url_for("get_file", bucket_name=root_bucket_name, subpath=root_subpath)
        redirect_url += "?original_filename={}".format(rootUID)
        return redirect(redirect_url)

    @app.route("/laika/oauth/memorialize/<rootUID>", methods=["POST"])
    @app.route("/oauth/memorialize/<rootUID>", methods=["POST"])
    @app.route("/memorialize/<rootUID>", methods=["POST"])
    @enforce_auth(laika_auth=laika_auth)
    def memorialize(rootUID):
        logging.info("Received request to memorialize rootUID: {}".format(rootUID))
        try:
            uuid_date = generate_uuid_date(rootUID)
        except Exception as e:
            logging.info('[-] rootUID: [{}]. e: [{}]'.format(rootUID, e))
            return send_invalid_rootUID()

        uuid_date_datetime  = datetime.datetime(*[int(item) for item in uuid_date[:-1].split('-')])
        logging.info('rootUID provided date: {}'.format(uuid_date[:-1]))

        found_in_bucket, object_content, method_that_succeeded, sub_path = search_json_buckets(uuid_date, rootUID)

        if object_content is None or len(object_content) == 0:
            return send_no_results_found()

        logging.debug("{} found in bucket {} with storage format {}".format(rootUID, found_in_bucket, method_that_succeeded))

        if method_that_succeeded == 2:
            logging.error('cannot memorialize accross minio and s3!')
            return Response(
                json.dumps({"error": "The new GUI is not able to memorialize old storage-formats!" }),
                status=422
            )

        # Try to convert the object that was found as JSON
        try:
            scan_result = storage_helper.get_json_from_text(object_content)
        except Exception as e:
            logging.exception(e)
            return Response(
                json.dumps({"error": "object content pulled from bucket {} was not valid JSON!".format(found_in_bucket)}),
                status=500
            )

        full_subpath = "{}/json/{}".format(uuid_date[:-1], sub_path)

        try:
            storage_helper.memorialize(scan_result, found_in_bucket, full_subpath, rootUID)
        except Exception as e:
            logging.exception(e)
            return Response(
                json.dumps({"error": "Failed to memorialized rootUID: {}".format(rootUID)}),
                status=500
            )

        return Response(
            json.dumps({"message": "Successfully memorialized rootUID: {}".format(rootUID)}),
            status=200
        )


    @app.route("/laika/oauth/search/<rootUID>", methods=["POST"])
    @app.route("/oauth/search/<rootUID>", methods=["POST"])
    @app.route('/search/<rootUID>', methods=["POST"])
    @enforce_auth(laika_auth=laika_auth)
    def search(rootUID):
        searcher_username = request.environ.get("REMOTE_USER", "-")
        logging.info("Received request to search rootUID: {} from {}".format(rootUID, searcher_username))
        try:
            uuid_date = generate_uuid_date(rootUID)
        except Exception as e:
            logging.info('[-] rootUID: [{}]. e: [{}]'.format(rootUID, e))
            return send_invalid_rootUID()

        uuid_date_datetime  = datetime.datetime(*[int(item) for item in uuid_date[:-1].split('-')])
        logging.info('rootUID provided date: {} rootUID: {} '.format(uuid_date[:-1], rootUID))

        found_in_bucket, object_content, method_that_succeeded, sub_path = search_json_buckets(uuid_date, rootUID)

        if object_content is None:
            return send_no_results_found()

        # Try to convert the object that was found as JSON
        try:
            scan_result = storage_helper.get_json_from_text(object_content)
        except Exception as e:
            logging.exception("value prefix:'{}' found_in_bucket:'{}' method_that_succeeded:'{}' sub_path:'{}' buckets_searched: {}".format(object_content[:20],found_in_bucket,method_that_succeeded,sub_path, storage_helper.bucket_list_with_rootUIDs))
            return Response(
                json.dumps({"error": "object content pulled from bucket {} was not valid JSON!".format(found_in_bucket)}),
                status=500
            )


        # Get the names of interesting attachments
        try:
            attachments = storage_helper.get_interesting_attachments(scan_result, storage_format=method_that_succeeded)
            logging.info('successfully retrieved interesting attachments for {}'.format(rootUID))
        except Exception as e:
            logging.exception(e)
            logging.error("rootUID: {} could not get attachment names. Error: {}".format(rootUID, e))
            attachments = [{
                "file_name": 'Errors pulling interesting attachments',
                "file_bucket": None,
                "file_hash": None,
                "sub_path": None
            }]

        # Get top-level information
        try:
            fallback_bucket_type = found_in_bucket[11:-5] # For legacy api
            root_bucket_name, root_subpath = storage_helper.storage_bucket_info(scan_result, fallback_bucket_type, storage_format=method_that_succeeded)
            storage_filename = root_subpath.split('/')[-1:][0]
        except Exception as e:
            logging.exception(e)
            logging.error("rootUID: {} could not get top level file info. Error: {}".format(rootUID, e))
            return Response(
                json.dumps({"error": "Could not get file top-level file info"}),
                status=500
            )

        # Flatten scan_result for better viewing
        try:
            flat_scan_results = flatten_scan_result(scan_result, storage_format=method_that_succeeded)
        except Exception as e:
            logging.exception(e)
            logging.error("rootUID: {} could not be flattened. Error: {}".format(rootUID, e))
            return Response(
                json.dumps({"error": "Could not flatten scan results."}),
                status=500
            )

        # get root object
        root_object_content = None
        try:
            root_object_content = storage_helper.query_bucket_for_object(root_bucket_name, root_subpath, storage_format=method_that_succeeded)
            if root_object_content is None:
                raise ValueError("Got an empty file")
        except Exception as e:
            logging.exception(e)
            logging.error("rootUID: {} , failed to query root Object. error: {}".format(rootUID, e))
            return Response(
                json.dumps({"error": "Could not retrieve object from storage."}),
                status=500
            )

        header_info=""
        if flat_scan_results['is_email']:
            # All we cared about was the header information for the root object
            # NOTE: Should we display this extra information to the client (or auto-prepare the file for donwload?)
            try:
                header_info = re.split(r"\r\n\r\n|\n\n",root_object_content.decode('utf-8', errors='replace'))[0]
            except Exception as e:
                logging.exception(e)
                logging.error("rootUID: {} failed to extract header, error: {}".format(rootUID, e))

        # Check if memorialized
        is_memorialized = None
        try: 
            is_memorialized = 'yes' if storage_helper.is_memorialized(sub_path) else 'no'
        except Exception as e:
            logging.exception(e)
            is_memorialized = 'unknown'

        if is_memorialized == 'yes':
            for attachment in attachments:
                file_hash = attachment['file_hash']
                attachment['file_bucket'] = storage_helper.memorialized_bucket_name
                attachment['sub_path'] = "{}/{}/{}/{}".format(file_hash[:2], file_hash[2:4], file_hash[4:6], file_hash)

        return Response(
            json.dumps({
                "header_info": header_info,
                "scan_bucket": {
                    "bucket_name": found_in_bucket,
                    "sub_path": sub_path
                },
                "storage_bucket": {
                    "bucket_name": root_bucket_name,
                    "sub_path": root_subpath
                },
                "scan_results": flat_scan_results,
                "search_val": rootUID,
                "is_memorialized": is_memorialized,
                "interesting_attachments": attachments
            }, indent=4, sort_keys=True)
        )
