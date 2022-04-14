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
import json
import time
import datetime
import logging
import binascii

from flask import g
from flask import request
from flask import Response
from werkzeug.utils import secure_filename
from werkzeug import datastructures

from laikarest.utils import str2bool
from laikarest.utils import encode_buf
from laikarest.authentication.decorators import enforce_auth

from laikaboss.objectmodel import ExternalObject, ExternalVars, ScanResult
from laikaboss.redisClientLib import Client, parse_local_queue_info

def scan(buf, store, submitID, base_submission_dir, redis_client):
    """ Given a file and extra info send that file to be scanned by LB.

    Args:
        buf (str): file content
        store (dict): Extra info to store
        submitID (str): A unique identifier to keep track of scan status. (Hex encoded)
        base_submission_dir (str): A path to where the queue of files to scan is kept on disk
        redis_client (redis.StrictRedis) The place where scan status information
            will be written to.

    Raises:
        Everything and anything. If anything is raised that means the scan was
        probably not submitted successfully

    """
    ext_obj = ExternalObject(buffer=buf, externalVars=ExternalVars(**store))
    store_str = ExternalObject.encode(ext_obj)

    err = False

    now = datetime.datetime.utcnow()
    val = now.strftime("%Y-%m-%d_%H:%M:%SZ") + "-" + str(submitID) + ".submit"

    submission_dir = base_submission_dir

    dir_path = os.path.join(submission_dir, store["queue"])
    if not os.path.isdir(dir_path):
        os.mkdir(dir_path)
    path = os.path.join(dir_path, val)
    logging.info("Storing submission queue %s submitID:%s ephid:%s uniqid:%s as file %s" % (store["queue"], submitID, store["ephID"], store["uniqID"], path))

    # do this so it doesn't load the partial files
    tmpfile = path + ".partial"
    with open(tmpfile, "wb") as f:
        f.write(store_str)

    os.rename(tmpfile, path)

    status = {}
    status["status"] = "submitted"
    status["submit_datetime"] = now.strftime("%Y-%m-%d_%H:%M:%SZ")

    redis_client.hmset(submitID, status)
    redis_client.expire(submitID, int(14 * 24 * 60))


def inline_scan(buf, store, queue_mapping, submitID, redis_client, timeout=60):
    """
    Scan immediately with the Dispatch laikaboss function
    (experimental)
    Args:
        buf (bytes): file content
        store (dict): parameters to ExternalVars
        submitID (str): the submission id of the job
        redis_client (Client): an open connection to the redis job submission queue
    Returns:
        A dictionary that should be sent back to the client
    """
    extVars = ExternalVars(**store)
    extObj = ExternalObject(buf, externalVars=extVars)
    # Other parameters
    queue = queue_mapping.get(store["queue"], "laikacollector")
    QID = "lbworker:%s:%s" % (os.uname().nodename, submitID)
    # Do the actual scan (locally)
    errmsg = ""
    result = ScanResult()
    try:
        client = Client(redis_client=redis_client)
        ql = client.sendMsg(QID, queue, extObj)
        msg = client.recvMsg(QID, timeout=timeout, block=True)
        result = msg.val
    except Exception as e:
        errmsg = str(e)
    resultObj = {}
    resultObj["datetime"] = datetime.datetime.utcnow().strftime('%Y-%m-%d_%H:%M:%SZ')
    if result.rootUID:
        resultObj["rootUID"] = result.rootUID
    if result.disposition:
        resultObj["disposition"] = result.disposition
    if errmsg:
        resultObj["errmsg"] = errmsg
    return resultObj

def scan_routes(app, config, laika_auth, redis_client):
    """Setup all routes related to scanning samples

    Args:
        app (flask.Flask) flask web server
        config (dict): A dictionary containing all the items
            specified in the config file/environment vars.
        laika_auth (laikarest.authentication.auth.LaikaRestAuth)
        redis_client (redis.Redis): connection
    """
    queue_mapping, _ = parse_local_queue_info(config.get("queue_mapping", "webui:lc-webui:1"))

    @app.route("/laika/oauth/scan/<queue>", methods=["POST"])
    @app.route("/oauth/scan/<queue>", methods=["POST"])
    @app.route("/scan/<queue>", methods=["POST"])
    @app.route("/laika/api/v1/submit", methods=["POST"])
    @enforce_auth(laika_auth=laika_auth)
    def scan_route(queue=None):
        if not queue and request.path == "/laika/api/v1/submit":
            queue = "ebz"
        base_submission_dir = config.get("submission_dir")

        # generate submission id.
        # make sure its unique because it could be cached files from the same rootUid
        submitID = binascii.hexlify(os.urandom(10)).decode('ascii')
        request.environ["SUBMITID"] = submitID

        queue = secure_filename(queue)
        source = request.form.get("source", None)
        origRootUID = request.form.get("origRootUID", "")
        filename = request.form.get("filename", "")

        # For legacy purposes only - new submission methods should populate 
        # the 'args' list in external metadata themselves
        legacy_args = {}
        submit_to_splunk = str2bool(request.form.get("submit_to_splunk"))
        submit_to_storage = str2bool(request.form.get("submit_to_storage"))
        submit_to_farm = str2bool(request.form.get("submit_to_farm"))
        if submit_to_splunk:
            legacy_args["submit_to_splunk"] = submit_to_splunk
        if submit_to_storage:
            legacy_args["submit_to_storage"] = submit_to_storage
        if submit_to_farm:
            legacy_args["submit_to_farm"] = submit_to_farm

        content_type = request.form.get("contentType", "")
        ephid = request.form.get("ephID", "")
        uniqid = request.form.get("uniqID", "")
        external_metadata = request.form.get("extMetaData", "")
        inline_scan_flag = request.form.get("inlineScan", False)
        timeout = int(request.form.get("timeout", config.get("inline_scan_timeout", 60)))

        # check the old incorrect capitialization
        if not external_metadata:
            external_metadata = request.form.get("extMetadata", {})

        comment = request.form.get("comment", "")
        submitter = request.environ.get("REMOTE_USER", "-")

        request.environ["EPHID"] = ephid if ephid else "-"
        request.environ["SOURCE"] = source if source else "-"
        responseBody = json.dumps({"submitID": submitID})
        
        #Translate menlo requests
        MENLO_FIELDS = ("userid", "srcuri", "clientip", "sha256", "filename", 
                        "file_type", "filesize")
        if request.path == "/laika/api/v1/submit":
            menlo_ext_metadata = {}
            for field in MENLO_FIELDS:
                menlo_ext_metadata[field] = request.form.get(field, '')
            if not source:
                source = "ebz"
            if menlo_ext_metadata and not external_metadata:
                external_metadata = json.dumps(menlo_ext_metadata)
            responseBody = json.dumps({"uuid": submitID})

        #Check if stuff is missing
        missing = []
        if not source:
            missing.append("source")
        if not request.files:
            missing.append("file")
        if missing:
            return Response(json.dumps({"errmsg": "missing args or files %s" % (str(missing))}), status=501)

        # Make sure we have a good filename
        # Prefer explicit filename from form
        submitted_file = request.files[sorted(request.files.keys())[0]]
        if not filename:
            filename = submitted_file.filename
        filename = secure_filename(filename)
        request.environ["FILENAME"] = filename

        if external_metadata:
            try:
                external_metadata = json.loads(external_metadata)
                if "args" not in external_metadata:
                    external_metadata["args"] = legacy_args
            except Exception:
                app.logger.exception("invalid extMetaData queue:%s, source:%s, submitID:%s, ephID:%s, uniqID:%s path:%s" % (queue, source, submitID, ephid, uniqid, filename))
                return Response(json.dumps({"errmsg": "extMetaData JSON object is not structured correctly"}), status=501)

        if external_metadata and not legacy_args:
           legacy_args = external_metadata.get('args', {})

        try:
            store = {
                "submitter": submitter,
                "comment": comment,
                "queue": queue,
                "filename": filename,
                "ephID": ephid,
                "uniqID": uniqid,
                "extMetaData": external_metadata,
                "source": source,
                "contentType": content_type,
                "origRootUID": origRootUID,
                'submitID': submitID,
                'extArgs': legacy_args,
                "ver": config.get("version", "unknown"),
            }

            buf = submitted_file.read()
            if inline_scan_flag:
                response = inline_scan(buf, store, queue_mapping,
                                            submitID, redis_client, timeout)
                responseBody = json.dumps(response)
            else:
                scan(buf, store, submitID, base_submission_dir, redis_client)

        except Exception as e:
            app.logger.exception("error ")
            return Response(json.dumps({"errmsg": str(e)}), status=501)

        return Response(responseBody, mimetype="application/json")
