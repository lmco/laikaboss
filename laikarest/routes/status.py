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
import json
import time
import logging

from flask import g
from flask import request
from flask import Response

from laikarest.utils import str2bool
from laikarest.authentication.decorators import enforce_auth

def status_routes(app, config, laika_auth, redis_client):
    """Setup all routes related to checking the status of a scan

    Args:
        app (flask.Flask) flask web server
        config (dict): A dictionary containing all the items
            specified in the config file/environment vars.
        laika_auth (laikarest.authentication.auth.LaikaRestAuth)
            used for authentication and session management
    """

    _timeout = None
    try:
        _timeout = int(config.get("redis_status_timeout_secs", "500"))
    except ValueError:
        logging.error('failed to cast redis_status_timeout_secs to integer')
        _timeout = 500


    @app.route("/laika/oauth/status/<id1>", methods=["GET"])
    @app.route("/oauth/status/<id1>", methods=["GET"])
    @app.route("/status/<id1>", methods=["GET"])
    @app.route("/laika/api/v1/result", methods=["GET"])
    @enforce_auth(laika_auth=laika_auth)
    def id_status(id1=None):
        sync = str2bool(request.form.get("sync"))
        sync_status = request.form.get("sync_status")
        custom_timeout = request.form.get("timeout")
        if sync:
            # Do a regular status check first if a specific status was requested, 
            # just in-case that status is already available
            try:
                status = redis_client.hgetall(id1)
                if status:
                    new_status = {}
                    for key in status: # convert all data to unicode for the json module
                        new_status[key.decode('utf-8')] = status[key].decode('utf-8')
                    if sync_status and new_status.get("status") == sync_status:
                        return Response(json.dumps(new_status), mimetype="application/json")
            except:
                pass

            p = redis_client.pubsub(ignore_subscribe_messages=True)
            try:
                p.subscribe(id1)
            except:
                return Response(json.dumps({"status": "not found"}), mimetype="application/json", status=501)

            timeout = int(time.time()) + _timeout
            if custom_timeout:
                try:
                    timeout = int(time.time()) + int(custom_timeout)
                except ValueError:
                    pass
            while int(time.time()) < timeout:
                val = None
                data = p.get_message()
                if data:
                    # val is a string not json
                    val = data.get("data", None)
                    if isinstance(val, bytes):
                        val = val.decode('utf-8')
                    if not sync_status or json.loads(val).get("status") == sync_status:
                        break
                time.sleep(0.1)

            if val:
                return Response(val, mimetype="application/json")
            else:
                return Response(
                    json.dumps({"status": "timed out"}),
                    mimetype="application/json",
                    status=102
                )

        try:
            if not id1:
                id1 = request.args.get("uuid", None)
            status = redis_client.hgetall(id1)
            logging.info("Got status: %s %s" % (str(id1), str(status)))
            if status:
                # Convert all keys to unicode
                new_status = {}
                for key in status: # convert all data to unicode for the json module
                    new_status[key.decode('utf-8')] = status[key].decode('utf-8')
                status = new_status
                # Do conversion for menlo if necessary
                if request.path == "/laika/api/v1/result":
                    menlo_status = {}
                    lb_status = status.get("status", "")
                    if lb_status == "complete":
                        disposition = status.get("disposition", "")
                        if "Accept" in disposition or "Alert" in disposition:
                            menlo_status["outcome"] = "clean"
                        elif "Deny" in disposition:
                            menlo_status["outcome"] = "infected"
                            menlo_status["outcome_categorization"] = "malware"
                        else:
                            menlo_status["outcome"] = "unknown"
                        rootUID = status.get("rootUID", "")
                        if rootUID:
                            menlo_status["report_url"] = request.host_url + \
                                                        "search/" + rootUID
                        menlo_status["result"] = "completed"
                    elif lb_status == "processing":
                        menlo_status["result"] = "pending"
                    elif lb_status == "submitted":
                        menlo_status["result"] = "pending"
                    else:
                        menlo_status["result"] = "unknown"
                    status = menlo_status
                return Response(json.dumps(status), mimetype="application/json")
            else:
                return Response(
                    json.dumps({"status": "not found"}), 
                    mimetype="application/json", 
                    status=404
                )
        except Exception as e:
            app.logger.exception("error {}".format(e))
            return Response(
                json.dumps({"status": "failed", "errmsg": str(e)}), 
                status=501
            )
