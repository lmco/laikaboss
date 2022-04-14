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
from builtins import str
import json
import time
import logging
from datetime import datetime

from flask import g
from flask import request
from flask import Response

from laikaboss.postgres_adapter import postgres
from laikarest.authentication.decorators import enforce_auth

def info_routes(app, config, storage_gui_config, laika_auth, redis_client):
    """These routes return information regarding the laikarestd instance.

    Args:
        app (flask.Flask) flask web server
        storage_gui_config (dict): Options related to storing scans
        config (dict): A dictionary containing all the items
            specified in the config file/environment vars.

    """

    def check_for_cookie(self, request):
        session_id = request.cookies.get('session_id')
        if not session_id:
            raise AuthMethodNotInUse("Cookie session not set")

        username = self.redis_client.get("session:{}".format(session_id))
        if isinstance(username, bytes):
            username = username.decode('utf-8')
        if not username:
            raise AuthAttemptedButFailed("Session is no longer valid")

        return username

    hostname = storage_gui_config['hostname']
    source_postfix = hostname.split('.')[0] if "." in hostname else hostname
    default_source = "webUI-{}".format(source_postfix)

    @app.route("/laika/oauth/source", methods=["GET"])
    @app.route("/oauth/source", methods=["GET"])
    @app.route("/source", methods=["GET"])
    @enforce_auth(laika_auth=laika_auth)
    def source():
        """ Returns the source= value for scan submissions """
        return Response(json.dumps({ "source": default_source }))

    @app.route("/laika/oauth/explain/<root_uid>", methods=["POST"])
    @app.route("/oauth/explain/<root_uid>", methods=["POST"])
    @app.route("/explain/<root_uid>", methods=["POST"])
    @enforce_auth(laika_auth=laika_auth)
    def explain(root_uid):
        """Track PDF URL Explanation Metrics"""
        session_id = request.cookies.get('session_id')
        username = redis_client.get("session:{}".format(session_id))
        if isinstance(username, bytes):
            username = username.decode('utf-8')
        data = request.get_json()
        data["root_uid"] = root_uid
        data["username"] = username
        date_time = datetime.now().strftime("%m-%d-%Y-%H")
        with open(f"/var/log/laikaboss/explain_metrics-{date_time}.log", "a+") as f:
            f.write(f"{json.dumps(data)}\n")
        return Response(json.dumps({ "status": "metric recorded" }))
