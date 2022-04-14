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
import requests

from flask import g
from flask import request
from flask import Response
from flask import redirect

from laikaboss.postgres_adapter import postgres
from laikarest.authentication.decorators import enforce_auth

from future.standard_library import install_aliases
install_aliases()
from urllib.parse import unquote_plus, quote_plus

def auth_routes(app, config, laika_auth):
    """Setup all routes related to authentication

    Args:
        app (flask.Flask) flask web server
        config (dict): A dictionary containing all the items
            specified in the config file/environment vars.
    """

    @app.route("/laika/oauth/auth", methods=["GET", "POST"])
    @app.route("/oauth/auth", methods=["GET", "POST"])
    @app.route("/auth", methods=["GET", "POST"])
    @enforce_auth(laika_auth=laika_auth)
    def auth():
        return Response(json.dumps({ "message": 'success!' }))

    @app.route("/laika/oauth/sso", methods=["GET"])
    @app.route("/oauth/sso", methods=["GET"])
    @app.route("/sso", methods=["GET"])
    @enforce_auth(laika_auth=laika_auth)
    def sso():
        try:
            redirect_url = unquote_plus(request.args.get("redirect", type=str))
        except Exception as e:
            logging.exception(e)
            return Response("failed to redirect", status=400)
        return redirect(redirect_url, code=302)

    @app.route("/connect/token", methods=["POST"])
    def connect_token_shim():
        missing = []

        oauth_connect_url = config["oauth_connect_url"]
        local_client_id = config["lb_client"]

        username = ""
        if "username" in request.form:
            username = request.form["username"]

        password = ""
        if "password" in request.form:
            password = request.form["password"]

        if "grant_type" not in request.form:
            missing.append("client_id")
        else:
            grant_type = request.form["grant_type"]

        if "client_id" not in request.form:
            missing.append("client_id")
        else:
            client_id = request.form["client_id"]

        client_secret = ""
        if "client_secret" in request.form:
            client_secret = request.form["client_secret"]

        if "scope" not in request.form:
            missing.append("scope")
        else:
            scope = request.form["scope"]

        if missing:
            return Response(json.dumps({"errmsg": "missing args or files %s" % (str(missing))}), status=501)

        headers = request.headers

        if "Authorization-Shim" in headers or "Host" in headers:
            # default type from request is immuntable and a straight copy fails
            headers = {key: value for (key, value) in headers.items()}

            if "Authorization-Shim" in headers:
                headers["Authorization"] = headers["Authorization-Shim"]
                del headers["Authorization-Shim"]

            if "Host" in headers:
                del headers["Host"]

        # if they requested the same client id we have the secret for, fill it in, otherwise just pass it through
        if client_id == local_client_id:
            client_secret = app.config["LB_CLIENT_SECRET"]

        data = {
            "grant_type": grant_type, 
            "scope": scope, 
            "client_id": client_id, 
            "client_secret": client_secret
        }

        if username:
            data["username"] = username
            data["password"] = password

        resp = requests.post(oauth_connect_url, data=data, headers=headers)

        return (resp.content, resp.status_code, list(resp.headers.items()))
