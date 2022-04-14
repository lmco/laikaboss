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
from builtins import oct
import os
import json
import logging

from .auth import auth_routes
from .status import status_routes
from .scan import scan_routes
from .storage import storage_routes
from .info import info_routes

from laikarest.utils import write_jwks_file
from laikarest.utils import load_ldap_settings
from laikarest.utils import load_auth_settings
from laikarest.utils import load_oauth_settings
from laikaboss.storage_utils import redisclient_from_url
from laikarest.authentication.auth import LaikaRestAuth

def init_app(app, laikarest_config, storage_gui_config):

    redis_url = laikarest_config["redis_url"]

    if not redis_url:
        errmsg = "redis_url is not defined exiting"
        logging.error("redis_url is not defined exiting laikarestd_config:%s" % (laikarest_config,))
        raise ValueError(errmsg)

    logging.info("loading redis_url:'%s'" % (str(redis_url),))

    ldap_config = load_ldap_settings(laikarest_config)
    auth_config = load_auth_settings(laikarest_config)
    oauth_config = load_oauth_settings(laikarest_config)

    redis_client = redisclient_from_url(redis_url)

    max_size = int(laikarest_config["max_submission_size"])
    jwt_enabled = True if laikarest_config.get("jwt_enabled", "false").lower() == "true" else False

    if max_size > 0:
       app.config['MAX_CONTENT_LENGTH'] = max_size

    jwt_settings = {}

    if jwt_enabled:
        client_secret_file = laikarest_config["lb_client_secret_file"]
        client_secret_var = "CLIENT_SECRET"
        if client_secret_var in os.environ:
            app.config["LB_CLIENT_SECRET"] = os.environ[client_secret_var]
        else:
            st = os.stat(client_secret_file)
            if oct(st.st_mode)[-1:] != "0":
                errmsg = "lb_client_secret_file %s file does not have proper permissions. Ensure not readable or writable by other. ie. chmod 400 <password_file>" % (
                    client_secret_file
                )
                logging.error(errmsg)
                raise ValueError(errmsg)

            with open(client_secret_file, "r") as f:
                tmp = f.readline().strip()
                app.config["LB_CLIENT_SECRET"] = tmp

        write_jwks_file(laikarest_config["remote_jwks_file_location"], laikarest_config["local_jwks_file_location"])
        jwt_settings[oauth_config["oauth_issuer"]] = {
            "keyfile.public": laikarest_config["local_jwks_file_location"], 
            "issuer": oauth_config["oauth_issuer"],
            "audience": oauth_config["oauth_audience"],
            "claim": oauth_config["oauth_claim"],
            "scope": oauth_config["oauth_scope"]
        }
        jwt_settings[oauth_config["oauth_internal_issuer"]] = {
            "keyfile.public": oauth_config["oauth_keyfile_public_internal"], 
            "issuer": oauth_config["oauth_internal_issuer"],
            "audience": oauth_config["oauth_audience"],
            "claim": oauth_config["oauth_claim"],
            "scope": oauth_config["oauth_scope"]
        }

    logging.debug("Oauth settings: \n" + json.dumps(jwt_settings, indent=2))

    laika_auth = LaikaRestAuth(ldap_config, auth_config, jwt_settings, redis_client, laikarest_config.get("ca_certificate"))

    auth_routes(app, laikarest_config, laika_auth)
    info_routes(app, laikarest_config, storage_gui_config, laika_auth, redis_client)
    status_routes(app, laikarest_config, laika_auth, redis_client)
    scan_routes(app, laikarest_config, laika_auth, redis_client)
    storage_routes(app, laikarest_config, storage_gui_config, laika_auth, redis_client)
