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
import logging

from flask import g
from flask import Flask
from flask_cors import CORS
from flask import g
from werkzeug.middleware.proxy_fix import ProxyFix
from laikaboss.lbconfigparser import LBConfigParser
from laikaboss.storage_utils import redisclient_from_url
from laikarest import routes

def create_flask_app():
    """ Creates a flask web server """
    app = Flask(__name__)
    app.wsgi_app = ProxyFix(app.wsgi_app)
    CORS(app, supports_credentials=True) # Allow requests from different origin
    return app

def setupLoggers(laikarest_config, app):
    logFormatter = logging.Formatter("%(asctime)s - %(process)d [%(levelname)-5.5s]  %(message)s")
    rootLogger = logging.getLogger()

    log_file_path = laikarest_config["log_file"]
    debug = True if laikarest_config.get("debug", '').lower() == 'true' else False
    fileHandler = logging.FileHandler(log_file_path)
    fileHandler.setFormatter(logFormatter)
    app.logger.addHandler(fileHandler)
    rootLogger.addHandler(fileHandler)

    consoleHandler = logging.StreamHandler()
    consoleHandler.setFormatter(logFormatter)
    app.logger.addHandler(consoleHandler)
    rootLogger.addHandler(consoleHandler)

    if debug:
       app.logger.setLevel(logging.DEBUG)
       rootLogger.setLevel(logging.DEBUG)
    else:
      if __name__ != "__main__":
         # if running under gunicorn set the loggers to that level
         gunicorn_logger = logging.getLogger("gunicorn.error")
         app.logger.setLevel(gunicorn_logger.level)
         rootLogger.setLevel(gunicorn_logger.level)
      else:
         app.logger.setLevel(logging.INFO)
         rootLogger.setLevel(logging.INFO)

# create Flask application
app = create_flask_app()

# path to config
config_file = app.config.get("CONFIG_FILE", "/etc/laikaboss/laikarestd.conf")

# environmental variable which if present must contain the client secret, and this overrides config file value
CLIENT_SECRET_VAR = "CLIENT_SECRET"

lb_api_client_id = "laikaboss-api"
lb_api_client_secret_file = "/etc/laikaboss/secrets/client_secret"
default_config = {
    "submission_dir": "/var/laikaboss/submission-queue",
    "lb_client_secret_file": lb_api_client_secret_file,
    "lb_client": lb_api_client_id,
    "lb_grant_type": "unset",
    "jwt_enabled": "False",
    "redis_url" : "redis://127.0.0.1:6379/0",
    "max_submission_size": 100 * 1024 * 1024
}

# Read config file into a dict

# Read config file into a dict
config = LBConfigParser()
config.read(config_file)

laikarest_config = default_config.copy()
laikarest_config.update(config.items("General"))
laikarest_config.update(config.items("laikarestd"))

storage_gui_config = default_config.copy()
storage_gui_config.update(config.items("General"))
storage_gui_config.update(config.items("storage-gui"))

# Setup logging
setupLoggers(laikarest_config, app)

# Register the routes pertaining to this application
routes.init_app(app, laikarest_config, storage_gui_config)

if __name__ == "__main__":
    # Start Flask web server
    # It should be okay to bind to all interfaces because gunicorn is
    # running on production and doesn't expose port 8123 to the world
    # (e.g. binding to all interfaces is convenient for dev work)
    app.run(host="0.0.0.0", port=8123, debug=False)

