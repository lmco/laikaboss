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
from __future__ import print_function
from __future__ import division
from builtins import object, str
import uuid
import socket
import base64
import logging
import requests
import datetime

def get_UUID_timestamp(uuid_string):
    """ Attemps to get datetime from rootUID

    Raises:
        ValueError: If not a valid UUID1
    """
    epoch = datetime.datetime(1582, 10, 15)
    uuid_obj = uuid.UUID(uuid_string)
    timestamp = epoch + datetime.timedelta(microseconds = uuid_obj.time/10)
    return timestamp

def generate_uuid_date(uuid_string):
    """ Get datetime encoded into rootUID (UUID version )

    Raises:
        ValueError: If not a valid UUID1 or a valid datetime is not found

    """
    uuid_date = get_UUID_timestamp(uuid_string)
    if not uuid_date:
        raise ValueError("Failed to get date from rootUID [{}]".format(uuid_string))
    return uuid_date.strftime('%Y-%m-%d-')


def write_jwks_file(remote_jwks_file_location, local_jwks_file_location):
    try:
        jwks_file = requests.get(remote_jwks_file_location)
        if jwks_file.text:
            with open(local_jwks_file_location, "w") as f:
                f.write(jwks_file.text)
    except Exception as e:
        print(e)
        logging.exception("Problem with creating the new jwks file: %s" % (e))

def load_ldap_settings(config):
    """ Load all the ldap configuration settings into a dict
    LDAP configuration settings contain an ldap_ prefix.

    Args:
        config (dict): the global config

    Returns:
        (dict) All the ldap_ settings
    """
    ldap_config  = {}
    for key, value in config.items():
        if key.lower().startswith("ldap_"):
            ldap_config[key] = value
    return ldap_config

def load_auth_settings(config):
    """ Load all the auth configuration settings into a dict
    auth configuration settings contain an auth_ prefix.

    Args:
        config (dict): the global config

    Returns:
        (dict): All the auth settings
    """
    auth_config  = {}
    for key, value in config.items():
        if key.lower().startswith("auth_"):
            auth_config[key] = value
    return auth_config

def load_oauth_settings(config):
    oauth_config  = {}
    for key, value in config.items():
        if key.lower().startswith("oauth_"):
            oauth_config[key] = value
    return oauth_config

def get_hostname():
    """ Retrieves the hostname of the machine

    Returns:
        hostname (str): the hostname or "Unknown otherwise"
    """
    hostname = ""
    try:
        hostname = socket.gethostname()
        if "." in hostname:
            hostname = hostname[: hostname.find(".")]
    except:
        hostname = "UNKNOWN"

    return hostname

def encode_buf(buf):
    """ Encoded the provided buffer into base64"""
    if buf:
        bbuf = base64.b64encode(buf)
        return bbuf
    return buf

def str2bool(v):
    """ Convert a string into a boolean """
    return v and str(v.lower()) == "true"


class force_https(object):
    """ A class used by flask to force usage of TLS/SSL."""
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        environ["wsgi.url_scheme"] = "https"
        return self.app(environ, start_response)
