# Copyright 2020 National Technology & Engineering Solutions of Sandia, LLC 
# (NTESS). Under the terms of Contract DE-NA0003525 with NTESS, the U.S. 
# Government retains certain rights in this software.
#
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
from future import standard_library
standard_library.install_aliases()
import redis
import json

import configparser
from laikaboss import config
from laikaboss.storage_utils import redisclient_from_url

# configs = ConfigParser.ConfigParser({"exp_period":"172800"})


def create_connection(url, db=0, **kwargs):
    return redisclient_from_url(url, db=db, **kwargs)

def exists(key):
    return create_connection().exists(key)

def store(key, subkey, value):
    """
    key: file hash or url string
    value: dictionary of the metadata for the given file / url
    stores the metadata with its corresponding object in redis database
    """
    print("Storing...")
    # turn python dictionary into a json string for storage (handles complex data structures)
    val = json.dumps(value)
    conn = create_connection()
    # store in redis database
    return conn.hset(key, subkey, val) and conn.expire(key, 172800)
    # conn.expire(key, configs.getint('redis','exp_period'))

def retrieve(key, subkey):
    """
    key: file hash or url string
    returns: value stored at the key (as a python dictionary) or -1 if the key does not
    exist in the redis database
    """
    db = create_connection()
    return json.loads(db.hget(key, subkey))

