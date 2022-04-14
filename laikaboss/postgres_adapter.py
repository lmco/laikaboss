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
from builtins import str
from builtins import object
import datetime
import hashlib
import json
import os
import sys
import tempfile
import time
import copy

import logging
import sqlalchemy
from sqlalchemy import (
    Column,
    create_engine,
    ForeignKey,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    DateTime,
)
from sqlalchemy.engine.url import URL
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.sql import select, update
from sqlalchemy.types import JSON, ARRAY


class postgres(object):

    """
    Purpose: Sets up initial postgres_adapter
    Parameters:
        db: (String) db to connect to
    returns:
        N/A
    """

    def __init__(self, host, port, username, password, database="laikaboss"):

        connection_info = {
            "drivername": "postgresql",
            "host": host,
            "port": port,
            "username": username,
            "password": password,
            "database": database,
        }

        self.log = logging

        self.connected = False

        self.con = create_engine(URL(**connection_info), client_encoding="utf8")
        self.meta = MetaData(bind=self.con)

        self.connected = True

    """
    Purpose: Create and connect to a table holding only keys and ints
    Parameters:
        table: (String) table to connect to
        primary_key: (String) the primary key
    returns:
        N/A
    """

    def connect_int_table(self, table="test_int"):
        try:
            self.table = Table(
                table,
                self.meta,
                Column("key", String, nullable=False, primary_key=True),
                Column("val", Integer, nullable=False),
                keep_existing=True,
            )
            ins = sqlalchemy.inspect(self.con)
            if not ins.has_table(table):
                self.meta.create_all(self.con, checkfirst=True)
        except Exception as e:
            self.log.exception("Unable to create Postgres table: [%s]" % (e))
            self.connected = False

    def put_int(self, key, val, ignore_duplicate=True):
        """
        Purpose: put_int - insert or int value
        Parameters:
            primary_key: (String) primary key to query against
            val: (String) value of primary key
        returns:
            Boolean based on success, error_message
        """
        if not self.connected:
            return False, None

        result = None
        is_success = False

        try:
            i = insert(self.table)
            i = i.values({"key": key, "val": val})

            result = self.con.execute(i)
            if result.inserted_primary_key is None:
                val = "Unable to write to Postgres DB: [%s]" % (e)
                self.log.error(val)
            else:
                is_success = True
        except sqlalchemy.exc.IntegrityError as e:
            if "duplicate" in str(e):
                is_success = True
            else:
                val = "Unable to write to Postgres DB: [%s]" % (e)
                self.log.error(val)
        except Exception as e:
            val = "Unable to write to Postgres DB: [%s]" % (e)
            self.log.error(val)

        # except psycopg2.IntegrityError, e:
        return is_success, val

    def get_int(self, key):
        """
        Purpose: get from db, if it exists return the int value, otherwise none
        Parameters:
            key: (String) primary key value to query against
        returns:
            Boolean based on success, a copy of the int or None
        """
        result = None

        is_success = False

        if not self.connected:
            return False, None

        try:
            clause = select([self.table.c["val"]]).where(self.table.c["key"] == key)
            res = self.con.execute(clause).fetchone()

            is_success = True

            # row already exists in table
            if res:
                result = res[0]

        except Exception as e:
            self.log.error("Unable to read from Postgres DB: [%s]" % (e))
            self.log.error("KEY: %s" % (key))
            is_success = False

        return is_success, result

    """
    Purpose: Closes the connection
    Parameters:
        N/A
    returns:
        N/A
    """

    def close(self):
        if not self.connected:
            return

        self.con.dispose()
