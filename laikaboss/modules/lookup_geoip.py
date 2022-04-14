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
from laikaboss.si_module import SI_MODULE
from laikaboss.util import get_option
from laikaboss.extras.extra_util import parse_log_record
import geoip2.database as geoip
from laikaboss.extras.dictParser import DictParser
import logging
import os

_module_name = "LOOKUP_GEOIP"
_result_name = "location"

class LOOKUP_GEOIP(SI_MODULE):
    '''Laika module for lookup up geographic locations of ip address - using a local maxmind geoip database.

    Parameters:
        key, geoip_key - one or more metadata keys specifying which IP address(s) to lookup - if multiple they must be separated by a vertical pipe, 
            multiple values are acceptable results will be in an array.
        dbpath, geoip_dbpath -  The path to the local maxmind city db .mmdb file.

    Metadata:
         LOOKUP_GEOIP.location.city - The city of the ip address
         LOOKUP_GEOIP.location.country_code - The 2 letter country code of ip address
         LOOKUP_GEOIP.location.region_name - The state or similar for an ip address
         LOOKUP_GEOIP.location.ip - The ip address of the record

    Flags:
        location.NON-US - One or more of the specified IP address(es) are from outside the US
    '''

    def __init__(self,):
        '''Main constructor'''
        self.module_name = _module_name
        self.db = None
        self.dbpath = None
        self.modtime = None

    def _run(self, scanObject, result, depth, args):
        """Main module execution. Logs the scan result to mls."""

        dbpath = get_option(args, "dbpath", "geoip_dbpath", None)

        if not dbpath:
            logging.error("geoip_dbpath not set, no geoip database configured - skipping module")
            return []

        modtime = os.path.getmtime(dbpath)

        # only re-open if we suspect the source has been updated
        if not self.db or dbpath != self.dbpath or modtime!=self.modtime:
            if self.db:
               self.db.close()
            self.db = geoip.Reader(dbpath)
            self.dbpath = self.dbpath
            self.modtime = modtime

        tmp = get_option(args, "key", "geoip_key", None)
        if tmp and '|' in tmp:
           keys = tmp.split("|")
        else:
           keys = [tmp]

        keys = [key.strip() for key in keys]

        log = parse_log_record(result)
        d = DictParser(log)

        tmp_keys = []
        for key in keys:
           keys = d.evalMeta(key).value(force_list=True, flatten=True)
           if keys:
              keys_tuples = [(key, i) for i in keys]
              tmp_keys.extend(keys_tuples)

        ret = []
        # TODO: Need to dedup tuple based on second element.. use Counter?
        keys = list(set(tmp_keys))

        if len(keys) > 0:

            for key_tuple in keys:
               key = key_tuple[1]
               key_ret = {"ip":key, "source": key_tuple[0]}

               city = None

               try:
                  city = self.db.city(key)
               except:
                  pass

               if city:
                   try:
                        val = city.city.name;
                        if val:
                            key_ret["city"] = val
                   except:
                        pass

                   try:
                       val = city.subdivisions[0].iso_code;
                       if val:
                          key_ret["region_name"] = val
                   except:
                       pass

                   try:
                      val = city.country.iso_code;
                      if val:
                         key_ret["country_code"] = val
                         if val != "US":
                            scanObject.addFlag('%s:%s' % (_result_name, 'NON-US'))
                   except:
                       pass

               # note if we it cant find any data on an ip it'll be in the list of results but with no details
               ret.append(key_ret)

            if ret:
                scanObject.addMetadata(self.module_name, _result_name, ret)

        return []
