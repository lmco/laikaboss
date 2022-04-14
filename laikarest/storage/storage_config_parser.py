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
import re
import logging
from laikaboss.lbconfigparser import LBConfigParser

class Parser():
    """ Responsible for parsing the config file specifying all the minio instances and buckets 

    Args:
        config_location (str): path to config specifying minio information

    """

    def __init__(self, config_location, host, cluster):
        self.host = host
        self.cluster = cluster
        self.config = LBConfigParser()
        self.config.read(config_location)

    # takes a host param like "lbemail.example.com"
    # return a list of all the indexes
    def get_indexes_by_host(self):
        result = []
        for section in self.config.sections():
            if section.startswith("index_"):
                if self.config.get(section, 'cluster', fallback='default') != self.cluster:
                   continue
                oIndex_list = self.split(self.config.get(section, 'index'))
                oPrimary_list = self.split(self.config.get(section, 'primary_instance'))
                oSecondary_list = self.split(self.config.get(section, 'secondary_instance'))
                oPrimary_action = self.config.get(section, 'expire_on_primary')
                oSecondary_action = self.config.get(section, 'expire_on_secondary')
                oDays = self.config.get(section, 'days')

                url_path = self.filter_by_host(oPrimary_list)
                for item in url_path:
                    for index in oIndex_list:
                        if index not in result:
                            result.append(index)

                url_path = self.filter_by_host(oSecondary_list)
                for item in url_path:
                    for index in oIndex_list:
                        if index not in result:
                            result.append(index)

        return result


    # takes a host param like "lb-2"
    # return some json containing each path on the OS to the index's bucket along with its expiration strategy and date
    def get_index_expiration_by_host(self):
        result = {}
        for section in self.config.sections():
           if section.startswith("index_"):
               if self.config.get(section, 'cluster', fallback='default') != self.cluster:
                   continue
               oIndex_list = self.split(self.config.get(section, 'index'))
               oPrimary_list = self.split(self.config.get(section, 'primary_instance'))
               oSecondary_list = self.split(self.config.get(section, 'secondary_instance'))
               oPrimary_action = self.config.get(section, 'expire_on_primary')
               oSecondary_action = self.config.get(section, 'expire_on_secondary')
               oDays = self.config.get(section, 'days')

               url_path = self.filter_by_host(oPrimary_list)
               for item in url_path:
                   for index in oIndex_list:
                      result[index] = (oPrimary_action, oDays)

               url_path = self.filter_by_host(oSecondary_list)
               for item in url_path:
                   for index in oIndex_list:
                      result[index] = (oSecondary_action, oDays)

        return result

    # takes a cluster param like "prod"
    # return some json containing the minio locations along with all the buckets in them that contain the UUIDs (the -json buckets)
    def get_url_index_by_cluster(self):
        result = {}
        for section in self.config.sections():
           if section.startswith("index_"):

               oIndex_by_rootuid_list = self.split(self.config.get(section, 'index_by_rootuid'))
               oPrimary_list = self.split(self.config.get(section, 'primary_instance'))
               oCluster = self.config.get(section, 'cluster', fallback='default')

               if oCluster == self.cluster:
                   for item in oPrimary_list:
                       url, host, path = self.parse_instance(item)
                       tmp = result.get(url, [])
                       tmp.extend(oIndex_by_rootuid_list)
                       result[url] = list(set(tmp))

        return result


    def parse_instance(self, item):
        url, host, path = self.split(item, "|")
        return url, host, path

    def split(self, item, sep = ','):
        result = []
        if item != None and item.lower() != "none":
            item_list = item.split(sep)
            if item_list:
               result = [item.strip() for item in item_list]

        return result

    def filter_by_host(self, instance_list):
        result = []
        for instance in instance_list:
            iUrl, iHost, iPath = self.parse_instance(instance)
            if iHost == 'localhost' or iHost == self.host or self.host.startswith(iHost):
                result.append((iUrl, iPath))

        return list(set(result))

if __name__ == '__main__':
    parser = Parser('/etc/laikaboss/laikastorage-index.conf', host='lb-2', cluster='prod')
    print(parser.get_index_expiration_by_host())
    print(parser.get_url_index_by_cluster())
    print(parser.get_indexes_by_host())
