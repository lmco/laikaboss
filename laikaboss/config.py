# Copyright 2015 Lockheed Martin Corporation
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
import ConfigParser
import logging

Config = ConfigParser.ConfigParser()

defaults = { 
                'yaradispatchrules' : 'etc/framework/dispatch.yara',
                'yaraconditionalrules' : 'etc/framework/conditional-dispatch.yara',
                'defaultmodulepriority' : '9',
                'maxdepth' : '10',
                'global_scan_timeout' : '3600',
                'global_module_timeout' : '600',
                'tempdir' : '/tmp/laikaboss_tmp',
                'logfacility' : 'LOG_LOCAL0',
                'logidentity' : 'laikad',
                'moduleloglevel' : 'LOG_INFO',
                'scanloglevel' : 'LOG_INFO',
                'modulelogging' : True,
                'logresultfromsource' : 'all'
           }

globals().update(defaults)

def _ConfigSectionMap(section):
    dict1 = {}
    try:
        options = Config.options(section)
    except ConfigParser.NoSectionError:
        logging.debug("Section %s does not exist in the config" % section)
        return dict1
    for option in options:
        try:
            dict1[option] = Config.get(section, option)
            logging.debug("Parsed option %s with value %s" % (option,Config.get(section, option)))
            if dict1[option] == -1:
                logging.debug("skip: %s" % option)
        except:
            logging.debug("exception on %s!" % option)
            dict1[option] = None
    return dict1

def _map_to_globals(dictionary):
    """Map the values in the dictionary into globals()"""
    for name, value in dictionary.iteritems():
        base = '%s' % (name,)
        if value.lower() == 'true': 
            globals()['%s' % (base,)] = True 
        elif value.lower() == 'false':
            globals()['%s' % (base,)] = False 
        else:
            globals()['%s' % (base,)] = '%s' % (value,)

def init(path):
    logging.debug("Initializing with config: %s" % (path))
    Config.read(path)

    _map_to_globals(_ConfigSectionMap('General'))
    _map_to_globals(_ConfigSectionMap('ModuleHelpers'))
    _map_to_globals(_ConfigSectionMap('Logging'))

    if Config.has_section('Proxies'):
        proxies = _ConfigSectionMap('Proxies')
        for (protocol,proxy) in proxies.items():
            if not proxy:
                proxies.pop(protocol, None)
        if proxies:
            globals()['proxies'] = proxies

