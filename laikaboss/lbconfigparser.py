# Copyright 2020 National Technology & Engineering Solutions of Sandia, LLC 
# (NTESS). Under the terms of Contract DE-NA0003525 with NTESS, the U.S. 
# Government retains certain rights in this software.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from __future__ import absolute_import
from past.builtins import basestring
from future import standard_library
standard_library.install_aliases()
import configparser
import jinja2
from jinja2 import meta as jinja2_meta
import os
import time
import urllib.parse as up
import socket
from collections import namedtuple
import copy
import logging

_environ_prefix = "LAIKA_"

#jinja substitutions may have substitutions - but limit recursiveness
_max_jinja_recursion = 5

Minio_url_parts = namedtuple('Minio_url_parts', "netloc,access_key,secret_key,secure,bucket_prefix")
Redis_url_parts = namedtuple('Redis_url_parts', "scheme,hostname,path,port,query,username,password,params,fragment,kwargs")

class LBConfigParser(configparser.ConfigParser, object):

   def __init__(self, defaults = None, use_env = True):

       if defaults:
          # a boolean in these values kills LBConfigParser
          defaults = {k:str(v) for k,v in defaults.items()}
       else:
          defaults = {}

       hostname = defaults.get('hostname', None)

       if hostname and 'hostname_short' not in defaults:
           if '.' in hostname:
              defaults['hostname_short'] = hostname[:hostname.find('.')]
           else:
              defaults['hostname_short'] = hostname

       self.defaults = defaults
       self.filenames = None
       self.opts = None
       self.use_env = use_env
       self.jinja_env = jinja2.Environment()

       super(LBConfigParser,self).__init__(defaults=defaults)

   def _variable_render(self, subst, warn=False):
       for section in self.sections():
            for option in self.options(section):
               v = self.get(section, option)
               i = 0

               while True:

                   if "{{" in v and isinstance(v, basestring):

                      ast = self.jinja_env.parse(v)
                      var_needed = jinja2_meta.find_undeclared_variables(ast)
                      missing_var = set(var_needed) - set(subst.keys())

                      if not missing_var:
                         j2 = jinja2.Template(v)
                         v = j2.render(**subst)
                      else:
                         if warn:
                             logging.warn("value has one or more substitutions could not be fullfilled: " + v + " missing:" + str(missing_var))
                         break

                   if "{{" in v and isinstance(v, basestring):
                       #substitutions may have substitutions - but limit recursiveness
                       if i > _max_jinja_recursion:
                          if warn:
                             logging.warn("value v still has subsitutions that where not fullfilled:" + v)
                          break
                       i=i+1
                   else:
                       break

               # treat new substituted value as something you can use in the future
               subst[option] = v

               self.set(section, option, v)

   def read(self, filenames, opts = None):

       if isinstance(filenames, basestring):
          filenames = [filenames]

       self.opts = opts

       tmp_config = configparser.ConfigParser()

       tmp_config.read(filenames)

       subst = {}

       base_dir = os.path.dirname(filenames[0])

       subst['laika_config_base'] = base_dir

       tmp_filenames = ";".join(filenames)

       # override config with site specific files - it can be one or a whole 
       # semicolon seperated list
       site_configs = []

       try:

          include_configs = tmp_config.get("General", "configpath", fallback=None)

          if include_configs:
             tmp_filenames =  include_configs + ";" + tmp_filenames

          site_configs = tmp_config.get("General", "siteconfig", fallback=None)

          if site_configs:
             tmp_filenames = tmp_filenames + ";" + site_configs


          # paths often contain {{ laika_config_base }}
          j2 = jinja2.Template(tmp_filenames)
          tmp_filenames = j2.render(**subst)

          site_configs = tmp_filenames.split(";")

       except configparser.NoSectionError as e:
          pass
       except configparser.NoOptionError as e:
          pass

       self.filenames = site_configs

       ret_value = super(LBConfigParser,self).read(self.filenames)

       # override values from config files with those from the environment (for Docker)
       if self.use_env:
           environ = {}

           for k,v in os.environ.items():
               if k.startswith(_environ_prefix):
                   k = k[len(_environ_prefix):].lower()
                   if k:
                      environ[k] = v

           for section in self.sections():
               for k,v in environ.items():
                  if v is not None and v != "":
                     self.set(section, k, str(v))

       # override values from from anywhere else with command line options
       # in every section
       opts_dict = {}

       if self.opts:
          if isinstance(self.opts, dict): 
              opts_dict = self.opts
          else:
              opts_dict = vars(self.opts)

          for section in self.sections():
            for k,v in opts_dict.items():
                #booleans aren't supported by configParser
                #so most things need converted to strings
                #don't accept empty values as values
                if v is not None and v != "":
                    self.set(section, k, str(v))

       # support jinja templating of values
       # with other config values 
       # jinja variable names ignores sections
       subst = self.as_dict(flatten=True)

       if not 'laika_config_base' in subst:
          base_dir = os.path.dirname(filenames[0])
          subst['laika_config_base'] = base_dir

       self._variable_render(subst)

       # this sets up ca certs for minio client and potentially other
       # python utilities - 
       if "ca_certificate" in subst and 'SSL_CERT_FILE' not in os.environ:
           os.environ['SSL_CERT_FILE'] = subst['ca_certificate']
           os.environ['REQUESTS_CA_BUNDLE'] = subst['ca_certificate']

       general = self._sections.get('General', None) if self._sections else None

       if general:
          hostname = general.get('hostname', None)
          if hostname and 'hostname_short' not in general:
             if '.' in hostname:
                self['General']['hostname_short'] = hostname[:hostname.find('.')]
             else:
                self['General']['hostname_short'] = hostname

             subst['hostname_short'] = self['General']['hostname_short']

       self._variable_render(subst, warn=True)

       return ret_value

   def as_dict(self, flatten=False):

      result = {}

      if flatten:
          for section in self.sections():
             result.update(dict(self.items(section)))
      else:
          for section in self.sections():
             result[section] = (dict(self.items(section)))

      return result
