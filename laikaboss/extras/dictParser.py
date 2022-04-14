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
from __future__ import absolute_import
from builtins import str
from past.builtins import basestring
from builtins import object
import json
import copy
from collections import OrderedDict

import sys
import os
from . import extra_util
import ast
import logging

#fix that oletools imports an old version of pyparsing and its in the path first
orig_sys_path = extra_util.remove_sys_paths(["oletools" + os.sep + "thirdparty"])

import pyparsing as pp

sys.path = orig_sys_path

import re

def init_parser():
    token = pp.Word(pp.alphanums + "-" + "_" + ":") + pp.Suppress(pp.Optional("."))
    token_parser = pp.OneOrMore(token)
    return token_parser

#cache this a global so we only have to caculate it once
_cmd_parser = init_parser()

# if the key and value evaluate to True - use them in the dict, otherwise ignore
def cond_set(d, key, value):
   if key and value:
      d[key] = value

# run a custom function on all nested strings
def cond_merge(d, val):
   if val:
      if isinstance(val, dict):
         d.update(val)
      if isinstance(val, list):
         for v in val:
            cond_merge(d, v)
      return

# run a custom function on all nested strings
# can accept a list of cleanup functions in which 
# case they will be run in order
def cleaner(v, custom_cleanup):
    if isinstance(v, list):
         res = type(v)()
         for item in v: 
             res = cleaner(item, custom_cleanup)
    elif isinstance(v, dict):
         res = type(v)()
         for key,val in v.items():
             val = cleaner(item, custom_cleanup)
             res[key] = val
    elif isinstance(v, basestring):
         res = custom_cleanup(v) 
    else: 
         res = v 
    return res

# turn nested lists, into 1 list.
def flatten(val):
    result = []
    if val and isinstance(val, list):
      for v2 in val:
          v2 = flatten(v2)
          result.append(v2)
      return result
    return val

# remove dups from a list, but keep ordering (keep the first item of match)
def dedup(v):
    vals = []
    if v and isinstance(v, list):
       for val in v:
           if val not in vals:
              vals.append(val)
       return vals
    return v

# internal simple cleanup routines dealing with spaces
def _cleanup_1(v):
  v = re.sub(r'[\s]+', ' ', v)
  v = re.sub(r' , ', ',', v)
  return v

# internal remove string brackets
def _cleanup_brackets(v):
  if v and isinstance(v, str) and v.startswith('[') and v.endswith(']'):
    try:
      v = ast.literal_eval(v)[0]
    except:
      # The format of originating-ip came through like:
      # [255.255.255.0] which is invalid inside.
      pass

  if v and type(v) == list:
    return v[0].rstrip(']').lstrip('[')
  elif v and isinstance(v, str):
    return v.rstrip(']').lstrip('[')

# internal turn bool strings into real bools
def _bool_string(val):
  if not isinstance(val, str):
    return False

  if val.lower() == "true" or val.lower() == "false":
    return True

  return False

# internal turn bool strings into real bools
def _convert_bool_string(val):
  if val.lower() == "true":
    return True

  return False

class DictParser(object):
   def __init__(self, d=None, parsing_array=None):
        self._vals = None
        if parsing_array:
           self._vals = parsing_array
        elif d:
           self._vals = [d]

   def init(self, d=None):
        self._vals = None
        if d:
           self._vals = [d]
        return self

   def eval(self, fmt):
      # fix me - to use proper array syntax
      # scan_result.any.META_EMAIL.Headers.accept-language
      global _cmd_parser
      tokens = _cmd_parser.parseString(fmt)

      d = self
      for component in tokens:
        d = d.getitem(component)

      return d

   def evalMeta(self, fmt):
      # META_EMAIL.Headers.accept-language
      global _cmd_parser
      tokens = _cmd_parser.parseString(fmt)

      d = self["scan_result"].any_index()["moduleMetadata"]

      for component in tokens:
        d = d.getitem(component)

      return d

   def evalMeta_helper(self, fmt):
      # it uses the cleanup and value functions from the fmt string
      # usually from a config file to return the value
      # it returns none when it doesn't exist, or actually is the none value

      val = None
      path = fmt.get('path')
      params = fmt.get('params', {})

      d = self.evalMeta(path)

      # Assign correct cleanup function
      if 'cleanup' in params:
        if params['cleanup'] == 'cleanup_1':
          params['cleanup'] = _cleanup_1

      val = d.value(**params)

      if 'cleanup' in params:
        if params['cleanup'] == 'accept_first':
          if type(val) == list:
            val = val[0]
          elif isinstance(val, str) and val.startswith('[') and val.endswith(']'):
            val = ast.literal_eval(val)[0]
        elif params['cleanup'] == 'cleanup_brackets':
          val = _cleanup_brackets(val)

      if val and _bool_string(val):
          return  _convert_bool_string(val)

      return val

   def any_key(self):
      vals = []
      if self._vals:
         for val in self._vals:
             if isinstance(val, dict):
                 for k,v in val.items():
                   try:
                      vals.append(v)
                   except Exception as e:
                      pass
      if vals:
          return DictParser(d=None, parsing_array=vals)
      return DictParser()

   # if its an array, copy in all indexes in parallel
   def any_index(self):
      vals = []
      if self._vals:
         for val in self._vals:
             if isinstance(val, list):
                 for v in val:
                   try:
                      vals.append(v)
                   except Exception as e:
                      pass
      if vals:
          return DictParser(d=None, parsing_array=vals)
      return DictParser()

   # downselect an array to just a subset of vvalues
   def select(self, start=None, end=None, step=1):
      vals = []
      if self._vals:
         vals = self._vals[start:end:step]
         if not vals:
            vals = None
      if vals:
         return DictParser(d=None, parsing_array=vals)
      return DictParser()

   # downselect the current array of values if the key/value pair is part of a dict in a value
   def find_index(self, key, values):
      ''' if the item for the list is a dict
	  only return items which contain a specific
	  key and at least one value in values
	  each value is a regex
      '''

      vals = []
      if self._vals:
         for val in self._vals:
             if isinstance(val, dict):
                if key not in val: 
                    continue
                internal_val = val[key]
                for test_val in values:
                    if re.match(test_val, internal_val):
                       vals.append(val)
                       break
      if vals:
         return DictParser(d=None, parsing_array=vals)

      return DictParser()


   def combine(self):
     vals = []
     result = []
     if self._vals:
       for val in self._vals:
          if isinstance(val, list):
             for v2 in val:
                 vals.append(v2)
          else:
             vals.append(val)
       # put all of the values into a new list as the first item
       result.append(vals)
       return DictParser(d=None, parsing_array=result)
     return DictParser()

   def flatten(self):
     vals = []
     if self._vals:
       for val in self._vals:
           vals.append(flatten(val))

       # put all of the values into a new list as the first item
       return DictParser(d=None, parsing_array=vals)
     return DictParser()

   def unique(self):
     vals = []
     if self._vals:
       for val in self._vals:
           vals.append(dedup(val))
     if vals:
        return DictParser(d=None, parsing_array=vals)
     return DictParser()

   def value(self, cleanup=None, maxlength=None, force_list=False, prefer_scalar=False, key_prefix=None, unique=False, flatten=False, regex_src=None, regex_dst=None):

     vals = self._vals

     if vals != None and len(vals) == 1 and not force_list:
        ret = vals[0]
        if isinstance(ret, list):
           if prefer_scalar:
              if len(ret) == 1:
                 ret = ret[0]
           if len(ret) == 0:
              ret = None
     else:
        ret = vals

     if cleanup:
         ret = cleaner(ret, cleanup)

     if isinstance(ret, dict) and key_prefix:
        tmp = type(ret)()
        for key, value in ret.items():
            tmp[key_prefix + key] = value
        ret = tmp

     if flatten and isinstance(ret, list):
         ret2 = []
         for val in ret:
             if isinstance(val, list):
               ret2 = ret2 + val
             else:
               ret2.append(val)
         ret = ret2

     if regex_src and regex_dst and ret:
       if isinstance(ret, list):
           for i,v in enumerate(ret):
               try:
                  ret[i] = re.sub(regex_src, regex_dst, v)
               except:
                  logging.exception("Error doing regex of value:" + str(val))
       else:
           try:
              ret = re.sub(regex_src, regex_dst, ret)
           except:
              logging.exception("Error doing regex of value:" + str(val))

     if unique and isinstance(ret, list):
        ret = dedup(ret)

     return ret

   def getitem(self, key):
      vals = []
      if self._vals:
         for i,val in enumerate(self._vals):
             try:
                 ret = self._vals[i][key]
                 vals.append(ret)
             except Exception as e:
                 pass
      if vals:
          return DictParser(d=None, parsing_array=vals)
      return DictParser()

   def __getitem__(self, key):
        return self.getitem(key)

   def __str__(self):
         return str(self._vals) 

def remove_sys_path(snippet):
   tmp = os.copy(sys.path)
   for path in tmp:
       if snippet in path:
          sys.path.remove(tmp)
   return
