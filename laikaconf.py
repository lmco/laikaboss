#!/usr/bin/env python
# Copyright 2020 National Technology & Engineering Solutions of Sandia, LLC 
# (NTESS). Under the terms of Contract DE-NA0003525 with NTESS, the U.S. 
# Government retains certain rights in this software.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from __future__ import print_function
from laikaboss.lbconfigparser import LBConfigParser
import json
import sys

# lbconfigparser requires pip3 install future

def main():

  config = LBConfigParser()
  filename = sys.argv[1]

  print("reading filename:" + filename)
  config.read(filename)

  print(json.dumps(config.as_dict(),sort_keys=False, indent=4))

if __name__ == '__main__':
  main()
