#!/usr/bin/env python
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
from setuptools import setup, find_packages

setup(
    name = "laikaboss",
    version = "2.0",
    author = "Lockheed Martin",
    description = "laikaboss: file centric intrusion detection system",
    license = "Apache 2.0",
    keywords = "malware",
    url = "https://github.com/lmco/laikaboss/",
    packages = find_packages(),
    data_files = [ ('/etc/laikaboss', ['etc/dist/laikaboss.conf', 'etc/dist/laikad.conf', 
                                       'etc/framework/dispatch.yara', 'etc/framework/conditional-dispatch.yara',
                                       'etc/cloudscan/cloudscan.conf']),
                   ('/etc/laikaboss/modules/scan-yara', ['etc/modules/signatures.yara']),
                   ('/etc/laikaboss/modules/dispositioner', ['etc/modules/disposition.yara'])],
    scripts = [ "laika.py", "laikad.py", "cloudscan.py" ],
)
