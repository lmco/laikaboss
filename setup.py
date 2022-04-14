#!/usr/bin/env python
# Copyright 2015 Lockheed Martin Corporation
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
from setuptools import setup, find_packages

setup(
    name = "laikaboss",
    author = "Lockheed Martin and Sandia National Laboratories",
    description = "laikaboss: file centric intrusion detection system Sandia National Laboratories Branch",
    license = "Apache 2.0",
    keywords = "malware",
    url = "https://github.com/sandialabs/laikaboss",
    packages = find_packages(),

    data_files = [ ('/etc/laikaboss', ['etc/dist/laikaboss.conf',
                                       'etc/dist/laika_cluster.conf',
                                       'etc/dist/laikad.conf',
                                       'etc/framework/dispatch.yara',
                                       'etc/framework/conditional-dispatch.yara',
                                       'etc/cloudscan/cloudscan.conf',
                                       'etc/dist/laikacollector.conf',
                                       'etc/dist/laikarestd_config.py',
                                       'etc/dist/laikamail.conf',
                                       'etc/dist/laikarestd.conf',
                                       'etc/dist/submitstorage.conf',
                                       'etc/dist/laikastorage.conf',
                                       'etc/dist/laikastorage-index.conf']),
                   ('/var/laikaboss/submission-error',[]),
                   ('/var/laikaboss/submission-queue',[]),
                   ('/var/laikaboss/tmp',[]),
                   ('/var/laikaboss/storage-error',[]),
                   ('/var/laikaboss/storage-queue',[]),
                   ('/etc/laikaboss/modules/suspicious_md5/',
                        ['etc/framework/modules/suspicious_md5/suspicious_md5s.txt']),
                   ('/etc/laikaboss/modules/dispositioner',
                        ['etc/framework/modules/dispositioner/disposition.yara']),
                   ('/etc/laikaboss/modules/scan-yara',
                        ['etc/framework/modules/scan-yara/signatures.yara'])],

    scripts = [ "laikacollector.py", "laikamail.py", "laikaconf.py", "laikadq.py", "laika.py", "laikad.py", "laikamilter.py", "cloudscan.py", "rediscloudscan.py", "laikaq-cli.py", "laikatest.py", "submitstoraged.py", "laikarestd.py", "expire.py"],
    test_suite='nose2.collector.collector',
)
