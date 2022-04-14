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
"""
This module parses MSG file types and their attachments.

Requires: ExtractMsg 0.3 (https://github.com/mattgwwalker/msg-extractor)

Sandia National Labs
"""

import logging
import os

from laikaboss.objectmodel import ExternalVars, ModuleObject
from laikaboss.si_module import SI_MODULE
import extract_msg

class EXPLODE_MSG(SI_MODULE):

    def __init__(self):

        self.module_name = "EXPLODE_MSG"
        self.output_tz = "UTC"

    def _run(self, scanObject, result, depth, args):

        moduleResult = []

        try:
            # Force timestamps to UTC so that we don't get timezone weirdness
            old_tz = None
            if "TZ" in os.environ:
                old_tz = os.environ["TZ"]
            os.environ["TZ"] = self.output_tz
            # Actually do extraction
            msg = extract_msg.Message(scanObject.buffer)
            # Reset TZ variable, if applicable
            del os.environ["TZ"]
            if old_tz:
                os.environ["TZ"] = old_tz
        except Exception as e:
            scanObject.addFlag("msg:PARSE_ERROR")
            return []

        if msg.subject:
            scanObject.addMetadata(self.module_name, "Subject", msg.subject)

        if msg.sender:
            scanObject.addMetadata(self.module_name, "Sender", msg.sender)

        if msg.date:
            scanObject.addMetadata(self.module_name, "Message Date", msg.date)

        if msg.to:
            scanObject.addMetadata(self.module_name, "Message Recipient", msg.to)

        if msg.cc:
            scanObject.addMetadata(self.module_name, "Message CC", msg.cc)

        if msg.attachments:
            scanObject.addMetadata(self.module_name, "Number of Attachments", len(msg.attachments))

        if msg.body:
            scanObject.addMetadata(self.module_name, "Message Body", msg.body)

        # Add all attachments as children
        for attachment in msg.attachments:
            moduleResult.append(ModuleObject(buffer=attachment.data, externalVars=ExternalVars(filename=attachment.longFilename)))

        return moduleResult
