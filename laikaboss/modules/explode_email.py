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
import email
from email import header
import logging
from laikaboss.objectmodel import ModuleObject, ExternalVars
from laikaboss.si_module import SI_MODULE
from laikaboss.util import get_option, toBool


class EXPLODE_EMAIL(SI_MODULE):
    def __init__(self,):
        self.module_name = "EXPLODE_EMAIL" 
        self.global_search = "GLOBAL_SEARCH"
    def _run(self, scanObject, result, depth, args):
        moduleResult = []
        if isinstance(scanObject.buffer, str):
            e = email.message_from_string(scanObject.buffer)
        else:
            e = email.message_from_bytes(scanObject.buffer)

        attachments = []

        i = 1
        for p in e.walk():
            childBuffer = p.get_payload(decode=True)
            charset = p.get_content_charset(failobj="")
            if childBuffer is not None:
                filename = p.get_filename()
                if filename is None:
                    filename = 'e_email_%s_%s' % (p.get_content_type(),i)
                else:
                    try:
                       d = header.decode_header(filename)
                       if d[0][1]:
                           filename = d[0][0].decode(d[0][1])
                    except:
                        logging.exception("Error running decode_header on " + filename + " resuming...")

                    attachments.append(filename)

                moduleResult.append(ModuleObject(buffer=childBuffer, 
                                                 externalVars=ExternalVars(filename=filename,
                                                                           contentType=p.get_content_type(),
                                                                           charset=charset)))
                i += 1

        # If enabled, this will combine the email headers and all decoded
        # text portions contained in the email into a single object
        if toBool(get_option(args, 'createhybrid', 'explodeemlcreatehybrid', False)):
            # First, grab the headers
            header_end = scanObject.buffer.find(b'\x0a\x0a')
            hybrid = scanObject.buffer[:header_end] + b'\n\n'
            for mo in moduleResult:
                if 'text' in mo.externalVars.contentType or 'text/plain' in mo.externalVars.contentType or 'text/html' in mo.externalVars.contentType or 'html' == mo.externalVars.contentType:
                    hybrid += mo.buffer + b'\n\n'

            # Add the hybrid as another object with a special content type
            # for easy identification.
            moduleResult.append(ModuleObject(buffer=hybrid, 
                                             externalVars=ExternalVars(filename='e_email_hybrid',
                                                                       contentType='application/x-laika-eml-hybrid')))
            
        # Since we already gathered up the attachment names, we'll add them
        # on behalf of META_EMAIL
        scanObject.addMetadata('META_EMAIL', 'Attachments', attachments)
 
        return moduleResult
