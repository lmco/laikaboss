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
# Laika module to explode a multipart form data payload

from future import standard_library
standard_library.install_aliases()
import logging
import cgi
import io
import base64
import quopri

# Import classes and helpers from the Laika framework
from laikaboss.objectmodel import ExternalVars, ModuleObject, ScanError, ScanObject
from laikaboss.util import get_option
from laikaboss.si_module import SI_MODULE

class EXPLODE_MULTIPARTFORM(SI_MODULE):
    ''' 
    A Laika module to parse a multipart form body

    It expects the content-type header of the HTTP POST request to be in the content-type key
    of external metadata and for the body of the request to be in the buffer.
    '''

    def __init__(self):
        self.module_name = "EXPLODE_MULTIPARTFORM"
        self.metadata_name = "META_WWWFORM"

    def _run(self, scanObject, result, depth, args):
        #List of sub-objects
        moduleResult = []
        header_location = get_option(args, 'header_location', 
                    'httpform_header_location', 'EXTERNAL.http_request')
        if header_location:
            headers = self._getnested(scanObject.moduleMetadata, header_location)
        else:
            headers = None
        #Try to get the headers metadata (usually comes from recursive invocation of this module)
        if not headers:
            #Try to get the content type from the external metadata
            contentType_location = get_option(args, 'contentType_location', 
                    'httpform_contentType_location', 'EXTERNAL.http_request.content-type')
            if contentType_location:
                contentType = self._getnested(scanObject.moduleMetadata, contentType_location)
            else:
                contentType = None

            #If the content type header is not provided, guess at what the boundary is
            if not contentType:
                lines = scanObject.buffer.splitlines()
                idx = 0
                while idx < len(lines) and not lines[idx].startswith(b"--"):
                    idx += 1
                if idx == len(lines):
                    logging.warn("Content-type header not provided and boundary discovery failed for multipart form data")
                else:
                    boundary = lines[idx][2:].strip().decode("utf-8")
                    contentType = "multipart/form-data;boundary=" + boundary
            #Content type is really the only important header, so construct new headers
            headers = {"content-type" : contentType, 
                        "content-length": len(scanObject.buffer)}
        
        body = io.BytesIO(scanObject.buffer)
        form = cgi.FieldStorage(fp=body, headers=headers, environ={"REQUEST_METHOD":"POST"})
        formFields = {}
        for key in form:
            item = form[key]
            #If a key is specified multiple times, it will show up as a top-level list
            if type(item) is list:
                formFields[key] = [subval.value for subval in item]
            else:
                self._process_item(item, formFields, moduleResult)
        #Insert the form fields without keeping the parent key
        for field in formFields:
            scanObject.addMetadata(self.metadata_name, field, formFields[field])
        return moduleResult
    
    #Parse an item based on its type
    def _process_item(self, item, formFields, moduleResult):
        #Decode item if encoded
        if(hasattr(item, "headers")):
                encoding = item.headers.get("content-transfer-encoding") or ""
                if encoding.lower() == "base64":
                    item.value = base64.b64decode(item.value)
                if encoding.lower() == "quoted-printable":
                    item.value = quopri.decodestring(item.value)
        #Nested multipart item, recurse
        if item.type and item.type.startswith("multipart") and type(item.value) is list:
            for childItem in item.value:
                self._process_item(childItem, formFields, moduleResult)
        #File upload
        elif item.filename:
            externalvars = ExternalVars(contentType=item.type, sourceModule=self.module_name,
                                        filename=item.filename)
            moduleResult.append(ModuleObject(buffer=item.value, externalVars=externalvars))
        #Normal form field
        else:
            formFields[item.name] = item.value

    def _getnested(self, dictionary, location):
        return_value = dictionary
        for key in location.split("."):
            if key in return_value:
                return_value = return_value[key]
            else:
                return_value = None
                break
        return return_value

