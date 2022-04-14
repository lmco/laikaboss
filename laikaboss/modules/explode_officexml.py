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
# Module to explode objects embedded in office XML documents (usually Word 2003 XML, but also others)
# Code inspired by oletools' olevba module (with some functions directly used)
#
# Sandia National Labs
from laikaboss.si_module import SI_MODULE
from laikaboss.objectmodel import ModuleObject, ExternalVars

import logging
import base64
from io import BytesIO
from defusedxml import ElementTree as defused
from xml.etree import ElementTree
from oletools import olevba

class EXPLODE_OFFICEXML(SI_MODULE):
    '''
    This module attempts to explode pure-XML office documents. Unlike regular office documents, which
    are containers for other objects, these files are monolithic XML that sometimes contain embedded 
    objects like macros and images.

    WordML documents will only have binary objects (which could be OLE) exploded out
    Flat OPC documents will have all sub-documents (including XML) exploded out
    '''
    NS_WORDML2003 = '{http://schemas.microsoft.com/office/word/2003/wordml}' # WordML namespace
    NS_FLATOPC = '{http://schemas.microsoft.com/office/2006/xmlPackage}' # Flat OPC namespace

    def __init__(self):
        self.module_name = 'EXPLODE_OFFICEXML'

    def _run(self, scanObject, result, depth, args):
        moduleResult = []
        try:
            tree = defused.fromstring(scanObject.buffer)
            # Find binData elements in WordML namespaces
            for binTag in tree.iter(self.NS_WORDML2003 + 'binData'):
                filename = binTag.get(self.NS_WORDML2003 + 'name', default='noname.mso')
                rawData = base64.b64decode(binTag.text)
                if olevba.is_mso_file(rawData):
                    rawData = olevba.mso_file_extract(rawData)
                moduleResult.append(ModuleObject(buffer=rawData, externalVars=ExternalVars(filename=filename))) 
            # Find pkg parts in Flat OPC documents
            for partTag in tree.iter(self.NS_FLATOPC + 'part'):
                partName = partTag.get(self.NS_FLATOPC + 'name', default='noname') # Name of part
                partContentType = partTag.get(self.NS_FLATOPC + 'contentType', default=None) # Content type
                xmlChild = partTag.find(self.NS_FLATOPC + 'xmlData') # XML file data
                binChild = partTag.find(self.NS_FLATOPC + 'binaryData') # Binary data
                partData = b''
                if xmlChild is not None:
                    childStrings = [ElementTree.tostring(child) for child in xmlChild.iter() if child is not xmlChild]
                    partData = b''.join(childStrings)
                elif binChild is not None:
                    partData = base64.b64decode(binChild.text)
                moduleResult.append(ModuleObject(buffer=partData, 
                        externalVars=ExternalVars(filename=partName, contentType=[partContentType] if partContentType else [])))
        except ElementTree.ParseError as e:
            logging.exception('EXPLODE_OFFICEXML: Error while parsing XML file')

        return moduleResult
