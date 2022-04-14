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
from builtins import str
import email
import email.feedparser
import copy
from laikaboss.objectmodel import QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError
from laikaboss.si_module import SI_MODULE
from laikaboss.util import get_option
import re
import logging
from IPy import IP

class META_EMAIL(SI_MODULE):
    def __init__(self,):
        self.module_name = "META_EMAIL" 
        # Domain regex
        self.domainMatch = re.compile(r"(\b((?=[a-z0-9-]{1,63}\.)(xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}\b)")
        # Email Address
        self.emailMatch = re.compile(r"(\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b)")
        # IPv4 Address
        self.ipMatch = re.compile(r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')
        # IPv6 Address
        self.ipv6Match = re.compile(r'((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))')
        #If message_from_bytes not available (Python 2), copy message_from_string
        if not hasattr(email, 'message_from_bytes'):
            email.message_from_bytes = email.message_from_string

    def _run(self, scanObject, result, depth, args):
        moduleResult = []
        
        e = email.message_from_bytes(scanObject.buffer)
        
        sIParray = []
        domainArray = []
        toArray  = []
        frArray  = []
        rtoArray  = []
        rfrArray  = []
        metaDict = {}
        metaDictDecode = {}
        message_id_domain = ""
        header_order = ""
        
        spam_address = get_option(args, 'spamaddressregex', 'spamaddressregex')
        
        if spam_address:
           spam_address = spam_address.strip()
            

        header_order_symbols = { "mime-version": "V",
                                "message-id": "M",
                                "to": "T",
                                "content-type": "C",
                                "from": "F",
                                "subject": "S",
                                "date": "D" }


        for key, value in e.items():
            try:
                key = str(key)
            except (QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError):
                raise
            except:
                key = "UNPARSEABLE KEY"
            try:
                if isinstance(value, bytes):
                    value = value.decode('utf-8', errors='replace').encode('utf-8', errors='replace')
                else:
                    value = str(value)
            except (QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError):
                raise
            except:
                value = "UNPARSEABLE VALUE"

            #key = key.replace(".", "[d]") # Removing as this will be handled in the framework
            
            metaDict = self._addToMetaDict(metaDict, key, value)
            
            if key.lower() == "dkim-signature":
                detailArray = value.lower().split()
                for detail in detailArray: #add one at a time due to current implementation
                    metaDict = self._addToMetaDict(metaDict, "dkim-signature-search", detail)

            if key.lower() == "x-laika-addr":
                if spam_address:
                    lst_emails = self.emailMatch.findall(value.lower())

                    #check the first one in case other ones are spoofed
                    if re.match(spam_address, lst_emails[0]):
                       scanObject.addFlag('m_email:spam_inbox')
                continue

            if key.lower() == "to" or key.lower() == "cc" or key.lower() == "bcc" or key.lower() == "x-cirt-orcpt":
                lst_emails = self.emailMatch.findall(value.lower())
                for singleEmail in lst_emails:
                    if singleEmail not in toArray:
                        toArray.append(singleEmail)
                        rtoArray.append(singleEmail[::-1]) # reversed
            if key.lower() == "from" or key.lower() == "x-cirt-from":
                lst_emails = self.emailMatch.findall(value.lower())
                for singleEmail in lst_emails:
                    if singleEmail not in frArray:
                        frArray.append(singleEmail)
                        rfrArray.append(singleEmail[::-1])
            
            if key.lower() == 'message-id':
                if '@' in value:
                    message_id_domain = value.split('@')[1].strip('>')
            
            if key.lower() in header_order_symbols:
                header_order = header_order + header_order_symbols[key.lower()]

            #for every value, try finding IPs and domains
            #escape single quotes
            strIPs = value.replace("'", "\\'").lower()
            IPs = self.ipMatch.findall(strIPs )
            IPv6s =  self.ipv6Match.findall(strIPs)
            domains = self.domainMatch.findall(strIPs)
            
            
            for IPv4 in IPs:
                if not IPv4 in sIParray:
                    IPyIP= IP(IPv4)
                    sIParray.append(str(IPyIP))
                    #convert the IP to an integer
            for IPv6 in IPv6s:
                strIPv6 = ""
                if type(IPv6) == tuple:
                    strIPv6 = IPv6[0]
                elif type(IPv6) == str:
                    strIPv6 = IPv6
                if not strIPv6 in sIParray:
                    IPyIP= IP(strIPv6)
                    sIParray.append(str(strIPv6))
                    #convert the IP to an integer
            for domain in domains:
                strDomain = ""
                if type(domain) == tuple:
                    strDomain = domain[0]
                elif type(domain) == str:
                    strDomain = domain
                if not strDomain in domainArray:
                    domainArray.append(str(strDomain))
 
        # Copy the headers and run them through decode to pull out the printable ASCII version
        metaDictDecode = {} #copy.deepcopy(metaDict)
        for key, value in metaDict.items():
            try:
                if not isinstance(value, list):
                    value = [value]
                for header_piece in value:
                    h = email.header.decode_header(header_piece)
                    final_decoded_vals = []
                    for (decoded, format) in h:
                        # if it's encoded, attempt to convert it
                        if format:
                            decoded_val = str(decoded, format, errors='replace')
                            final_decoded_vals.append(decoded_val.encode('utf-8'))
                        # format is empty (assumes ASCII)
                        else:
                            if isinstance(decoded, str):
                                final_decoded_vals.append(decoded.encode('utf-8'))
                            else:
                                final_decoded_vals.append(decoded)
                    
                    self._addToMetaDict(metaDictDecode, key, b' '.join(final_decoded_vals))
                    
            except (QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError):
                raise
            except:
                metaDictDecode[key] = ""

        # Add Message-ID to scan object as uniqID
        if not scanObject.uniqID:
            if "message-id" in metaDict:
                scanObject.uniqID = metaDict['message-id']

        if message_id_domain:
            scanObject.addMetadata(self.module_name, "MessageID_Domain", message_id_domain)

        scanObject.addMetadata(self.module_name, "String_IPs", sIParray)
        scanObject.addMetadata(self.module_name, "Domains", domainArray, unique=True)
        scanObject.addMetadata(self.module_name, "Recipients", toArray)
        scanObject.addMetadata(self.module_name, "Senders", frArray)
        scanObject.addMetadata(self.module_name, "Recipients_reverse", rtoArray)
        scanObject.addMetadata(self.module_name, "Senders_reverse", rfrArray)
        scanObject.addMetadata(self.module_name, "Headers", metaDict)
        scanObject.addMetadata(self.module_name, "Headers-Decode", metaDictDecode)
        scanObject.addMetadata(self.module_name, "Header_Order", header_order)
            
        return moduleResult
    
    @staticmethod
    def _addToMetaDict(metaDict, key, value):
        thisKey = key
        thisValue = value
        if thisKey.lower() in metaDict:
            newHeader = []
            if type(metaDict[str(thisKey.lower())]) is list:
                newHeader.extend(metaDict[str(thisKey.lower())])
            else:
                newHeader.append(metaDict[str(thisKey.lower())])
            try:
                newHeader.append(thisValue)
            except (QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError):
                raise
            except:
                logging.debug("Cannot convert email header key/value pair")
            del metaDict[str(thisKey.lower())]
            metaDict[str(thisKey.lower())] = newHeader
        else:
            try:
                metaDict[str(thisKey.lower())] = thisValue
            except (QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError):
                raise
            except:
                logging.debug("Cannot convert email header key/value pair")
                
        return metaDict
