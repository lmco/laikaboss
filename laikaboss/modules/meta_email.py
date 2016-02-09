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
import email
import copy
from laikaboss.objectmodel import QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError
from laikaboss.si_module import SI_MODULE
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

    def _run(self, scanObject, result, depth, args):
        moduleResult = [] 
        e = email.message_from_string(scanObject.buffer)
        
        sIParray = []
        domainArray = []
        toArray  = []
        frArray  = []
        rtoArray  = []
        rfrArray  = []
        metaDict = {}
        metaDictDecode = {}
        message_id_domain = ""

        for key, value in e.items():
            try:
                key = key.encode('ascii', 'ignore')
            except (QuitScanException, GlobalScanTimeoutError, GlobalModuleTimeoutError):
                raise
            except:
                key = "UNPARSEABLE KEY"
            try:
                value = value.encode('ascii', 'ignore')
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
        metaDictDecode = copy.deepcopy(metaDict)
        for key, value in metaDictDecode.iteritems():
            try:
                decoded, format = email.Header.decode_header(value)[0]
                # if the encoding it something other than utf-8, attempt to convert it
                if format and format != 'utf-8':
                    metaDictDecode[key] = unicode(decoded, format).encode('utf-8')
                # format is either empty (assumes ASCII) or utf-8 (our preferred encoding)
                else:
                    metaDictDecode[key] = decoded
                    
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
                newHeader.append(str(thisValue))
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
