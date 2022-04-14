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
#A module to analyze dmarc reports

#import libraries
import xml.etree.ElementTree as ET

#import classses and helpers from the Laika framework
from laikaboss.objectmodel import ExternalVars, ModuleObject, ScanError
from laikaboss.util import get_option
from laikaboss.si_module import SI_MODULE

class META_DMARC(SI_MODULE):
    ''' Laika module for collecting info from DMARC reports '''

    def __init__(self):
        ''' init and module name '''
        self.module_name = "META_DMARC"

    def _run(self, scanObject, result, depth, args):
        '''process the dmarc report, add metadata, and return result (empty)'''

        #create element tree object and get the root
        if scanObject.charset:
            strbuffer = scanObject.buffer.decode(scanObject.charset)
        else:
            strbuffer = scanObject.buffer.decode('utf-8', errors='ignore')
        root = ET.fromstring(strbuffer)

        metadata = [] #all metadata will go into this one list
        record_num = 0

        for record in root.findall("record"):
            row = record.find("row")
            policy_evaluated = row.find("policy_evaluated")
    
            #no need to collect metadata if it wasn't rejected
            if policy_evaluated.findtext("disposition") != "reject":
                continue

            record_data = {} #dict that will hold this record's info
            record_data["record_num"] = record_num

            #ip address of the smtp connecting host
            record_data["source_ip"] = row.findtext("source_ip")

            #this is the domain listed in the email as the sender
            record_data["header_from"] = record.find("identifiers").findtext("header_from")

            #domains used for dkim signature and spf check
            auth_results = record.find("auth_results")
            record_data["dkim_domain"] = auth_results.find("dkim").findtext("domain")
            record_data["spf_domain"] = auth_results.find("spf").findtext("domain")

            #results
            record_data["dkim_auth_result"] = auth_results.find("dkim").findtext("result")
            record_data["spf_auth_result"] = auth_results.find("spf").findtext("result")
            record_data["dkim_dmarc_aligned_result"] = policy_evaluated.findtext("dkim")
            record_data["spf_dmarc_aligned_result"] = policy_evaluated.findtext("spf")

            #number of emails this info (this record) characterizes
            record_data["num_emails_this_info_characterizes"] = row.findtext("count")

            metadata.append(record_data)
            record_num +=1

        scanObject.addMetadata(self.module_name,"metadata",metadata)
        moduleResult = []
        return moduleResult

    def _close(self):
        ''' nothing to be done here '''
        pass
