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

"""
Milter for LaikaBOSS

emails can be blocked according to laikaboss disposition.

The configuration is reloaded periodically.

The milter can be configured to write emails to a local filesystem. It is recommended that LaikaBOSS be used for archival,
but this option may assist with debugging.

Logging via syslog hardcoded to local0 with tag defined in config
Output: syslog.alert:  per email/recipient logs formatted in laika legacy log
                       format
        syslog.debug:  Debug Information
        syslog.err     Error Information

laika legacy log format:
#filename|messageid|instance|flags|disposition|attachments|sender|client IP|recipient|server IP|date|response|queue ID||scantime|Subject

The debug logs contain a per-connection randomly generated ID. This is not the
SMTP server queue ID because it is not available at the start of the connection
for some MTAs. This helps correlate actions on the same connection.

File handle limit is a common cause of crashing for milter. Two main limitations are in play:

1. Typical per process file handle limits, ulimit -n, usually 1024, can be
   adjusted through typical means.
2. FD_SETSIZE limit in select(), also usually 1024. See SM_CONF_POLL to enable
   poll() in libmilter.

The config item maxFiles is designed to help limit consumption of file handles after the specified limit is reached. This mechanism may help prevent reaching
file handle limits, but may not fully prevent reaching file handle limit on
servers that process many email simultaneously. An as alternative to increasing these limits, one might running more instances of the milter server and load balance across them.


helowhitelist allows a whitelist of milter clients and STMP clients for which
mail is not scanned. The purpose it to allow all the mail from an MTA to be sent
to the milter but exempt some clients/relays from scanning.

For example, given the following json file:

{
  "group": {
    "gateway": [
      "10.1.200.1",
      "10.1.200.2",
      "10.1.200.3",
      "10.1.200.4"
    ],
    "internala": [
      "192.168.100.1",
      "192.168.100.2"
    ],
    "internalb": [
      "192.168.101.1",
      "192.168.101.2"
    ],
    "localhost": [
      "127.0.0.1"
    ]
  },
  "exclusions": {
    "gateway": [
      "internala",
      "internab"
    ],
    "localhost": [
      "localhost"
    ]
  }
}

If the MTAs in group gateway are connected to this milter, then emails from from the systems in groups internala and internalb will not be scanned (but emails
from other upstream servers will be). Localhost to localhost email is also
exempted.

"""

from __future__ import print_function

import ConfigParser
import datetime
import json
import Milter
import os
import random
import resource
import socket
import StringIO
import sys
import syslog
import time
import traceback
import uuid

from email.utils import formatdate
from email.utils import mktime_tz
from email.utils import parsedate_tz

from laikaboss.objectmodel import ExternalObject, ExternalVars
from laikaboss.constants import level_metadata
from laikaboss.clientLib import (
    Client,
    dispositionFromResult,
    finalDispositionFromResult,
    flagRollup,
    getAttachmentList
)

global_whitelist = {}


class LaikaMilter(Milter.Base):
    """
    Main Milter class
    libmilter uses one instance per connection and closes

    1) Create Milter.Factory referencing this class
    2) Start Milter

    """

    def __init__(self):
        self.altConfig = None
        if len(sys.argv) == 2:
            self.altConfig = sys.argv[1]
        self.fph = None #IO buffer to store headers
        self.fpb = None #IO buffer to store body
        self.headers = []
        self.fileBuffer = ""
        self.rulesMatched = "" #LaikaBOSS flags
        self.warnings = ""
        self.sender = ""
        self.receiver = "" #recipient
        self.disposition = ""
        self.dispositions = "" #list of dispositions
        self.scanPerformedOn = ""
        self.subject = ""
        self.qid = ""
        self.messageID = ""
        self.messageDate = ""
        self.attachments = ""
        self.CUSTOMHELO = ""
        self.CUSTOMFROM = ""
        self.CUSTOMORCPT = []
        self.milterConfig = MilterConfig()
        if self.altConfig:
            self.milterConfig.configFileLoc = self.altConfig
        self.milterConfig.loadAll()
        self.archiveFileName = milterConfig.storeDir
        self.logger = logger

        self.startTimeDT = None
        self.startTime = None
        self.endTime = None
        self.startTimeZMQ = None
        self.endTimeZMQ = None
        self.rtnToMTA = Milter.CONTINUE #Fail Closed
        self.alreadyScanned = False
        self.uuid = str(uuid.uuid4())[-12:]

    # Handle Aborted Callbacks
    #Try To send to EOM callback
    def abort(self):
        try:
            #Try sending it to EOM for scanning and disposition.
            log = "{} Aborted QID: {} Attempting to send direct to EOM".format(
                self.uuid,
                self.qid
            )
            self.logger.writeLog(syslog.LOG_DEBUG, str(log))
            self.eom()
        except:
            log = "{} Uncaught Exception in Abort".format(self.uuid)
            self.logger.writeLog(syslog.LOG_ERR, str(log))

        return Milter.CONTINUE

    def unknown(self, cmd):
        log = self.uuid+" Unknown Callback Received: "+str(cmd)
        self.logger.writeLog(syslog.LOG_DEBUG, "{}".format(str(log)))
        return Milter.CONTINUE


    # Start libmilter callbacks
    def hello(self, heloname):
        returnval = Milter.CONTINUE
        try:
            self.logger.writeLog(
                syslog.LOG_DEBUG,
                "{} hello:{} client_addr:{} if_addr:{}".format(
                    self.uuid,
                    str(heloname),
                    str(self._getClientAddr()),
                    str(self._getIfAddr())))
            self.CUSTOMHELO = heloname
        except:
            log = self.uuid+" Uncaught Exception in Hello"
            self.logger.writeLog(syslog.LOG_ERR, "{}".format(str(log)))
        return returnval

    def envfrom(self,f,*str):
        try:
            #If anything is left over from the last email, re -initialize.
            if self.CUSTOMFROM != "":
                self.__init__()
            self.startTime = time.time()
            self.startTimeDT = datetime.datetime.now()
            if (self.milterConfig.mode == "shutdown"):
                log = (
                    self.uuid +
                    " Milter in Maint mode, returning [Sender:" +
                    ''.join(f) +
                    "]"
                )
                self.logger.writeLog(syslog.LOG_DEBUG, "{}".format(log))
                return self.milterConfig.dispositionModes["InMaintMode".lower()]

            log = self.uuid+" envFrom: "
            log += ''.join(f)
            self.logger.writeLog(syslog.LOG_DEBUG, "{}".format(log))
            self.CUSTOMFROM = f

            self.CUSTOMFROM = self.CUSTOMFROM.replace("<", "")
            self.CUSTOMFROM = self.CUSTOMFROM.replace(">", "")

            self.sender = self.CUSTOMFROM

            self.fph = StringIO.StringIO()
            self.fpb = StringIO.StringIO()

        except:
            log = self.uuid+" Uncaught Exception in EnvFrom"
            self.logger.writeLog(syslog.LOG_ERR, "{}".format(str(log)))
        return Milter.CONTINUE    #ALWAYS continue to gather the entire email

    def envrcpt(self,to,*str):
        try:
            self.CUSTOMORCPT.append(to)
            log = self.uuid+" envRcpt: "
            rcpt = ' '.join(self.CUSTOMORCPT)
            log += rcpt
            self.logger.writeLog(syslog.LOG_DEBUG, "{}".format(log))
            self.receiver = rcpt
            # clean the first "<" off the string
            self.receiver = self.receiver.replace("<", "")
            self.receiver = self.receiver.replace(">", "")
        except:
            log = self.uuid+" Uncaught Exception in EnvRcpt"
            self.logger.writeLog(syslog.LOG_ERR, "{}".format(str(log)))
        return Milter.CONTINUE


    def header(self,name,val):
        try:
            lname = name.lower()
            tname = lname.strip()
            tval  = val.strip()
            headerstring = "{}: {}\n".format(tname, tval)
            self.headers.append(headerstring)

            self._getSpecialHeaderLines(lname, val)
        except:
            log = self.uuid+" Uncaught Exception in Header"
            self.logger.writeLog(syslog.LOG_ERR, "{}".format(str(log)))
        return Milter.CONTINUE


    def eoh(self):
        try:
            self._writeHeaderToFP()
        except:
            log = self.uuid+" Uncaught Exception in EOH"
            self.logger.writeLog(syslog.LOG_ERR, "".format(str(log)))
        return Milter.CONTINUE

    def body(self,chunk):        # copy body to temp file
        try:
            if (isinstance(chunk, str)):
                chunk = chunk.replace("\r\n", "\n")
            self.fpb.write(chunk)
            self.fpb.flush()
        except:
            log = self.uuid+" Uncaught Exception in Body"
            self.logger.writeLog(syslog.LOG_ERR, "{}".format(str(log)))
        return Milter.CONTINUE


    def eom(self):
        try:
            self._getQID()
            checklist = "{}_{}".format(
                str(self._getIfAddr()),
                str(self._getClientAddr())
            )
            if checklist in global_whitelist:
                log = (
                    "{} ACCEPT ON WHITELIST: ".format(self.uuid) +
                    "qid:{} client_addr:{} ".format(
                        str(self.qid,),
                        str(self._getClientAddr())
                    ) +
                    "if_addr:{}".format(str(self._getIfAddr()))
                )
                self.logger.writeLog(syslog.LOG_DEBUG, "{}".format(str(log)))
                self.rtnToMTA = Milter.ACCEPT
            else:
                if not self.alreadyScanned:
                    self._getBufferFromFP()#build the header
                    self._generateArchiveFileName()
                    self.rtnToMTA = self._dispositionMessage()
                    self.fph.write("{}: {}\n".format(
                        self.milterConfig.MailscanResultHeaderString,
                        self.disposition))
                    self.fph.write("{}: {}\n".format(
                        "X-Flags",
                        self.rulesMatched))
                    #Rebuild the buffer with the result header
                    self._getBufferFromFP()
                    self.fph.close()
                    self.fpb.close()
                    self._writeFileToDisk()
                    self._addHeaders()
                    self._logDetails()
                    self._logEachEnvelope()
                    log = (
                        self.uuid +
                        " " +
                        self.qid +
                        " response " +
                        self.milterConfig._unconvertDispositionMode(
                            self.rtnToMTA)
                    )
                    self.logger.writeLog(syslog.LOG_DEBUG, "{}".format(str(log)))
                    self.alreadyScanned = True
                else:
                    log = (
                        self.uuid +
                        " File " +
                        self.archiveFileName +
                        " Already scanned"
                    )
                    self.logger.writeLog(syslog.LOG_DEBUG, "{}".format(str(log)))
        except Exception:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            ERROR_INFO = repr(traceback.format_exception(
                exc_type,
                exc_value,
                exc_traceback))
            ERROR = "{} ERROR EOM: RETURNING DEFAULT ({})   {}".format(
                self.uuid,
                self.rtnToMTA,
                ERROR_INFO
            )
            print(ERROR)
            self.logger.writeLog(syslog.LOG_ERR, "{}".format(str(ERROR)))
        return self.rtnToMTA


    # END libmilter callbacks

    # START helper functions
    # _addHeader adds a single header to the mail message sent to the user
    def _addHeader(self,name,value):
        try:
            if value:    # add header
                self.addheader(name,value)
        except Exception:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            log = "{} Error adding header {}".format(
                self.uuid,
                repr(traceback.format_exception(
                    exc_type,
                    exc_value,
                    exc_traceback)
                )
            )
            self.logger.writeLog(syslog.LOG_ERR, "{}".format(str(log)))
            log = "{}: {}".format(name,value)
            self.logger.writeLog(
                syslog.LOG_ERR,
                "{} Tried to Add: {}".format(self.uuid, str(log))
            )

    #_addHeaders adds miltiple headers to the mail message sent to the user
    def _addHeaders(self):
        if (self.milterConfig.ApplyMailscanResultHeader):
            self._addHeader(
                self.milterConfig.MailscanResultHeaderString,
                self.disposition
            )

        if (self.milterConfig.ApplyCustomHeaders):
            self._addHeader(
                "X-{}-HELO".format(self.milterConfig.CustomHeaderBase),
                self.CUSTOMHELO
            )
            self._addHeader(
                "X-{}-FROM".format(self.milterConfig.CustomHeaderBase),
                self.sender
            )
            self._addHeader(
                "X-{}-ORCPT".format(self.milterConfig.CustomHeaderBase),
                self.receiver
            )

    #_getMboxLine generates the Mbox line to be stored in the archive to disk
    def _getMboxLine(self):
        cleanSender = self.sender.replace("<", "")
        cleanSender = cleanSender.replace(">", "")

        POSIXtime = time.asctime(self.startTimeDT.timetuple())
        envelope_from_extra = ""

        mbox_from_line = (
            "From " +
            cleanSender +
            " " +
            str(POSIXtime) +
            " " +
            envelope_from_extra
        )

        return mbox_from_line

    #_checkFilePath checks the archive file path exits.  if not, creates
    # the path.  Logs errors to syslog.error.
    def _checkFilePath(self, path):
        try:
            if not os.path.exists(path):
                os.makedirs(path)
        except OSError:
            log = "Could not create "+ path
            self.logger.writeLog(syslog.LOG_ERR, "{}".format(str(log)))

    def _checkOKToContinueWithOpenFiles(self):
        okToContinue = True

        try:
            pid = os.getpid()
            try:
                fd_dir=os.path.join('/proc/', str(pid), 'fd/')
            except:
                self.logger.writeLog(
                    syslog.LOG_DEBUG,
                    "Open Files:  Problem With PID: "+str(pid)
                )
            numOpenFilesOutput = 0
            for file in os.listdir(fd_dir):
                numOpenFilesOutput += 1
            if (int(numOpenFilesOutput) > int(self.milterConfig.maxFiles)):
                log = (
                    "Open Files: " +
                    str(numOpenFilesOutput) +
                    ", Returning " +
                    str(self.milterConfig.dispositionModes["OverLimit".lower()]) +
                    " to avoid shutdown at " +
                    str(self.milterConfig.maxFiles)
                )
                self.logger.writeLog(syslog.LOG_ERR, "{}".format(str(log)))
                okToContinue = False
            else:
                self.logger.writeLog(
                    syslog.LOG_DEBUG,
                    (self.milterConfig.milterInstance +
                     " Open Files: " +
                     str(numOpenFilesOutput) +
                     " of " +
                     str(self.milterConfig.maxFiles))
                )
        except ValueError:
            self.logger.writeLog(
                syslog.LOG_ERR,
                "Value Error in checkOpenFiles"
            )
        except Exception:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            print(
                "ERROR EOM  {}".format(
                    repr(traceback.format_exception(
                        exc_type,
                        exc_value,
                        exc_traceback)
                    )
                )
            )
            self.logger.writeLog(syslog.LOG_ERR, "Error in checkOpenFiles")
        return okToContinue

    #_dispositionMessage main helper function to open dispositioner class to
    # disposition message.
    def _dispositionMessage(self):
        self.startTimeZMQ = time.time()
        if (not self._checkOKToContinueWithOpenFiles()):
            self.disposition = "Over Process File Handle Limit"
            self.logger.writeLog(
                syslog.LOG_ERR,
                "Disposition: {}".format(str(self.disposition))
            )
            rtnToMTA = self.milterConfig.dispositionModes["OverLimit".lower()]
        else:
            dispositioner = Dispositioner(self.logger)
            # success = dispositioner.zmqGetFlagswithRetry(
            #    self.milterConfig.zmqMaxRetry, self)
            self.disposition = dispositioner.strScanResult
            self.scanPerformedOn = dispositioner.scanServerToUse
            self.rulesMatched = ' '.join(dispositioner.match)
            self.warnings = dispositioner.warnings
            self.attachments = dispositioner.attachements
            self._dispositionMessage_AttachmentHelper()
            self.dispositions = dispositioner.dispositions
            self.logger.writeLog(
                syslog.LOG_DEBUG, "{} Disposition: {}".format(
                    self.uuid,
                    str(dispositioner.dispositions))
            )
            rtnToMTA = self._getReturnToMTAValue(dispositioner)
            dispositioner.close()
        self.endTimeZMQ = time.time()
        return rtnToMTA

    #_dispositionMessage_AttachmentHelper helps _dispositionMessage convert the
    # attachment list to string.
    def _dispositionMessage_AttachmentHelper(self):
        if (len(self.attachments) > 80):
            #Finds the comma that exists between 80 and 300 characters
            commaLoc = self.attachments.find(",", 80, 300)
            attachmentsReduced = self.attachments[:commaLoc] #\\
            # Reduces the string to the  first comma after 80 chars and marks
            # with truncated.
            self.attachments = attachmentsReduced
            self.attachments += "(truncated)"                #//
        # Return true for now, TODO: return whether or not the list was
        # truncated.
        return True

    #_generateArchiveFileName generates the file name used for the archive file
    # location.
    def _generateArchiveFileName(self):
        # Reset file name here.  Bug found where eom callback repeated
        if self.milterConfig.storeEmails:
            self.archiveFileName = self.milterConfig.storeDir
            now = datetime.datetime.now()
            unixNow = time.time()
            # Use the custom date format supplied in the config file.
            strCustomDateFolderFormat = now.strftime(
                self.milterConfig.customFolderDateFormat
            )
            randNum = str(random.random())
            uniqueNum = self.qid
            if not uniqueNum:
                uniqueNum = randNum
            ifAddr = self._getIfAddr()
            clientAddr = self._getClientAddr()
            self.archiveFileName += strCustomDateFolderFormat
            self._checkFilePath(self.archiveFileName)
            # generates the file name as email.
            # <timestamp><randomNumber><clientAddr>
            self.archiveFileName += (
                "email." +
                str(int(unixNow)) +
                "." +
                uniqueNum +
                "." +
                str(clientAddr) +
                "." +
                str(ifAddr)
            )
        else:
            self.archiveFileName = ""

    #_getBufferFromFP combines the header buffer and body buffer
    def _getBufferFromFP(self):
        self.fph.flush()
        self.fpb.flush()
        self.fileBuffer = self.fph.getvalue()
        self.fileBuffer += self.fpb.getvalue()

    def _getClientAddr(self):
        Addr = self.getsymval("{client_addr}")
        return Addr

    def _getIfAddr(self):
        Addr = self.getsymval("{if_addr}")
        return Addr

    def _getQID(self):
        self.qid = self.getsymval("{i}")



    #_getReturnToMTAValue convert the string returned by the dispositioner to
    # actual milter return values defined by the milterConfig class
    def _getReturnToMTAValue(self, dispositioner):
        if (dispositioner.strScanResult.lower() in
            self.milterConfig.dispositionModes):
            rtnToMTA = self.milterConfig.dispositionModes[
                dispositioner.strScanResult.lower()
            ]
        else: #Default if not included
            rtnToMTA = self.milterConfig.dispositionModes["default"]
            self.logger.writeLog(
                syslog.LOG_ERR,
                ("Disposition: {} (lc) was not in available ".format(
                    str(dispositioner.strScanResult.lower())) +
                 "dispositions, using default ({})".format(
                     str(self.milterConfig.dispositionModes["default"]))
                )
            )

        return rtnToMTA

    #_getSpecialHeaderLines grabs headers worth logging
    def _getSpecialHeaderLines(self, lname, val):
        if (lname == "subject"):
            self.subject = val
        if (lname == "message-id"):
            self.messageID = val
            self.messageID = self.messageID.replace("<", "")
            self.messageID = self.messageID.replace(">", "")
        if (lname == "date"):
            try:
                self.messageDate = formatdate(
                    mktime_tz(parsedate_tz(val.split('\n')[0])), True)
            except:
                log = self.uuid+" Error Parsing "+str(val)+" to RFC822 Date"
                self.logger.writeLog(syslog.LOG_ERR, "{}".format(str(log)))

    def _logDetails(self):
        log = self.uuid+" Flags: {}".format(self.rulesMatched)
        self.logger.writeLog(syslog.LOG_DEBUG, "{}".format(str(log)))


    def _logEachEnvelope(self):
        while (len(self.CUSTOMORCPT)>0):
            individualRCPT = self.CUSTOMORCPT.pop()
            individualRCPT = individualRCPT.replace("<", "")
            individualRCPT = individualRCPT.replace(">", "")
            self._logMail(individualRCPT)

    def _logMail(self, individualReceiver):
        # Remove the "None" used to differentiate between no result and result
        # with No rules matched to save space in log file.
        if self.rulesMatched == "None":
            self.rulesMatched = ""
        self.endTime = time.time()
        # Convert to Microsec
        #timeDiff = int((self.endTime - self.startTime)*100000)
        # Convert to Microsec
        timeDiffZMQ = int((self.endTimeZMQ - self.startTimeZMQ)*100000)
        log = "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}".format(
            self._logMail_sanitize(self.archiveFileName),
            self._logMail_sanitize(self.messageID),
            self._logMail_sanitize(self.milterConfig.milterInstance),
            self._logMail_sanitize(self.rulesMatched),
            self._logMail_sanitize(self.dispositions),
            self._logMail_sanitize(self.attachments),
            self._logMail_sanitize(self.sender),
            self._logMail_sanitize(self._getClientAddr()),
            self._logMail_sanitize(individualReceiver),
            self._logMail_sanitize(self._getIfAddr()),
            self._logMail_sanitize(self.messageDate),
            #self._logMail_sanitize(timeDiff),
            self._logMail_sanitize(
                self.milterConfig._unconvertDispositionMode(self.rtnToMTA)),
            self._logMail_sanitize(self.qid),
            self._logMail_sanitize(""), #TODO: scanner IP?
            self._logMail_sanitize(timeDiffZMQ),
            self._logMail_sanitize(self.subject)
        )

        self.logger.writeLog(syslog.LOG_ALERT, "{}".format(str(log)))


    def _logMail_sanitize(self, inputString):
        strInputString = str(inputString)
        log_delimiter="|"
        log_delimiter_replacement="_"
        return strInputString.replace(log_delimiter, log_delimiter_replacement)

    def _writeFileToDisk(self):
        if self.archiveFileName:
            try:
                fp = open(self.archiveFileName, "wb")
                fp.write(self.fileBuffer)
                fp.flush()
                fp.close()
            except IOError:
                log = (
                    self.uuid +
                    " Could not open " +
                    self.archiveFileName +
                    " for writing"
                )
                self.logger.writeLog(syslog.LOG_ERR, "{}".format(str(log)))

    #Write Custom header to the file pointer to be written to disk
    def _writeHeaderToFP(self):
        self.fph.write(self._getMboxLine()+"\n")
        for header in self.headers:
            self.fph.write(header)

        clientAddr = self._getClientAddr()
        self.fph.write(
            "X-{}-HELO: {} [{}]\n".format(
                self.milterConfig.CustomHeaderBase,
                self.CUSTOMHELO,
                clientAddr
            )
        )
        self.fph.write(
            "X-{}-FROM: {}\n".format(
                self.milterConfig.CustomHeaderBase,
                self.sender
            )
        )
        self.fph.write(
            "X-{}-ORCPT: {}\n".format(
                self.milterConfig.CustomHeaderBase,
                self.receiver
            )
        )
        self.fpb.write("\n")


class Dispositioner():
    '''
    Dispositioner: Class used to Dispostion (and with LaikaBOSS, determine
    response to MTA) input email
    '''

    def __init__(self, logger):
        self.altConfig = None
        self.client = None
        if len(sys.argv) == 2:
            self.altConfig = sys.argv[1]
        self.match = []
        self.strScanResult = "SCAN ERROR"
        self.dispositions = "SCAN ERROR"
        self.warnings = ""
        self.scanServerToUse = "None"
        self.numScanSigsMatched = -1
        self.currentScanServerNum = -1
        self.milterConfig = MilterConfig()
        if self.altConfig:
            self.milterConfig.configFileLoc = self.altConfig
        self.milterConfig.loadAll()
        self.logger = logger
        self.attachements = ""

    #Required final call to close zmq connection
    def close(self):
        try:
            self.client.close()
        except:
            self.logger.writeLog(
                syslog.LOG_ERR,
                self.uuid + " ERROR attempting to close ZMQ context")

    #public function to get flags from si-scan
    def zmqGetFlagswithRetry(self, numRetries, milterContext):
        sendResponse = self._zmqGetFlags(numRetries, milterContext)
        return sendResponse

    def _getNextScanServer(self):
        if (len(self.milterConfig.servers)> 1):
            self.currentScanServerNum = (
                self.currentScanServerNum + 1
                ) % (len(self.milterConfig.servers) - 1)
            self.scanServerToUse = self.milterConfig.servers[
                self.currentScanServerNum]
        else:
            self.scanServerToUse = self.milterConfig.servers[0]
        return self.scanServerToUse


    def _getRandomScanServer(self):
        randServer = 0
        #server = ""
        numServers = len(self.milterConfig.servers)
        if (numServers>1):
            randServer = random.randint(0, numServers-1)
        self.scanServerToUse = self.milterConfig.servers[randServer]
        return self.scanServerToUse


    def _zmqGetFlags(self, numRetries, milterContext):
        REQUEST_TIMEOUT = milterContext.milterConfig.zmqTimeout
        gotResponseFromScanner=-1
        if (len(self.milterConfig.servers)>0):#servers Available
            SERVER_ENDPOINT = self._getNextScanServer()
            gotResponseFromScanner=-1 #Default No Response
            gotResponseFromScanner = self._zmqSendBuffer(milterContext, numRetries, REQUEST_TIMEOUT, SERVER_ENDPOINT)
        else:
            log = "No Scan Servers Defined"
            self.logger.writeLog(syslog.LOG_DEBUG, "{}".format(str(log)))

        return gotResponseFromScanner

    def _zmqSendBuffer(self,
                       milterContext,
                       numRetries,
                       REQUEST_TIMEOUT,
                       SERVER_ENDPOINT):
        gotResponseFromScanner=-1
        self.client = Client(SERVER_ENDPOINT)

        log = (
            milterContext.uuid +
            " Sending " +
            str(milterContext.qid) +
            " to " +
            SERVER_ENDPOINT
        )
        self.logger.writeLog(syslog.LOG_DEBUG, "{}".format(str(log)))
        myhostname = socket.gethostname()
        externalObject = ExternalObject(
            buffer=milterContext.fileBuffer,
            externalVars=ExternalVars(
                filename=milterContext.archiveFileName,
                source=(
                    milterContext.milterConfig.milterName +
                    "-" +
                    str(myhostname[:myhostname.index(".")])
                ),
                ephID=milterContext.qid,
                uniqID=milterContext.messageID
            ),
            level=level_metadata
        )
        result = self.client.send(
            externalObject,
            retry=numRetries,
            timeout=REQUEST_TIMEOUT)
        if result:
            self.match  = flagRollup(result)
            if not self.match:
                self.match = []
            self.attachements  = ','.join(getAttachmentList(result))
            strScanResult = finalDispositionFromResult(result)
            strScanResults= " ".join(dispositionFromResult(result))
            if strScanResult:
                self.strScanResult = strScanResult
            try:
                self.dispositions  = strScanResults
            except:
                self.logger.writeLog(
                    syslog.LOG_ERR,
                    (milterContext.uuid +
                     " ERROR getting dispositions via client lib")
                )
            gotResponseFromScanner = 1
        else:
            self.logger.writeLog(
                syslog.LOG_ERR,
                (milterContext.uuid +
                 " " +
                 str(milterContext.qid) +
                 "| no result object from scanner, returning SCAN ERROR")
            )

        return gotResponseFromScanner

class log2syslog():
    def __init__(self, name, facility):
        syslog.openlog(name, 0, facility)

    def writeLog(self, logLevel, stringToLog):
        syslog.syslog(logLevel, "{}".format(str(stringToLog)))

    def closeLog(self):
        syslog.closelog()


class MilterConfig():
    '''
    MilterConfig: Class used to load config file

    Start: 1) Instantiate with new MilterConfig()
       2) Load config file
        2.1) loadAll: loads all sections (listed below) of the config file
        2.2) loadConfig: loads COMMON section of the config file
        2.3) loadDispositionModes: loads DispositionMode section of the config
                                   file
        2.4) loadHeaderOptions: loads HeaderOptions section of the config file
        2.5) loadScanServers: loads ScanServers section of the config file

    '''

    def __init__(self):
        self.milterName = "laikamilter"           #Will appear in syslog
        self.milterInstance = "laika"
        self.socketname = "inet:7226@localhost" #Socket to listen for connections
        self.servers = []                    #zmq Servers
        self.mode = "run"                 #Default mode "run" or "shutdown"
        self.zmqMaxRetry = 1
        self.zmqTimeout = 55000
        self.maxFiles = 950
        self.heloWhitelist = ""
        self.configFileLoc = "/etc/laikamilter/laikamilter.conf"
        self.storeEmails = False
        self.storeDir = "/data/mail/"
        self.customFolderDateFormat = ""
        self.ApplyCustomHeaders = False
        self.CustomHeaderBase = "LAIKA"
        self.ApplyMailscanResultHeader = True
        self.MailscanResultHeaderString = "X-Mailscan-Result"
        self.loadAttempt = 0
        self.maxLoadAttempts = 2
        self.loadError = False
        self.dispositionModes = {}
        self.dispositionModes["default"] = Milter.CONTINUE


    def loadAll(self):
        self.loadError = False
        self.loadAttempt += 1
        self.loadConfig()
        self.loadScanServers()
        self.loadDispositionModes()
        self.loadHeaderOptions()

        # Allow config file to reload itself.  If a new config file gets
        # written, it may be unreadable while the new file is written to disk.
        # Sleep 1 sec and try again when file write is complete.
        if ((self.loadError) and (self.loadAttempt <= self.maxLoadAttempts)):
            log = "Error loading Config File from loadAll, trying again"
            logger = log2syslog(self.milterName, syslog.LOG_LOCAL0)
            logger.writeLog(syslog.LOG_ERR, "{}".format(str(log)))
            time.sleep(1)
            self.loadAll()
        elif ((self.loadError) and (self.loadAttempt > self.maxLoadAttempts)):
            log = "Error loading Config File from loadAll, using Defaults"
            logger = log2syslog(self.milterName, syslog.LOG_LOCAL0)
            logger.writeLog(syslog.LOG_ERR, "{}".format(str(log)))

    def loadConfig(self):
        Config = ConfigParser.ConfigParser()
        try:
            Config.read(self.configFileLoc)
            self.socketname = Config.get('COMMON', 'socketname')
            self.milterName = Config.get('COMMON', 'MilterName')
            self.milterInstance = Config.get('COMMON', 'MilterInstance')
            self.mode = Config.get('COMMON', 'mode')
            self.zmqMaxRetry = int(Config.get('COMMON', 'zmqMaxRetry'))
            self.zmqTimeout = int(Config.get('COMMON', 'zmqTimeout'))
            self.maxFiles = int(Config.get('COMMON', 'maxFiles'))
            self.heloWhitelist = str(Config.get('COMMON', 'helowhitelist'))
            self.storeEmails = self._convertTrueFalse(
                Config.get('ArchiveOptions', 'storeEmails'))
            self.storeDir = Config.get('ArchiveOptions', 'storeDir')
            self.customFolderDateFormat = Config.get(
                'ArchiveOptions', 'customFolderDateFormat')
        except ConfigParser.NoSectionError:
            if (self.loadAttempt >= self.maxLoadAttempts):
                log = ("Error loading Config File for COMMON config, " +
                       "USING DEFAULTS")
                logger = log2syslog(self.milterName, syslog.LOG_LOCAL0)
                logger.writeLog(syslog.LOG_ERR, "{}".format(str(log)))
            else:
                self.loadError = True
                log = ("Error loading Config File for COMMON config, " +
                       "should try again")
                logger = log2syslog(self.milterName, syslog.LOG_LOCAL0)
                logger.writeLog(syslog.LOG_ERR, "{}".format(str(log)))

    def loadDispositionModes(self):
        Config = ConfigParser.ConfigParser()
        try:
            Config.read(self.configFileLoc)
            DispositionModes = Config.items('DispositionMode')
            for DispositionMode in DispositionModes:
                self.dispositionModes[DispositionMode[0]] = \
                    self._convertDispositionMode(DispositionMode[1])
        except ConfigParser.NoSectionError:
            if (self.loadAttempt >= self.maxLoadAttempts):
                log = ("Error loading Config File for DispositionMode config," +
                       " USING DEFAULTS")
                logger = log2syslog(self.milterName, syslog.LOG_LOCAL0)
                logger.writeLog(syslog.LOG_ERR, "{}".format(str(log)))
            else:
                self.loadError = True
                log = ("Error loading Config File for DispositionMode config," +
                       " should try again")
                logger = log2syslog(self.milterName, syslog.LOG_LOCAL0)
                logger.writeLog(syslog.LOG_ERR, "{}".format(str(log)))

    def loadHeaderOptions(self):
        Config = ConfigParser.ConfigParser()
        try:
            Config.read(self.configFileLoc)
            self.ApplyCustomHeaders = self._convertTrueFalse(
                Config.get('HeaderOptions', 'ApplyCustomHeaders'))
            self.CustomHeaderBase = Config.get(
                'HeaderOptions', 'CustomHeaderBase')
            self.ApplyMailscanResultHeader = self._convertTrueFalse(
                Config.get('HeaderOptions', 'ApplyMailscanResultHeader'))
            self.MailscanResultHeaderString = Config.get(
                'HeaderOptions', 'MailscanResultHeaderString')
        except ConfigParser.NoSectionError:
            if (self.loadAttempt >= self.maxLoadAttempts):
                log = ("Error loading Config File for HeaderOptions config," +
                       " USING DEFAULTS")
                logger = log2syslog(self.milterName, syslog.LOG_LOCAL0)
                logger.writeLog(syslog.LOG_ERR, "{}".format(str(log)))
            else:
                self.loadError = True
                log = ("Error loading Config File for HeaderOptions config," +
                       " should try again")
                logger = log2syslog(self.milterName, syslog.LOG_LOCAL0)
                logger.writeLog(syslog.LOG_ERR, "{}".format(str(log)))
        except ConfigParser.NoOptionError:
            if (self.loadAttempt >= self.maxLoadAttempts):
                log = ("Error loading Config File for HeaderOptions config," +
                       " USING DEFAULTS")
                logger = log2syslog(self.milterName, syslog.LOG_LOCAL0)
                logger.writeLog(syslog.LOG_ERR, "{}".format(str(log)))
            else:
                self.loadError = True
                log = ("Error loading Config File for HeaderOptions config," +
                       " should try again")
                logger = log2syslog(self.milterName, syslog.LOG_LOCAL0)
                logger.writeLog(syslog.LOG_ERR, "{}".format(str(log)))

    def loadScanServers(self):
        Config = ConfigParser.ConfigParser()
        try:
            Config.read(self.configFileLoc)
            servers = Config.items('ScanServers')
            for server in servers:
                self.servers.append(server[1])
        except ConfigParser.NoSectionError:
            if (self.loadAttempt >= self.maxLoadAttempts):
                log = ("Error loading Config File for ScanServers config," +
                       " USING DEFAULTS")
                logger = log2syslog(self.milterName, syslog.LOG_LOCAL0)
                logger.writeLog(syslog.LOG_ERR, "{}".format(str(log)))
            else:
                self.loadError = True
                log = ("Error loading Config File for ScanServers config," +
                       " should try again")
                logger = log2syslog(self.milterName, syslog.LOG_LOCAL0)
                logger.writeLog(syslog.LOG_ERR, "{}".format(str(log)))


    def _convertDispositionMode(self, strMode):
        convertedMode = Milter.CONTINUE
        if(strMode == "ACCEPT"):
            convertedMode = Milter.ACCEPT
        elif(strMode == "CONTINUE"):
            convertedMode = Milter.CONTINUE
        elif(strMode == "REJECT"):
            convertedMode = Milter.REJECT
        elif(strMode == "DISCARD"):
            convertedMode = Milter.DISCARD
        elif(strMode == "TEMPFAIL"):
            convertedMode = Milter.TEMPFAIL

        return convertedMode

    def _unconvertDispositionMode(self, convertedMode):
        '''
        convert integer value of rtnToMTA to back to string
        '''
        strMode = ""
        if(convertedMode == Milter.ACCEPT):
            strMode = "ACCEPT"
        elif(convertedMode == Milter.CONTINUE):
            strMode = "CONTINUE"
        elif(convertedMode == Milter.REJECT):
            strMode = "REJECT"
        elif(convertedMode == Milter.DISCARD):
            strMode = "DISCARD"
        elif(convertedMode == Milter.TEMPFAIL):
            strMode = "TEMPFAIL"
        return strMode


    def _convertTrueFalse(self, input):
        convertedValue = False
        if (input.upper() == "TRUE"):
            convertedValue = True
        elif(input.upper == "FALSE"):
            convertedValue = False
        else:
            convertedValue = "Error"

        return convertedValue


#Main entry point for the program.
if __name__ == "__main__":

    random.seed()

    altConfig = None
    if len(sys.argv) == 2:
        altConfig = sys.argv[1]
        print("Config: " + altConfig)

    milterConfig = MilterConfig()


    if altConfig:
        print("using alternative config path: {}".format(altConfig))
        if not os.path.exists(altConfig):
            print("the provided config path is not valid, exiting")
        else:
            milterConfig.configFileLoc = altConfig


    milterConfig.loadConfig()

    logger = log2syslog(milterConfig.milterName, syslog.LOG_LOCAL0)

    try:
        with open (milterConfig.heloWhitelist, 'rb') as f:
           config = json.load(f)
           for MTA_group, exclusions_group in config['exclusions'].items():
               for MTA_address in config['group'][MTA_group]:
                   for exclusion in exclusions_group:
                       for exclusion_address in config['group'][exclusion]:
                           global_whitelist["{}_{}".format(
                               MTA_address,
                               exclusion_address)] = None
    except IOError:
        global_whitelist = {}
        logger.writeLog(
            syslog.LOG_ERR,
            "IOError: Unable to load whitelist from config file: {}".format(
                milterConfig.heloWhitelist)
        )
    except:
        global_whitelist = {}
        logger.writeLog(
            syslog.LOG_ERR,
            "Unknown error while loading whitelist: {}".format(
                milterConfig.heloWhitelist)
        )

    logger.writeLog(
        syslog.LOG_DEBUG,
        "{} Starting".format(milterConfig.milterInstance)
    )

    myID = os.getuid()
    grID = os.getgid()
    log = str(myID)+" "+str(grID)
    logger.writeLog(
        syslog.LOG_DEBUG,
        "{} running as uid:{} gid{}".format(
            milterConfig.milterInstance,
            myID,
            grID
        )
    )

    # resource.setrlimit(resource.RLIMIT_NOFILE, limits)
    maxNumOpenFiles = resource.getrlimit(resource.RLIMIT_NOFILE)
    logger.writeLog(
        syslog.LOG_DEBUG,
        "{} File Handle Limits (soft, hard): {}".format(
            milterConfig.milterInstance,
            str(maxNumOpenFiles)
        )
    )

    # Configure  LaikaMilter factory
    Milter.factory = LaikaMilter
    Milter.set_flags(Milter.CHGBODY + Milter.CHGHDRS + Milter.ADDHDRS)
    sys.stdout.flush()

    # Attempt to start Milter factory. If milter cannot start, is is usually
    # because there is another milter running.
    try:
        Milter.runmilter(milterConfig.milterName,milterConfig.socketname,240)
    except Milter.error:
        log = (
            "Could not open port " +
            milterConfig.socketname +
            ".  Another milter instance may be running."
        )
        logger.writeLog(syslog.LOG_ERR, "{}".format(str(log)))

    logger.writeLog(
        syslog.LOG_DEBUG,
        "{} Shutting Down".format(milterConfig.milterInstance)
    )
    logger.closeLog()
