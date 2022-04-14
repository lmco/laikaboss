from __future__ import print_function
from gevent import monkey
monkey.patch_all()

import logging
import optparse
import slimta.relay.blackhole
import slimta.relay
import slimta.logging
import ssl
import os
import shutil
import binascii
import sys
import datetime
import ipaddress
import time
import pathlib
import socket

from builtins import str as text
from slimta.edge.smtp import SmtpEdge
from slimta.queue import Queue
from slimta.policy.headers import *
from laikaboss.extras.extra_util import write_to_log
from laikaboss.objectmodel import ExternalObject, ExternalVars
from laikaboss.util import laika_submission_encoder
from laikaboss.lbconfigparser import LBConfigParser
from configparser import NoSectionError
from slimta.policy import QueuePolicy
from slimta.diskstorage import AioFile
from collections import OrderedDict

_sys_config_path = "/etc/laikaboss/laikamail.conf"
_dev_config_path = "etc/laikamail/laikamail.conf"
_mail_msg_log = "/var/log/laikaboss/laikamail-messages.log"
_mail_daemon_log = "/var/log/laikaboss/laikamail-app.log"
_submission_dir = "/var/laikaboss/submission-queue/"
_logging_fields = ['from', 'msgid', 'qid', 'recipients', 'client_ip', 'client_helo', 'client_host', 'proto', 'size']
_default_log_level = logging.WARN
_hostname = socket.getfqdn()
_short_hostname = _hostname

if '.' in _hostname:
  _short_hostname = _hostname[:_hostname.find('.')]

_source = 'email-' + _short_hostname

def setupLoggers(log_path, debug=False):

    logFormatter = logging.Formatter("%(asctime)s - %(process)d [%(levelname)-5.5s]  %(message)s")

    rootLogger = logging.getLogger()
    fileHandler = logging.FileHandler(log_path, mode='a')
    fileHandler.setFormatter(logFormatter)
    rootLogger.addHandler(fileHandler)

    for x in ['slimta', 'slimta.edge', 'slimta.smtp.io', 'slimta.diskstorage']:
        tmp = logging.getLogger(x)
        if debug:
           tmp.setLevel(logging.DEBUG)
        else:
           tmp.setLevel(_default_log_level)
        tmp.addHandler(fileHandler)

    consoleHandler = logging.StreamHandler()
    consoleHandler.setFormatter(logFormatter)
    rootLogger.addHandler(consoleHandler)

    if debug:
       rootLogger.setLevel(logging.DEBUG)
    else:
       rootLogger.setLevel(_default_log_level)

def log_failure(err_path, recipient=None, code="", msg="", result="error", envelope=None, session=None, mtaId=""):

    item = OrderedDict()
    item["eventtime"] = str(datetime.datetime.utcnow().isoformat("T") + "Z")
    item["result"] = result

    for x in _logging_fields:
       item[x] = get_log_item(session, envelope, x, "", recipient = recipient)

    item['code'] = code
    item['msg'] = msg

    try:
       write_to_log(err_path, item)
    except:
       qid = str(item.get("qid", ""))
       msgid = str(item.get("msgid", ""))
       logging.exception("error logging:" + qid + " message-id:" + str(msgid) + " mtaID:" + mtaId)


def get_header(envelope, name, default='', strip_brackets=False, as_list = False):

    tmp = ''

    if envelope and envelope.headers:
        tmp = envelope.headers.get_all(name, '')

    try:

        if tmp:
           if not isinstance(tmp, list):
              tmp = [tmp]

        # filter out empty items, force sub headers to strings
        tmp = [str(x).strip() for x in tmp if x]
        if tmp and len(tmp) == 1 and not as_list:
           tmp = tmp[0]
    except IndexError as e:
        pass

    if tmp and not as_list and strip_brackets:
        # its an unexpected list - possibly multiple message-ids
        if isinstance(tmp, list):
           tmp = '|'.join(tmp)
        tmp = tmp.replace("<", "").replace(">", "")

    if not tmp:
       return default

    return tmp

def _encode_headers(d, encoding=None):
    result = ""
    for key in d:
        value = d[key]
        result += (key + ": " + value + "\r\n")
    if encoding:
       result = result.encode(encoding)
    return result


def get_log_item(session, envelope, item, default=None, recipient=None):
    val = ""

    if item == "from":
       if envelope:
          val = envelope.sender
    if item == "client_ip":
       if session and session.address:
          val = session.address[0]
       if not val and envelope:
          val = envelope.client.get("ip", '')
    elif item == "client_helo":
       if session:
          val = session.ehlo_as
       if not val and envelope:
          val = envelope.client.get("name", '')
    elif item == "client_host":
       if session:
          val = session.reverse_address
       if not val and envelope:
          val = envelope.client.get("name", '')
    elif item == "proto":
       if envelope:
          val = envelope.client.get("protocol", '')
       if not val and session:
          val = session.protocol
       if not val and session:
          val = session.security
    elif item == "size":
       if envelope and envelope.buffer:
          # currently this is the size before we modify it
          val = len(envelope.buffer)
    elif item == "msgid":
       if envelope:
          val = get_header(envelope, 'Message-Id', '', strip_brackets=True)
    elif item == "qid":
       if envelope:
          val = get_header(envelope, 'X-LAIKA-ID', '', as_list=True)
    elif item == "subject":
       if envelope:
          val = get_header(envelope, 'Subject', '')
    elif item == "recipients":
       val = []
       if recipient:
          val.append(recipient)
       elif envelope:
          val.extend(envelope.recipients)
    else:
       val = get_header(envelope, item, '', as_list=True)

    if not val:
       return default

    return val

class LogMailPolicy(QueuePolicy):

    def __init__(self, path=None, mid_header=""):
        super(QueuePolicy, self).__init__()
        self.set_args(path, mid_header)

    def set_args(self, path=None, mid_header=""):
        self.path = path
        self.mid_header = mid_header

    def apply(self, envelope):

        item = OrderedDict()
        item["eventtime"] = str(datetime.datetime.utcnow().isoformat("T") + "Z")
        item["result"] = "ok"

        for x in _logging_fields:
           item[x] = get_log_item(None, envelope, x, "")

        try:
           write_to_log(self.path, item)
        except:
           mtaId = ""
           if self.mid_header:
              mtaId = get_header(envelope, self.mid_header, '')
           qid = str(item.get("qid", ""))
           msgid = str(item.get("msgid", ""))
           logging.exception("error logging:" + qid + " message-id:" + str(msgid) + " mtaID:" + mtaId)

class AddStoreDiskPolicy(QueuePolicy):

    def __init__(self, msg_log, submission_dir="/tmp", tmp_dir="/tmp", mid_header="", source="", modify=True, stash_headers=False):
        super(QueuePolicy, self).__init__()
        self.set_args(msg_log, submission_dir, tmp_dir, mid_header, source, modify, stash_headers)

    def set_args(self, msg_log, submission_dir="/tmp", tmp_dir="/tmp", mid_header="", source="", modify=True, stash_headers=False):
        self.msg_log = msg_log
        self.submission_dir = submission_dir
        self.tmp_dir = tmp_dir
        self.mid_header = mid_header
        self.source = source
        self.modify = modify
        self.stash_headers = stash_headers

    def prepare(self, envelope):

        result = "ok"
        qid = binascii.hexlify(os.urandom(10)).decode('utf8')

        buf = envelope.buffer

        now = datetime.datetime.utcnow()

        extra_headers = {}

        if self.modify:

           extra_headers["X-LAIKA-ID"] = qid
           extra_headers["X-LAIKA-HELO"] = str(envelope.client.get("name",''))
           extra_headers["X-LAIKA-FROM"] = str(envelope.sender)
           extra_headers["X-LAIKA-DATE"] = str(now.isoformat("T") + "Z")
           extra_headers["X-LAIKA-ADDR"] = str(envelope.recipients)

           for header in extra_headers:
               # if the header is already there, this one will be closer to the top
               envelope.prepend_header(header, extra_headers[header])

        messageID = get_header(envelope, 'Message-Id', '', strip_brackets=True)

        mtaId = ""
        if self.mid_header:
           mtaId = get_header(envelope, self.mid_header, '')

        externalVars = ExternalVars(source=self.source, submitID=qid)
        if self.modify:
           mbox_header = "From " + str(envelope.sender).replace(">", "").replace("<", '') + ' ' + str(time.asctime(now.timetuple()))
           buf = (mbox_header.encode('utf-8') + b"\r\n" + _encode_headers(extra_headers, 'utf-8') + buf)

        externalObject = ExternalObject(buf, externalVars = externalVars)

        archiveEncoder = laika_submission_encoder(submission_dir=self.submission_dir, queue = 'email', externalVars = externalVars)

        fileName = archiveEncoder.get_output_filename()

        externalVars.set_ephID(qid)
        externalVars.set_uniqID(messageID)
        externalVars.set_filename(fileName)

        # this is purely a debugging hack, so we can see the headers in automated tests
        if self.stash_headers:
           externalVars.set_comment(envelope.headers.items())

        buf = ExternalObject.encode(externalObject)

        return fileName, buf, result


    def apply(self, envelope):

        fileName, buf, _ = self.prepare(envelope)

        partialFileName = os.path.join(self.tmp_dir, os.path.basename(fileName)) + ".partial"

        try:
            AioFile(partialFileName, self.tmp_dir).dump(buf)
            shutil.move(partialFileName, fileName)
        except IOError:
            logging.exception("Could not open "+ fileName + " or " + partialFileName + " for writing")

        return

class smtpValidator(slimta.edge.smtp.SmtpValidators):

     valid_recipients = None
     path = None
     networks = None

     @classmethod
     def set_args(cls, valid_recipients, networks=None, path=None):
         smtpValidator.path = path
         if valid_recipients:
            valid_recipients = valid_recipients.split(",")
            smtpValidator.valid_recipients = [x.lower().strip() for x in valid_recipients]

         if networks:
            networks = networks.split(",")
            # convert ip to unicode on py2
            smtpValidator.networks = [ipaddress.ip_network(text(x.lower().strip())) for x in networks]
     def handle_banner(self, reply, address):

         result = True

         # address tuple is (ip, port)
         saddr = text(address[0])

         if smtpValidator.networks:
            addr = ipaddress.ip_address(saddr)
            result = False
            for network in smtpValidator.networks:
                if addr in network:
                   result = True
                   break

         if not result:
            reply.code = '550'
            reply.message = \
                    '5.7.1 client address <{0}> Not allowed'.format(saddr)
            log_failure(smtpValidator.path, session=self.session, code=reply.code, msg=reply.message, mtaId="")

     def handle_rcpt(self, reply, recipient, params):

         tmp = recipient.lower().strip()
         tmp_short = ''
      
         try:
            tmp_short, _ = tmp.split('@', 2)
         except:
            pass

         if smtpValidator.valid_recipients:
            if (tmp in smtpValidator.valid_recipients) or (tmp_short and tmp_short in smtpValidator.valid_recipients):
                pass
            else:
                reply.code = '550'
                reply.message = \
                        '5.7.1 Recipient <{0}> Not allowed'.format(recipient)

                log_failure(smtpValidator.path, session=self.session, code=reply.code, msg=reply.message, mtaId="")

def create_smtpValidator(msg_log, recipients="", networks=""):

    validator = None
    if recipients or networks:
       validator = smtpValidator
       validator.set_args(valid_recipients=recipients, path=msg_log, networks=networks)

    return validator

def create_ssl_context(cert, key):

       context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

       try:
          with open(cert) as fp:
              pass
       except e:
          logging.exception("file access issue " + cert)
          raise e

       try:
          with open(key) as fp:
              pass
       except Exception as e:
          logging.exception("file access issue " + key)
          raise e

       context.load_cert_chain(cert, key)

       return context

def main():
    '''Main program logic. Becomes the supervisor process.'''
    parser = optparse.OptionParser(usage="usage: %prog [options]\n"
        "Overrides settings in config file: laikamail.conf")

    parser.add_option("-d", "--debug",
                      action="store_true", default=False,
                      dest="debug",
                      help="enable debug messages to the console. default:%default")
    parser.add_option("--log-headers",
                      action="store", default="",
                      dest="log_headers",
                      help="comma seperated list of allowed recipients or blank for all")
    parser.add_option("-r", "--recipients",
                      action="store", default="",
                      dest="recipients",
                      help="comma seperated list of allowed recipients or blank for all")
    parser.add_option("--submission-dir", default=_submission_dir,
                      action="store", type="string",
                      dest="submission_dir",
                      help="specify the path for persistant storage queue. default:%default")
    parser.add_option("--source", default=_source,
                      action="store", type="string",
                      dest="source",
                      help="specify the path for persistant storage queue default:%default")
    parser.add_option("--tmp-dir",
                      action="store", type="string", default="/tmp",
                      dest="tmp_dir",
                      help="specify the path for temp storage queue default:%default")
    parser.add_option("-p", "--port",
                      action="store", type="int", default=25,
                      dest="port",
                      help="specify the listening port default:%default")
    parser.add_option("-n", "--networks",
                      action="store", type="string", default="",
                      dest="networks",
                      help="comma seperated list of cidr networks which are allowed to send email")
    parser.add_option("-a", "--address",
                      action="store", type="string", default="127.0.0.1",
                      dest="address",
                      help="specify the listening ip default:%default")
    parser.add_option("-m", "--message-log",
                      action="store", type="string", default=_mail_msg_log,
                      dest="msg_log",
                      help="path to the message log file default:%default")
    parser.add_option("--daemon-log",
                      action="store", type="string", default=_mail_daemon_log,
                      dest="daemon_log",
                      help="path to the daemon log file default:%default")
    parser.add_option("--mta-id-header",
                      action="store", type="string", default="",
                      dest="mid_header",
                      help="if the mta puts a specific header in which ids the email include it here:%default")
    parser.add_option("--mode",
                      action="store", type="string", default="disk",
                      dest="storage_mode",
                      help="disk")
    parser.add_option("--tls",
                      action="store", type="string", default="off",
                      dest="tls",
                      help="on, off, start-tls default:%default")
    parser.add_option("-k", "--tls-key",
                      action="store", type="string", default="key.pem",
                      dest="tls_key",
                      help="path to tls key default:%default")
    parser.add_option("-c", "--tls-cert",
                      action="store", type="string", default="cert.pem",
                      dest="tls_cert",
                      help="path to tls cert default:%default")


    # contains results including default values - use as the base for configs
    (options_with_defaults, _) = parser.parse_args()


    configs = {}

    #create an empty values object - needed as a flag to tell it not to use defaults
    trigger_disable_default_usage = optparse.Values()

    # contains all options which were not from defaults - used to override config files with explicit command line options
    options_with_no_defaults, args = parser.parse_args(values=trigger_disable_default_usage)

    # Read the laikamail config file
    config_path = None
    for tmp in [_dev_config_path, _sys_config_path]:
        if os.path.exists(tmp):
           config_path = tmp
    config_parser = LBConfigParser()

    if config_path:
       config_parser.read(config_path)

    configs.update(vars(options_with_defaults))


    try:
       configs.update(dict(config_parser.items("General")))
    except NoSectionError:
       pass

    try:
       configs.update(dict(config_parser.items("laikamail")))
    except NoSectionError:
       pass


    configs.update(vars(options_with_no_defaults))

    pathlib.Path(configs["submission_dir"]).mkdir(parents=True, exist_ok=True)

    setupLoggers(configs["daemon_log"], debug=configs["debug"])

    headers = configs.get("log_headers", "")

    if headers:
       headers = headers.split(",")
       headers = [x.strip() for x in headers]
       _logging_fields.extend(headers)

    tmp_dir = configs["tmp_dir"]
    queue_storage = slimta.diskstorage.DiskStorage(env_dir=tmp_dir, meta_dir=tmp_dir, tmp_dir=tmp_dir)

    relay = slimta.relay.blackhole.BlackholeRelay()

    queue = Queue(queue_storage, relay)
    queue.start()

    # Ensure necessary headers are added.
    #queue.add_policy(AddDateHeader())
    #queue.add_policy(AddMessageIdHeader())
    #queue.add_policy(AddReceivedHeader())

    source = configs.get("source", None)

    msg_log = configs.get("msg_log")

    storage_mode = configs["storage_mode"]
    if storage_mode == 'disk':
        queue.add_policy(AddStoreDiskPolicy(msg_log, submission_dir=configs["submission_dir"], tmp_dir=tmp_dir, mid_header=configs["mid_header"], source=source, modify=True))
    else:
        logging.error("storage_mode:" + storage_mode + " does not exist exiting")
        print("storage_mode: " + str(storage_mode) + " does not exist exiting", file=sys.stderr)
        sys.exit(1)

    queue.add_policy(LogMailPolicy(msg_log))

    tls_immediately = False
    context = None
    tls = configs["tls"].lower()
    if tls in ['on', 'start-tls']:
       context = create_ssl_context(configs["tls_cert"], configs["tls_key"])
       tls_immediately = True
       if tls == 'start-tls':
          tls_immediately = False

    validator = create_smtpValidator(msg_log, configs["recipients"], configs["networks"])

    edge = SmtpEdge((configs["address"], configs["port"]), queue, tls_immediately=tls_immediately, context=context, validator_class=validator)

    edge.start()
    try:
        edge.get()
    except KeyboardInterrupt:
        print

if __name__ == "__main__":
    main()
