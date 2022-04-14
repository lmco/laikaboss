# Copyright 2016 Josh Liburdi
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
# upstream project: https://github.com/jshlbrd/laikaboss-modules
#

from future import standard_library
standard_library.install_aliases()
from laikaboss.si_module import SI_MODULE
from laikaboss.objectmodel import ModuleObject, ExternalVars, ScanError
from laikaboss.util import get_option
from laikaboss.extras import email_word_list_util

import pdfminer
import pdfminer.ccitt
from pdfminer.pdfparser import PDFParser
from pdfminer.pdfdocument import PDFDocument, PDFEncryptionError, PDFPasswordIncorrect
from pdfminer.pdftypes import PDFStream, PDFObjectNotFound, PDFObjRef, PSException, PDFException, int_value
from pdfminer.psparser import PSEOF, LIT, PSLiteral
import io
import sys
import codecs
import logging

class EXPLODE_PDF(SI_MODULE):
    '''

    extract PDF streams and URIs
    
    requires python-pdfminer package

    params:
        filelimit (global: pdffilelimit): max number of streams to extract
        totalbytelimit (global: pdftotalbytelimit): stop extracting streams after totalbytelimit bytes are extracted
    '''
    def __init__(self,):
        self.module_name = "EXPLODE_PDF"
        # PdfMiner logs can be super noisy, turn them down
        pdflog = logging.getLogger('pdfminer')
        pdflog.setLevel(logging.WARNING)

    def _run(self, scanObject, result, depth, args):
        moduleResult = []

        file_limit = int(get_option(args, 'filelimit', 'pdffilelimit', 1000))
        byte_limit = int(get_option(args, 'totalbytelimit', 'pdftotalbytelimit', 1073741824))
        password = get_option(args, 'password', 'pdfpassword', '')
        hardcoded_password_list_path = get_option(args, 'passwordlistpath', 'PasswordListLocation', '/etc/laikaboss/passwords_to_try')

        file_limit_reached = False
        total_byte_limit_reached = False
        total_bytes_extracted = 0
        stream_count = 0

        pdfBuffer = io.BytesIO(scanObject.buffer)

        uris = set([])
        missing_object_ids = set([])

        try:
            try:
                pdf = PDFParser(pdfBuffer)
                #Construct this separately so we can get encryption info if __init__() fails
                pdfDoc = PDFDocument.__new__(PDFDocument)
                pdfDoc.__init__(pdf)
                # If it's encrypted, but no exception, it had a blank password
                if hasattr(pdfDoc, 'encryption') and pdfDoc.encryption:
                    scanObject.addFlag('pdf:encrypted')
                    scanObject.addFlag('pdf:blank_password')
            except PDFEncryptionError as e:
                scanObject.addFlag('pdf:encrypted')
                encryption_version = int_value(pdfDoc.encryption[1].get('V', 0))
                if encryption_version > 4:
                    password_encoding = 'utf-8'
                else:
                    password_encoding = 'latin1'
                # Get password candidate list from sibling objects if they exist
                sibling_text = email_word_list_util.get_sibling_text(result, scanObject)
                word_list = email_word_list_util.create_word_list(sibling_text, hardcoded_password_list_path)
                # Prepend password if given
                if password:
                    if isinstance(password, bytes):
                        password = password.decode('utf-8', 'ignore')
                    word_list.insert(0, password)
                # Try all passwords
                correct_password = None
                for word in word_list:
                    try:
                        # Older versions of pdfminer take bytes, not string
                        if pdfminer.__version__ <= '20140328':
                            word = word.encode(password_encoding)
                        pdf = PDFParser(pdfBuffer)
                        pdfDoc = PDFDocument(pdf, word)
                        # If we get to here, was right password
                        correct_password = word
                        if isinstance(correct_password, bytes):
                            correct_password = correct_password.decode(password_encoding)
                        scanObject.addMetadata(self.module_name, 'Password', 
                                                correct_password)
                        scanObject.addFlag('pdf:decrypt_success')
                        break
                    except (PDFEncryptionError, UnicodeEncodeError) as e:
                        pass
                if not correct_password:
                    scanObject.addFlag('pdf:decrypt_failure')
                    raise

            for xref in pdfDoc.xrefs:
                for objid in xref.get_objids():
                    if objid == 0:
                        scanObject.addFlag('pdf:INVALID_OBJECT_ID')
                        continue
                    try:
                        obj = pdfDoc.getobj(objid)
                        if isinstance(obj, dict):
                            items = list(obj.items())
                            for (key,val) in items:
                                if key in ['AA','OpenAction']:
                                    scanObject.addFlag('pdf:auto_action')
                                elif key in ['JS','Javascript']:
                                    scanObject.addFlag('pdf:js_embedded')
                                    # Pop out javascript as child object
                                    if stream_count >= file_limit:
                                        file_limit_reached = True
                                    elif total_bytes_extracted > byte_limit:
                                        total_byte_limit_reached = True
                                    else:
                                        script_data = val
                                        # Dereference script objects as necessary
                                        if isinstance(script_data, PDFObjRef):
                                            script_data = script_data.resolve()
                                        if isinstance(script_data, PDFStream):
                                            script_data = script_data.get_data()
                                        if isinstance(script_data, PSLiteral):
                                            script_data = script_data.name
                                        # If left with string/bytes, decode
                                        if isinstance(script_data, (bytes, str)):
                                            total_bytes_extracted = total_bytes_extracted + len(script_data)
                                            script = self.decode_pdf_string(script_data)
                                            moduleResult.append(ModuleObject(buffer=script, externalVars=ExternalVars(filename='e_pdf_javascript_%s' % objid, contentType='text/javascript')))
                                        else:
                                            logging.warning('Javascript was of type', type(script_data), 'instead of string, not extracting')
                                elif key in ['URI','URL']:
                                    if isinstance(val, PDFObjRef):
                                        uris.add(val.resolve())
                                    elif isinstance(val, dict):
                                        uris.add(val['Base'])
                                    else:
                                        uris.add(val)
                                elif isinstance(val, dict):
                                    items.extend(list(val.items()))
                        if isinstance(obj, PDFStream):
                            if 'Type' in obj.attrs:
                                if stream_count >= file_limit:
                                    file_limit_reached = True
                                elif total_bytes_extracted > byte_limit:
                                    total_byte_limit_reached = True
                                else:
                                    try:
                                        child_data = obj.get_data()
                                        total_bytes_extracted = total_bytes_extracted + len(child_data)
                                        moduleResult.append(ModuleObject(buffer=child_data, externalVars=ExternalVars(filename='e_pdf_stream_%s' % objid)))
                                    except PSException as e:
                                        scanObject.addFlag('pdf:%s' % type(e).__name__)
                                    except PDFException as e:
                                        scanObject.addFlag('pdf:%s' % type(e).__name__)
                                    except ScanError:
                                        raise
                                    except pdfminer.ccitt.CCITTG4Parser.InvalidData:
                                        logging.error('Invalid data in pdf stream %s' % objid)
                                    except (IndexError, TypeError, ValueError, AttributeError) as e:
                                        logging.exception('Error while extracting pdf stream')
                                stream_count = stream_count + 1

                    except PDFObjectNotFound:
                        scanObject.addFlag('pdf:MISSING_OBJECT')
                        missing_object_ids.add(objid)
                    except ScanError:
                        raise
            if uris:
                scanObject.addMetadata(self.module_name, "URIs", uris)
            if missing_object_ids:
                scanObject.addMetadata(self.module_name, "missing_object_ids", missing_object_ids)
            if file_limit_reached:
                scanObject.addFlag('pdf:FILE_LIMIT_EXCEEDED')
            if total_byte_limit_reached:
                scanObject.addFlag('pdf:TOTAL_BYTE_LIMIT_EXCEEDED') 
        except PDFPasswordIncorrect as e:
            pass
        except PSException as e:
            scanObject.addFlag('pdf:%s' % type(e).__name__)
        except PDFException as e:
            scanObject.addFlag('pdf:%s' % type(e).__name__)
        except ScanError:
            raise

        return moduleResult

    # Decodes a pdf string by detecting the UTF-16 BOM, and defaulting to latin1 
    # if not found. Non-utf16 strings are actually in their own special encoding, 
    # but latin1 is close enough.
    @classmethod
    def decode_pdf_string(cls, data):
        if not isinstance(data, bytes):
            return data
        decoded = ''
        if data.startswith(codecs.BOM_UTF16_LE): # \xff\xfe
            decoded = data[2:].decode('utf-16le')
        elif data.startswith(codecs.BOM_UTF16_BE): # \xfe\xff
            decoded = data[2:].decode('utf-16be')
        else:
            decoded = data.decode('latin1')
        return decoded
