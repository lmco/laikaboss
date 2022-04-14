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
from future import standard_library
standard_library.install_aliases()
import pdfminer
from pdfminer.pdfdocument import PDFDocument, PDFEncryptionError, PDFPasswordIncorrect
from pdfminer.pdfparser import PDFParser
from pdfminer.pdfinterp import PDFResourceManager, PDFPageInterpreter
from pdfminer.pdfdevice import PDFDevice, TagExtractor
from pdfminer.pdfpage import PDFPage
from pdfminer.converter import XMLConverter, HTMLConverter, TextConverter
from pdfminer.cmapdb import CMapDB
from pdfminer.layout import LAParams
from pdfminer.image import ImageWriter
from pdfminer.pdftypes import PSException, PDFException, int_value

# Import classes and helpers from the Laika framework
from laikaboss.util import get_option
from laikaboss.si_module import SI_MODULE
from laikaboss.objectmodel import ModuleObject, ExternalVars
from laikaboss.extras import email_word_list_util

from io import BytesIO
import logging

class EXPLODE_PDF_TEXT(SI_MODULE):
    ''' 
    Extract text from PDF document, based on pdf2text command
    '''

    def __init__(self):
        self.module_name = "EXPLODE_PDF_TEXT"
        # PdfMiner logs can be super noisy, turn them down
        pdflog = logging.getLogger('pdfminer')
        pdflog.setLevel(logging.WARNING)

    def _run(self, scanObject, result, depth, args):
        
        moduleResult = []
        
        outfp = BytesIO()
        fp = BytesIO(scanObject.buffer)

        pdf_text = None
        
        password = get_option(args, 'password', 'pdfpassword', '')
        hardcoded_password_list_path = get_option(args, 'passwordlistpath', 'PasswordListLocation', '/etc/laikaboss/passwords_to_try')

        #potential parameters
        debug = 0
        pagenos = set()
        laparams = LAParams()
        imagewriter = None
        maxpages = 0
        rotation = 0
        stripcontrol = False
        layoutmode = 'normal'
        codec = 'utf-8'
        pageno = 1
        scale = 1
        caching = True
        showpageno = True
        
        PDFDocument.debug = debug
        PDFParser.debug = debug
        CMapDB.debug = debug
        PDFPageInterpreter.debug = debug
        #
        rsrcmgr = PDFResourceManager(caching=caching)
        
        try:
            # See if the pdf is encrypted, and try to guess the password if it is
            correct_password = ''
            try:
                pdf = PDFParser(fp)
                #Construct this separately so we can get encryption info if __init__() fails
                pdfDoc = PDFDocument.__new__(PDFDocument)
                pdfDoc.__init__(pdf)
				# If it's encrypted, but no exception, it had a blank password
                if hasattr(pdfDoc, 'encryption') and pdfDoc.encryption:
                    scanObject.addFlag('pdf:encrypted')
                    scanObject.addFlag('pdf:blank_password')
            except PDFEncryptionError as e:
                encryption_version = int_value(pdfDoc.encryption[1].get('V', 0))
                if encryption_version > 4:
                    password_encoding = 'utf-8'
                else:
                    password_encoding = 'latin1'	
                # Get password candidate list from sibling objects if they exists
                sibling_text = email_word_list_util.get_sibling_text(result, scanObject)
                word_list = email_word_list_util.create_word_list(sibling_text, hardcoded_password_list_path)
                # Prepend password if given
                if password:
                    if isinstance(password, bytes):
                        password = password.decode('utf-8', 'ignore')
                    word_list.insert(0, password)
                # Try all passwords
                for word in word_list:
                    try:
                        # Old versions of pdfminer take password as bytes
                        if pdfminer.__version__ <= '20140328':
                            word = word.encode(password_encoding)
                        pdf = PDFParser(fp)
                        pdfDoc = PDFDocument(pdf, word)
                        # If we get to here, was right password
                        correct_password = word
                        break
                    except (PDFEncryptionError, UnicodeEncodeError) as e:
                        pass
                if not correct_password:
                    raise
            # Try to extract the actual pdf text
            device = TextConverter(rsrcmgr, outfp, codec=codec, laparams=laparams,
                                       imagewriter=imagewriter)
            interpreter = PDFPageInterpreter(rsrcmgr, device)
            for page in PDFPage.get_pages(fp, pagenos,
                                          maxpages=maxpages, password=correct_password,
                                          caching=caching, check_extractable=False):
                page.rotate = (page.rotate+rotation) % 360
                interpreter.process_page(page)
            device.close()
            
            pdf_text = outfp.getvalue()
        
        except PDFPasswordIncorrect as e:
            pass
        except PSException as e:
            scanObject.addFlag('pdf_text:%s' % type(e).__name__)
        except PDFException as e:
            scanObject.addFlag('pdf_text:%s' % type(e).__name__)

        if pdf_text is not None:
            moduleResult.append(ModuleObject(buffer=pdf_text, externalVars=ExternalVars(filename='e_pdf_text', contentType='application/x-laika-pdf-text')))
            scanObject.addMetadata(self.module_name, "text_size", len(pdf_text))

        return moduleResult

