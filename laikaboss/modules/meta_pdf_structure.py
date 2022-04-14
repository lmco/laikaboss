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


import yara
import re

# Import classes and helpers from the Laika framework
from laikaboss.util import get_option
from laikaboss.si_module import SI_MODULE


BOX_DIM_REGEX = b'''\[ ?([0-9\.-]{1,12}) ([0-9\.-]{1,12}) ([0-9\.-]{1,12}) ([0-9\.-]{1,12}) ?\]'''
IMAGE_DIM_REGEX = b'''\/(Width|Height)\s{0,20}?([0-9]{1,20}?)\s{0,20}?\/(Width|Height)\s{0,20}?([0-9]{1,20}?)\W'''


class META_PDF_STRUCTURE(SI_MODULE):
    ''' 
    Extract structural information using by searching for PDF markers (similar to pdfid tool)
    '''

    def __init__(self):
        self.module_name = "META_PDF_STRUCTURE"
        self.rules = None
        self.box_dim_regprog = None
        self.image_dim_regprog = None
        
    def _run(self, scanObject, result, depth, args):
        
        #lazy compile rules, not using yara_on_demand due to signatures in string vs. file
        if not self.rules:
            self.rules = yara.compile(source=pdf_rules_source)
        if not self.box_dim_regprog:
            self.box_dim_regprog = re.compile(BOX_DIM_REGEX)
        if not self.image_dim_regprog:
            self.image_dim_regprog = re.compile(IMAGE_DIM_REGEX)

        box_dims_limit = int(get_option(args, 'boxdimslimit', 'pdfboxdimslimit', 100))
        image_dims_limit = int(get_option(args, 'imagedimslimit', 'pdfimagedimslimit', 100))
        raw_dimensions = int(get_option(args, 'rawdims', 'pdfrawdims', 0))
                
        matches = self.rules.match(data=scanObject.buffer)
        result = {}
        strings = {}
        for match in matches:
            for string in match.strings:
                string_id = string[1][1:]
                if string_id in strings:
                    strings[string_id].append(string[2])
                else:
                    strings[string_id] = [string[2]]
                if string_id in result:
                    result[string_id] = result[string_id] + 1
                else:
                    result[string_id] = 1

        #handle obfuscated structure markers, prevent double counting
        obfuscated = False
        for key in list(result):
            if key[-4:] == "_obs":
                key_base = key[:-4]
                if key_base in result:
                    plain = result[key_base]
                else:
                    plain = 0
                total = result[key]
                obfuscated = total - plain
                result[key_base] = total
                if obfuscated:
                    obfuscated = True
                    scanObject.addFlag("pdf:obfuscated_%s" % (key_base))
                else:
                    del result[key]        
                
        if box_dims_limit and "box_dimensions" in strings:
            if raw_dimensions:
                scanObject.addMetadata(self.module_name, "box_dimensions_raw", strings["box_dimensions"][:box_dims_limit])
            formated_dims = []
            for raw_dim in strings["box_dimensions"][:box_dims_limit]:
                match = self.box_dim_regprog.match(raw_dim)
                if match:
                    formated_dims.append([float(match.group(3)) - float(match.group(1)), float(match.group(4)) - float(match.group(2))])
            scanObject.addMetadata(self.module_name, "box_dimensions", formated_dims)
        
        if image_dims_limit and "image_dimensions" in strings:
            if raw_dimensions:
                scanObject.addMetadata(self.module_name, "image_dimensions_raw", strings["image_dimensions"][:image_dims_limit])
            formated_dims = []
            for raw_dim in strings["image_dimensions"][:image_dims_limit]:
                match = self.image_dim_regprog.match(raw_dim)
                if match:
                    if match.group(1) == "Width":
                        formated_dims.append([float(match.group(2)), float(match.group(4))])
                    else:
                        formated_dims.append([float(match.group(4)), float(match.group(2))])
            scanObject.addMetadata(self.module_name, "image_dimensions", formated_dims)
        
        scanObject.addMetadata(self.module_name, "markers", result)

        return []


pdf_rules_source = '''

rule pdf_fonts
{
    strings:
        $courier = /\/Courier\W/
        $times = /\/Times\W/
        $symbol = /\/Symbol\W/
        $helvetica = /\/Helvetica\W/
        $dingbats = /\/ZapfDingbats\W/
    condition:
        any of them
}

rule pdf_filters
{
    strings:
        $asciihex = /\/ASCIIHexDecode\W/
        $ahx = /\/AHx\W/
        $ascii85 = /\/ASCII85Decode\W/
        $a85 = /\/A85\W/
        $lzwd = /\/LZWDecode\W/
        $lzw = /\/LZW\W/
        $flate = /\/FlateDecode\W/
        $fl = /\/Fl\W/
        $runlength = /\/RunLengthDecode\W/
        $rl = /\/RL\W/
        $ccittfax = /\/CCITTFaxDecode\W/
        $ccf = /\/CCF\W/
        $dctd = /\/DCTDecode\W/
        $jpx = /\/JPXDecode\W/
        $jbig2 = /\/JBIG2Decode\W/
    condition:
        any of them
}

rule pdf_structure
{
    strings:
        $obj = /\bobj\W/
        $endobj = /\bendobj\W/
        $stream = /\bstream\W/
        $endstream = /\bendstream\W/
        $xref = /\bxref\W/
        $trailer = /\btrailer\W/
        $startxref = /\bstartxref\W/
        $eof = /%EOF\W/
        $page = /\/Page\W/
        $encrypt = /\/Encrypt\W/
        $objstm = /\/ObjStm\W/
        $js = /\/JS\W/
        $javascript = /\/JavaScript\W/
        $aa = /\/AA\W/
        $openaction = /\/OpenAction\W/
        $acroform = /\/AcroForm\W/
        $jbig2decode = /\/JBIG2Decode\W/
        $richmedia = /\/RichMedia\W/
        $launch = /\/Launch\W/
        $embeddedfile = /\/EmbeddedFile\W/
        $xfa = /\/XFA\W/
        $annot = /\/Annot\W/
        $link = /\/Link\W/
        $group = /\/Group\W/
        $border = /\/Border\W/
        $structelem = /\/StructElem\W/
        $uri = /\/URI\W/
        $url = /\/URL\W/
        $rect = /\/Rect\W/
        $span = /\/Span\W/
        $lang = /\/Lang\W/
        $xobject = /\/XObject\W/
        $parent = /\/Parent\W/
        $filter = /\/Filter\W/
        $procset = /\/ProcSet\W/
        $contents = /\/Contents\W/
        $resources = /\/Resources\W/
        $pdf = /\/PDF\W/
        $mediabox = /\/MediaBox\W/
        $text = /\/Text\W/
        $devicergb = /\/DeviceRGB\W/
        $fontname = /\/FontName\W/
        $fontbbox = /\/FontBBox\W/
        $figure = /\/Figure\W/
        $transparency = /\/Transparency\W/
        $textbox = /\/Textbox\W/
        $image = /\/Image\W/
        $differences = /\/Differences\W/
        $bbox = /\/BBox\W/
        $cfm = /\/CFM\W/
        $docopen = /\/DocOpen\W/
        $authevent = /\/AuthEvent\W/
        $webcapture = /\/WebCapture\W/
        $viewstate = /\/ViewState\W/
        $viewarea = /\/ViewArea\W/
        $underlineposition = /\/UnderlinePosition\W/
        $trustedmode = /\/TrustedMode\W/
        $subfilter = /\/SubFilter\W/
        $startpage = /\/StartPage\W/
        $screen = /\/Screen\W/
        $printarea = /\/PrintArea\W/
        $products = /\/Products\W/
        $printstate = /\/PrintState\W/
        $panose = /\/Panose\W/
        $numblock = /\/NumBlock\W/
        $layer = /\/Layer\W/
        $journalpolicy = /\/JournalPolicy\W/
        $home = /\/Home\W/
        $fullname = /\/FullName\W/
        $dothumbnails = /\/DoThumbnails\W/
        $default = /\/Default\W/
        $description = /\/Description\W/
        $color = /\/Color\W/
        $createjdffile = /\/CreateJDFFile\W/
        $bitspersample = /\/BitsPerSample\W/
        $font = /\/Font\W/
        $colors = /\/Colors\W/
    condition:
        any of them
}

rule pdf_structure_obs
{
    strings:
        $js_obs = /\/(J|#4A)(S|#53)\W/
        $page_obs = /\/(P|#50)(a|#61)(g|#67)(e|#65)\W/
        $encrypt_obs = /\/(E|#45)(n|#6e)(c|#63)(r|#72)(y|#79)(p|#70)(t|#74)\W/
        $objstm_obs = /\/(O|#4f)(b|#62)(j|#6a)(S|#53)(t|#74)(m|#6d)\W/
        $javascript_obs = /\/(J|#4a)(a|#61)(v|#76)(a|#61)(S|#53)(c|#63)(r|#72)(i|#69)(p|#70)(t|#74)\W/
        $aa_obs = /\/(A|#41)(A|#41)\W/
        $openaction_obs = /\/(O|#4f)(p|#70)(e|#65)(n|#6e)(A|#41)(c|#63)(t|#74)(i|#69)(o|#6f)(n|#6e)\W/
        $acroform_obs = /\/(A|#41)(c|#63)(r|#72)(o|#6f)(F|#46)(o|#6f)(r|#72)(m|#6d)\W/
        $richmedia_obs = /\/(R|#52)(i|#69)(c|#63)(h|#68)(M|#4d)(e|#65)(d|#64)(i|#69)(a|#61)\W/
        $launch_obs = /\/(L|#4c)(a|#61)(u|#75)(n|#6e)(c|#63)(h|#68)\W/
        $font_obs = /\/(F|#46)(o|#6f)(n|#6e)(t|#74)\W/
    condition:
        any of them
}


rule image_dimensions
{
/*
$a = /\/(Width|Height)\s{0,20}?([0-9]{1,20}?)\s{0,20}?\/(Width|Height)\s{0,20}?([0-9]{1,20}?)\W/
*/
    strings:
        $image_dimensions = /\/(Width|Height)\s{0,20}?([0-9]{1,20}?)\s{0,20}?\/(Width|Height)\s{0,20}?([0-9]{1,20}?)\W/
/*
        $image_dimensions_wh = /\/Height\s{0,20}?([0-9]{1,20}?)\s{0,20}?\/Width\s{0,20}?([0-9]{1,20}?)\W/
        $image_dimensions_hw = /\/Width\s{0,20}?([0-9]{1,20}?)\s{0,20}?\/Height\s{0,20}?([0-9]{1,20}?)\W/
*/
    condition:
        any of them
}


rule pdf_box
{
    strings:
        $box_dimensions = /\[ ?([0-9\.-]{1,12}) ([0-9\.-]{1,12}) ([0-9\.-]{1,12}) ([0-9\.-]{1,12}) ?\]/
    condition:
        any of them
}

'''        
        
