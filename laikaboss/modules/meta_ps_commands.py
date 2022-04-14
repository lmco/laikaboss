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


class META_PS_COMMANDS(SI_MODULE):
    ''' 
    Extract structural information using by searching for PS commands
    '''

    def __init__(self):
        self.module_name = "META_PS_COMMANDS"
        self.rules = None
        
    def _run(self, scanObject, result, depth, args):
        
        #lazy compile rules, not using yara_on_demand due to signatures in string vs. file
        if not self.rules:
            self.rules = yara.compile(source=ps_rules_source)
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

        
        scanObject.addMetadata(self.module_name, "commands", result)

        return []


ps_rules_source = '''

rule ps_commands
{
    strings:
        $abs = "abs" fullword
        $add = "add" fullword
        $aload = "aload" fullword
        $anchorsearch = "anchorsearch" fullword
        $and = "and" fullword
        $arc = "arc" fullword
        $arcn = "arcn" fullword
        $arct = "arct" fullword
        $arcto = "arcto" fullword
        $array = "array" fullword
        $ashow = "ashow" fullword
        $astore = "astore" fullword
        $atan = "atan" fullword
        $awidthshow = "awidthshow" fullword
        $begin = "begin" fullword
        $bind = "bind" fullword
        $bitshift = "bitshift" fullword
        $bytesavailable = "bytesavailable" fullword
        $cachestatus = "cachestatus" fullword
        $ceiling = "ceiling" fullword
        $charpath = "charpath" fullword
        $clear = "clear" fullword
        $cleartomark = "cleartomark" fullword
        $cleardictstack = "cleardictstack" fullword
        $clip = "clip" fullword
        $clippath = "clippath" fullword
        $closefile = "closefile" fullword
        $closepath = "closepath" fullword
        $colorimage = "colorimage" fullword
        $concat = "concat" fullword
        $concatmatrix = "concatmatrix" fullword
        $condition = "condition" fullword
        $configurationerror = "configurationerror" fullword
        $copy = "copy" fullword
        $copypage = "copypage" fullword
        $cos = "cos" fullword
        $count = "count" fullword
        $countdictstack = "countdictstack" fullword
        $countexecstack = "countexecstack" fullword
        $counttomark = "counttomark" fullword
        $cshow = "cshow" fullword
        $currentblackgeneration = "currentblackgeneration" fullword
        $currentcacheparams = "currentcacheparams" fullword
        $currentcmykcolor = "currentcmykcolor" fullword
        $currentcolor = "currentcolor" fullword
        $currentcolorrendering = "currentcolorrendering" fullword
        $currentcolorscreen = "currentcolorscreen" fullword
        $currentcolorspace = "currentcolorspace" fullword
        $currentcolortransfer = "currentcolortransfer" fullword
        $currentcontext = "currentcontext" fullword
        $currentdash = "currentdash" fullword
        $currentdevparams = "currentdevparams" fullword
        $currentdict = "currentdict" fullword
        $currentfile = "currentfile" fullword
        $currentflat = "currentflat" fullword
        $currentfont = "currentfont" fullword
        $currentglobal = "currentglobal" fullword
        $currentgray = "currentgray" fullword
        $currentgstate = "currentgstate" fullword
        $currenthalftone = "currenthalftone" fullword
        $currenthalftonephase = "currenthalftonephase" fullword
        $currenthsbcolor = "currenthsbcolor" fullword
        $currentlinecap = "currentlinecap" fullword
        $currentlinejoin = "currentlinejoin" fullword
        $currentlinewidth = "currentlinewidth" fullword
        $currentmatrix = "currentmatrix" fullword
        $currentmiterlimit = "currentmiterlimit" fullword
        $currentobjectformat = "currentobjectformat" fullword
        $currentpacking = "currentpacking" fullword
        $currentpagedevice = "currentpagedevice" fullword
        $currentpoint = "currentpoint" fullword
        $currentrgbcolor = "currentrgbcolor" fullword
        $currentscreen = "currentscreen" fullword
        $currentshared = "currentshared" fullword
        $currentstrokeadjust = "currentstrokeadjust" fullword
        $currentsystemparams = "currentsystemparams" fullword
        $currenttransfer = "currenttransfer" fullword
        $currentundercolorremoval = "currentundercolorremoval" fullword
        $currentuserparams = "currentuserparams" fullword
        $curveto = "curveto" fullword
        $cvi = "cvi" fullword
        $cvlit = "cvlit" fullword
        $cvn = "cvn" fullword
        $cvr = "cvr" fullword
        $cvrs = "cvrs" fullword
        $cvs = "cvs" fullword
        $cvx = "cvx" fullword
        $def = "def" fullword
        $defaultmatrix = "defaultmatrix" fullword
        $definefont = "definefont" fullword
        $defineresource = "defineresource" fullword
        $defineusername = "defineusername" fullword
        $defineuserobject = "defineuserobject" fullword
        $deletefile = "deletefile" fullword
        $detach = "detach" fullword
        $deviceinfo = "deviceinfo" fullword
        $dict = "dict" fullword
        $dictfull = "dictfull" fullword
        $dictstack = "dictstack" fullword
        $dictstackoverflow = "dictstackoverflow" fullword
        $dictstackunderflow = "dictstackunderflow" fullword
        $div = "div" fullword
        $dtransform = "dtransform" fullword
        $dup = "dup" fullword
        $echo = "echo" fullword
        $eexec = "eexec" fullword
        $end = "end" fullword
        $eoclip = "eoclip" fullword
        $eofill = "eofill" fullword
        $eoviewclip = "eoviewclip" fullword
        $eq = "eq" fullword
        $erasepage = "erasepage" fullword
        $errordict = "errordict" fullword
        $exch = "exch" fullword
        $exec = "exec" fullword
        $execform = "execform" fullword
        $execstack = "execstack" fullword
        $execstackoverflow = "execstackoverflow" fullword
        $execuserobject = "execuserobject" fullword
        $executeonly = "executeonly" fullword
        $executive = "executive" fullword
        $exit = "exit" fullword
        $exp = "exp" fullword
        $false = "false" fullword
        $file = "file" fullword
        $filenameforall = "filenameforall" fullword
        $fileposition = "fileposition" fullword
        $fill = "fill" fullword
        $filter = "filter" fullword
        $findencoding = "findencoding" fullword
        $findfont = "findfont" fullword
        $findresource = "findresource" fullword
        $flattenpath = "flattenpath" fullword
        $floor = "floor" fullword
        $flush = "flush" fullword
        $flushfile = "flushfile" fullword
        $FontDirectory = "FontDirectory" fullword
        $for = "for" fullword
        $forall = "forall" fullword
        $fork = "fork" fullword
        $ge = "ge" fullword
        $get = "get" fullword
        $getinterval = "getinterval" fullword
        $globaldict = "globaldict" fullword
        $GlobalFontDirectory = "GlobalFontDirectory" fullword
        $glyphshow = "glyphshow" fullword
        $grestore = "grestore" fullword
        $grestoreall = "grestoreall" fullword
        $gsave = "gsave" fullword
        $gstate = "gstate" fullword
        $gt = "gt" fullword
        $handleerror = "handleerror" fullword
        $identmatrix = "identmatrix" fullword
        $idiv = "idiv" fullword
        $idtransform = "idtransform" fullword
        $if = "if" fullword
        $ifelse = "ifelse" fullword
        $image = "image" fullword
        $imagemask = "imagemask" fullword
        $index = "index" fullword
        $ineofill = "ineofill" fullword
        $infill = "infill" fullword
        $initclip = "initclip" fullword
        $initgraphics = "initgraphics" fullword
        $initmatrix = "initmatrix" fullword
        $initviewclip = "initviewclip" fullword
        $instroke = "instroke" fullword
        $internaldict = "internaldict" fullword
        $interrupt = "interrupt" fullword
        $inueofill = "inueofill" fullword
        $inufill = "inufill" fullword
        $inustroke = "inustroke" fullword
        $invalidaccess = "invalidaccess" fullword
        $invalidcontext = "invalidcontext" fullword
        $invalidexit = "invalidexit" fullword
        $invalidfileaccess = "invalidfileaccess" fullword
        $invalidfont = "invalidfont" fullword
        $invalidid = "invalidid" fullword
        $invalidrestore = "invalidrestore" fullword
        $invertmatrix = "invertmatrix" fullword
        $ioerror = "ioerror" fullword
        $ISOLatin1Encoding = "ISOLatin1Encoding" fullword
        $itransform = "itransform" fullword
        $join = "join" fullword
        $kshow = "kshow" fullword
        $known = "known" fullword
        $languagelevel = "languagelevel" fullword
        $le = "le" fullword
        $length = "length" fullword
        $limitcheck = "limitcheck" fullword
        $lineto = "lineto" fullword
        $ln = "ln" fullword
        $load = "load" fullword
        $lock = "lock" fullword
        $log = "log" fullword
        $loop = "loop" fullword
        $lt = "lt" fullword
        $makefont = "makefont" fullword
        $makepattern = "makepattern" fullword
        $mark = "mark" fullword
        $matrix = "matrix" fullword
        $maxlength = "maxlength" fullword
        $mod = "mod" fullword
        $monitor = "monitor" fullword
        $moveto = "moveto" fullword
        $mul = "mul" fullword
        $ne = "ne" fullword
        $neg = "neg" fullword
        $newpath = "newpath" fullword
        $noaccess = "noaccess" fullword
        $nocurrentpoint = "nocurrentpoint" fullword
        $not = "not" fullword
        $notify = "notify" fullword
        $null = "null" fullword
        $nulldevice = "nulldevice" fullword
        $or = "or" fullword
        $packedarray = "packedarray" fullword
        $pathbbox = "pathbbox" fullword
        $pathforall = "pathforall" fullword
        $pop = "pop" fullword
        $print = "print" fullword
        $printobject = "printobject" fullword
        $product = "product" fullword
        $prompt = "prompt" fullword
        $pstack = "pstack" fullword
        $put = "put" fullword
        $putinterval = "putinterval" fullword
        $quit = "quit" fullword
        $rand = "rand" fullword
        $rangecheck = "rangecheck" fullword
        $rcurveto = "rcurveto" fullword
        $read = "read" fullword
        $readhexstring = "readhexstring" fullword
        $readline = "readline" fullword
        $readonly = "readonly" fullword
        $readstring = "readstring" fullword
        $realtime = "realtime" fullword
        $rectclip = "rectclip" fullword
        $rectfill = "rectfill" fullword
        $rectstroke = "rectstroke" fullword
        $rectviewclip = "rectviewclip" fullword
        $renamefile = "renamefile" fullword
        $repeat = "repeat" fullword
        $resetfile = "resetfile" fullword
        $resourceforall = "resourceforall" fullword
        $resourcestatus = "resourcestatus" fullword
        $restore = "restore" fullword
        $reversepath = "reversepath" fullword
        $revision = "revision" fullword
        $rlineto = "rlineto" fullword
        $rmoveto = "rmoveto" fullword
        $roll = "roll" fullword
        $rootfont = "rootfont" fullword
        $rotate = "rotate" fullword
        $round = "round" fullword
        $rrand = "rrand" fullword
        $run = "run" fullword
        $save = "save" fullword
        $scale = "scale" fullword
        $scalefont = "scalefont" fullword
        $scheck = "scheck" fullword
        $search = "search" fullword
        $selectfont = "selectfont" fullword
        $serialnumber = "serialnumber" fullword
        $setbbox = "setbbox" fullword
        $setblackgeneration = "setblackgeneration" fullword
        $setcachedevice = "setcachedevice" fullword
        $setcachedevice2 = "setcachedevice2" fullword
        $setcachelimit = "setcachelimit" fullword
        $setcacheparams = "setcacheparams" fullword
        $setcharwidth = "setcharwidth" fullword
        $setcmykcolor = "setcmykcolor" fullword
        $setcolor = "setcolor" fullword
        $setcolorrendering = "setcolorrendering" fullword
        $setcolorscreen = "setcolorscreen" fullword
        $setcolorspace = "setcolorspace" fullword
        $setcolortransfer = "setcolortransfer" fullword
        $setdash = "setdash" fullword
        $setdevparams = "setdevparams" fullword
        $setfileposition = "setfileposition" fullword
        $setflat = "setflat" fullword
        $setfont = "setfont" fullword
        $setglobal = "setglobal" fullword
        $setgray = "setgray" fullword
        $setgstate = "setgstate" fullword
        $sethalftone = "sethalftone" fullword
        $sethalftonephase = "sethalftonephase" fullword
        $sethsbcolor = "sethsbcolor" fullword
        $setlinecap = "setlinecap" fullword
        $setlinejoin = "setlinejoin" fullword
        $setlinewidth = "setlinewidth" fullword
        $setmatrix = "setmatrix" fullword
        $setmiterlimit = "setmiterlimit" fullword
        $setobjectformat = "setobjectformat" fullword
        $setoverprint = "setoverprint" fullword
        $setpacking = "setpacking" fullword
        $setpagedevice = "setpagedevice" fullword
        $setpattern = "setpattern" fullword
        $setrgbcolor = "setrgbcolor" fullword
        $setscreen = "setscreen" fullword
        $setshared = "setshared" fullword
        $setstrokeadjust = "setstrokeadjust" fullword
        $setsystemparams = "setsystemparams" fullword
        $settransfer = "settransfer" fullword
        $setucacheparams = "setucacheparams" fullword
        $setundercolorremoval = "setundercolorremoval" fullword
        $setuserparams = "setuserparams" fullword
        $setvmthreshold = "setvmthreshold" fullword
        $shareddict = "shareddict" fullword
        $show = "show" fullword
        $showpage = "showpage" fullword
        $sin = "sin" fullword
        $sqrt = "sqrt" fullword
        $srand = "srand" fullword
        $stack = "stack" fullword
        $stackoverflow = "stackoverflow" fullword
        $stackunderflow = "stackunderflow" fullword
        $StandardEncoding = "StandardEncoding" fullword
        $start = "start" fullword
        $startjob = "startjob" fullword
        $status = "status" fullword
        $statusdict = "statusdict" fullword
        $stop = "stop" fullword
        $stopped = "stopped" fullword
        $store = "store" fullword
        $string = "string" fullword
        $stringwidth = "stringwidth" fullword
        $stroke = "stroke" fullword
        $strokepath = "strokepath" fullword
        $sub = "sub" fullword
        $syntaxerror = "syntaxerror" fullword
        $systemdict = "systemdict" fullword
        $timeout = "timeout" fullword
        $transform = "transform" fullword
        $translate = "translate" fullword
        $true = "true" fullword
        $truncate = "truncate" fullword
        $type = "type" fullword
        $typecheck = "typecheck" fullword
        $token = "token" fullword
        $uappend = "uappend" fullword
        $ucache = "ucache" fullword
        $ucachestatus = "ucachestatus" fullword
        $ueofill = "ueofill" fullword
        $ufill = "ufill" fullword
        $undef = "undef" fullword
        $undefined = "undefined" fullword
        $undefinedfilename = "undefinedfilename" fullword
        $undefineresource = "undefineresource" fullword
        $undefinedresult = "undefinedresult" fullword
        $undefinefont = "undefinefont" fullword
        $undefinedresource = "undefinedresource" fullword
        $undefineuserobject = "undefineuserobject" fullword
        $unmatchedmark = "unmatchedmark" fullword
        $unregistered = "unregistered" fullword
        $upath = "upath" fullword
        $userdict = "userdict" fullword
        $UserObjects = "UserObjects" fullword
        $usertime = "usertime" fullword
        $ustroke = "ustroke" fullword
        $ustrokepath = "ustrokepath" fullword
        $version = "version" fullword
        $viewclip = "viewclip" fullword
        $viewclippath = "viewclippath" fullword
        $VMerror = "VMerror" fullword
        $vmreclaim = "vmreclaim" fullword
        $vmstatus = "vmstatus" fullword
        $wait = "wait" fullword
        $wcheck = "wcheck" fullword
        $where = "where" fullword
        $widthshow = "widthshow" fullword
        $write = "write" fullword
        $writehexstring = "writehexstring" fullword
        $writeobject = "writeobject" fullword
        $writestring = "writestring" fullword
        $wtranslation = "wtranslation" fullword
        $xcheck = "xcheck" fullword
        $xor = "xor" fullword
        $xshow = "xshow" fullword
        $xyshow = "xyshow" fullword
        $yield = "yield" fullword
        $yshow = "yshow" fullword
    condition:
        any of them
}


'''        
        
