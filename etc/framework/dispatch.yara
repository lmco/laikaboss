/*

Laika Dispatcher : 1st pass

*Overview
    * This first pass dispatcher operates on the full buffer of the object. The 
      dispatcher can be configured to run modules based on the contents of the 
      object as well as the external variables provided to you.
* META fields
    * scan_modules : A space separated list of modules to run on the given object.
                     Some modules take comma seperated arguments, for example:
                     SCAN_MODULE(key1=value1,key2=value2).
    * flags        : Appends a flag to the current object if the rule is true.
    * parent_flags : Appends a flag to the parent of the current object if the 
                     rule is true.
    * priority     : This optional field can be used to control the order in which 
                     your modules will be executed. Within a single rule, modules will 
                     run in the order they are listed. If multiple rules match, modules 
                     will be run in order of their rule's priority. The default priority 
                     is 9, with 1 being the highest priority.
* External Variables
    * ext_parentModules (str) : a space separated list of the modules that have been 
      run on the parent of the current object (default: NONE)
    * ext_sourceModule (str)  : the module that produced this object or NONE if it's 
      the root object (default: NONE)
    * ext_contentType (str)   : content type set by client or a module (default: NONE)
    * ext_filename (str)      : filename set by client or a module (default: NONE)
    * ext_timestamp (str)     : timestamp set by client or a module (default: NONE)
    * ext_source (str)        : source set by client or a module (default: NONE) 
    * ext_flags (str)         : flags set by client or a module (default: NONE) 
    * ext_size (int)          : the length of the buffer (default: 0)
    * ext_depth (int)         : the depth of the current object (root == 0)

*/

/*-----------------------Private Rule Grouping-----------------------------*/

private rule root_object
{
    condition:
        ext_sourceModule contains "NONE" 
}

/*_________________________________________________________________________*/

/*---------------------------General Rules---------------------------------*/

rule scan_yara
{
    meta:
        scan_modules = "SCAN_YARA"
    condition:
        true
}

rule meta_hash 
{
    meta:
        scan_modules = "META_HASH"
    condition:
        true
}

/*_________________________________________________________________________*/

/*-------------------------Certificate Grouping----------------------------*/
rule type_is_X509_pem
{
    meta:
        file_type = "pem"
    strings:
        $pem = "-----BEGIN CERTI"
    condition:
        $pem at 0
}

rule type_is_X509_der
{
    meta:
        file_type = "der"
    condition:
        uint16(0) == 0x8230 and uint16(4) == 0x8230
}

rule type_is_X509
{
    meta:
        scan_modules = "META_X509"
        file_type = "crt"
    condition:
        type_is_X509_pem or type_is_X509_der
}

rule type_is_PKCS7
{
    meta:
        scan_modules = "EXPLODE_PKCS7"
        file_type = "pkcs7"
    strings:
        $pem = "-----BEGIN PKCS7-----"
    condition:
        (uint16(0) == 0x8230 and uint16(4) == 0x0906) or
        uint32(0) == 0x09068030 or 
        $pem at 0
        
}

/*_________________________________________________________________________*/

/*-------------------------PE File Grouping--------------------------------*/
rule type_is_mz
{
    meta:
        scan_modules = "META_PE"
        file_type = "pe"
    condition:
        uint16(0) == 0x5a4d
        and not ext_sourceModule contains "META_PE"
}
/*_________________________________________________________________________*/

/*---------------------------Archive Grouping--------------------------------*/
rule type_is_zip
{
    meta:
        scan_modules = "EXPLODE_ZIP(filelimit=1000)"
        file_type = "zip"
    condition:
        uint32(0) == 0x04034b50 and not uint32(4) == 0x00060014
}

rule type_is_rar
{
    meta:
        scan_modules = "EXPLODE_RAR(filelimit=1000)"
        file_type = "rar"
    strings:
        $a = { 52 61 72 21 1A 07 00 }
    condition:
        $a at 0
}

rule type_is_cab
{
    meta:
        file_type = "cab"
    strings:
        $mscf = { 4D 53 43 46 00 00 00 00 }
    condition:
        $mscf at 0 or (type_is_mz and $mscf)
}

rule type_is_tar
{
    meta:
        file_type = "tar"
    strings:
        $c = { 75 73 74 61 72 }
    condition:
        uint16(0) == 0x9d1f or
        uint16(0) == 0xa01f or
        $c at 257
}

rule type_is_arj
{
    meta:
        file_type = "arj"
    condition:
        uint16(0) == 0xea60
}

/*_________________________________________________________________________*/

/*-----------------------Document File Grouping----------------------------*/
rule type_is_msoffice2003
{
    meta:
        scan_modules = "EXPLODE_OLE(minFileSize=128)"
        file_type = "ole"
    strings:
        $a = { D0 CF 11 E0 A1 B1 1A E1 }
    condition:
        $a at 0
}

rule type_is_msoffice2007
{
    meta:
        scan_modules = "EXPLODE_ZIP"
        file_type = "officex"
    strings:
        $a = { 50 4B 03 04 14 00 06 00 }
    condition:
        $a at 0
}

rule type_is_rtf
{
    meta:
        file_type = "rtf"
    condition:
        uint32(0) == 0x74725c7b
}

rule type_is_pdf
{
    meta:
        file_type = "pdf"
    strings:
        $pdf1 = { 25 50 44 46 2d ?? 2e } // %PDF-.(dot)
        $pdf2 = { 25 50 44 46 2d }
    condition:

        ($pdf1 in (0 .. 1024) or $pdf2 at 0) and not (type_is_zip or 
                                                      type_is_msoffice2007 or 
                                                      type_is_tar or 
                                                      type_is_rar)
}

rule type_is_chm
{
    meta:
        file_type = "chm"
    condition:
        uint32(0) == 0x46535449
}

rule type_is_hlp
{
    meta:
        file_type = "hlp"
    condition:
        uint32(6) == 0xFFFF0000 and uint16(10) == 0xFFFF
}

rule type_is_wri
{
    meta:
        file_type = "wri"
    condition:
        uint32(0) == 0x0000be31 or uint32(0) == 0x0000be32
}

rule type_is_lnk
{
    meta:
        file_type = "lnk"
    strings:
        $a = { 4C 00 00 00 01 14 02 00 }
    condition:
        $a at 0
}

/*_________________________________________________________________________*/

/*----------------------------Java Grouping--------------------------------*/

rule type_is_java_class
{
    meta:
        scan_modules = "META_JAVA_CLASS"
        file_type = "class"
    condition:
        uint32(0) == 0xbebafeca
}

rule type_is_metainf_manifest
{
    meta:
        scan_modules = "META_JAVA_MANIFEST"
    strings:
        $a = { 4d 61 6e 69 66 65 73 74 }
    condition:
        $a at 0 and ext_parentModules contains "EXPLODE_ZIP"
}

rule jar_check
{
    meta:
        parent_flags = "misc_jar_file"
    condition:
        type_is_java_class and ext_sourceModule contains "EXPLODE_ZIP"
}

/*_________________________________________________________________________*/

/*---------------------------Email Grouping--------------------------------*/
rule type_is_email
{
    meta:
        scan_modules = "META_EMAIL EXPLODE_EMAIL"
        file_type = "eml"
    strings:
        $from = "From "
        $received = "\x0aReceived:"
        $return = "\x0aReturn-Path:"
    condition:
        (not ext_sourceModule contains "EXPLODE_EMAIL") and
        (($from at 0) or 
         ($received in (0 .. 2048)) or 
         ($return   in (0 .. 2048)))
}

rule type_is_mime
{
    meta:
        scan_modules = "EXPLODE_EMAIL"
        file_type = "mime"
    strings:
           $mime = "MIME-Version:"
    condition:
        not type_is_email and
        not ext_sourceModule contains "EXPLODE_EMAIL" and 
        $mime in (0 .. 2048)
}

rule type_is_attachment
{
    //meta:
    //    scan_modules = ""
    condition:
        ext_sourceModule contains "EXPLODE_EMAIL"
}

rule type_is_tnef
{
    meta:
        file_type = "tnef"
    condition:
        uint32(0) == 0x223e9f78
}

/*--------------------------Decode Grouping--------------------------------*/
rule type_is_base64
{
    meta:
        scan_modules = "DECODE_BASE64"
    condition:
        ext_contentType contains "base64"
}

/*_________________________________________________________________________*/

/*----------------------------SWF Grouping---------------------------------*/
rule type_is_SWF_FWS
{
    meta:
        file_type = "fws"
    condition:
        uint16(0) == 0x5746 and uint8(2) == 0x53
}

rule type_is_SWF_CWS
{
    meta:
        scan_modules = "EXPLODE_SWF"
        file_type = "cws"
    condition:
        uint16(0) == 0x5743 and uint8(2) == 0x53
}

rule type_is_SWF_ZWS
{
    meta:
        scan_modules = "EXPLODE_SWF"
        file_type = "zws"
    condition:
        uint16(0) == 0x575a and uint8(2) == 0x53
}

rule type_is_SWF
{
    meta:
        file_type = "swf"
    condition:
        type_is_SWF_CWS or type_is_SWF_FWS or type_is_SWF_ZWS
}

/*_________________________________________________________________________*/

/*-----------------------Media File Grouping-------------------------------*/
rule type_is_tiff
{
    meta:
        file_type = "tiff"
    condition:
        uint32(0) == 0x002a4949 or uint32(0) == 0x2a004d4d
}

rule type_is_mp3
{
    meta:
        file_type = "mp3"
    condition:
        uint16(0) == 0x4449 and uint8(2) == 0x33
}

rule type_is_wmv
{
    meta:
        file_type = "wmv"
    strings:
        $a = { 30 26 B2 75 8E 66 CF 11 A6 D9 00 AA 00 62 CE 6C }
    condition:
        $a at 0
}

rule type_is_avi
{
    meta:
        file_type = "avi"
    strings:
        $a = { 52 49 46 46 ?? ?? ?? ?? 41 56 49 20 4C 49 53 54 }
    condition:
        $a at 0
}

rule type_is_mov
{
    meta:
        file_type = "mov"
    condition:
        uint32(4) == 0x766f6f6d or // moov
        uint32(4) == 0x7461646d or // mdat
        uint32(4) == 0x65646977 or // wide
        uint32(4) == 0x70696b73 or // skip
        uint32(4) == 0x65657266 or // free
        uint32(4) == 0x63736469 or // idsc
        uint32(4) == 0x74616469 or // idat
        uint32(4) == 0x676b6370 or // pckg
        uint32(4) == 0x70797466 or // ftyp
        uint16(4) == 0x506a        // jP
}

/*_________________________________________________________________________*/

/*-------------------Dispatcher Flag Grouping------------------------------*/
rule exe_in_zip
{
    meta:
        flags = "misc_exe_in_zip"
    condition:
        ext_sourceModule contains "EXPLODE_ZIP" and
        type_is_mz 
}

/*_________________________________________________________________________*/

/*-----------------------EXIFTOOL Grouping---------------------------------*/
rule META_EXIFTOOL
{
    meta:
        scan_modules = "META_EXIFTOOL"
    condition:
        type_is_lnk or
        type_is_tiff or
        type_is_msoffice2003 or
        type_is_msoffice2007 or
        type_is_pdf or
        type_is_SWF_FWS or
        type_is_mz or
        type_is_mov or
        type_is_avi or
        type_is_wmv or
        type_is_mp3
}
/*_________________________________________________________________________*/
