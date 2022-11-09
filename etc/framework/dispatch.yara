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
    * ext_scanTime (int)      : timestamp of begining of processing of current object
    * ext_parent_scanTime(int): timestamp of begining of processing of parent object
    * ext_root_scanTime (int) : timestamp of begining of processing of root object
    * ext_time (int)          : current timestamp, similar to time.now() of yara 3.7+
    * ext_depth (int)         : depth of the current object + 1 (root == 1)
    * ext_cluster (str)       : name of the cluster for use in dispatching rules
    * ext_args (str)          : args passed to this laikaboss job, flattened into a
      string and demarcated by '|' characters
*/

/*-----------------------Global Rule Grouping------------------------------*/
//global rules used to disable all other rules


private global rule not_timeout_root
{
    condition:
        not ((ext_time - ext_root_scanTime) > 900)
}

private global rule not_timeout_subtree
{
    condition:
        not (ext_depth > 2 and (ext_time - ext_parent_scanTime) > 700 or
             ext_depth > 3 and (ext_time - ext_parent_scanTime) > 500)
}

/*_________________________________________________________________________*/
/*-----------------------Private Rule Grouping-----------------------------*/

private rule root_object
{
    condition:
        ext_sourceModule contains "NONE" 
}

/*_________________________________________________________________________*/
/*---------------------------General Rules---------------------------------*/

rule scaninfo_start
{
    meta:
        scan_modules = "META_SCANINFO(logfile=/var/log/laikaboss/metrics.log,summary_logfile=/var/log/laikaboss/summary_metrics.log)"
        priority = "1"
    condition:
        root_object and not ext_source contains "CLI" 
}

rule scaninfo_start_cli
{
    meta:
        scan_modules = "META_SCANINFO"
        priority = "1"
    condition:
        root_object and not scaninfo_start
}

rule scan_yara
{
    meta:
        scan_modules = "SCAN_YARA"
    condition:
        true
}

rule send_to_storage_buffer_s3
{
    meta:
         scan_modules = "SUBMIT_STORAGE_S3(type=buffer,bucket=email)"
         priority = "7"
    condition:
         root_object and ((not ext_source contains "CLI" and not ext_source contains "webUI") or
           (ext_args contains "|submit_to_storage=True|"))
}

rule meta_hash 
{
    meta:
        scan_modules = "META_HASH"
    condition:
        true
}

rule type_is_vcard
{
	meta:
		file_type = "vcf"
    condition:
        uint32(0) == 0x49474542 and uint32(4) == 0x43563a4e and uint32(8) == 0x0d445241
}

rule type_is_vcard_unix
{
//exiftool does not parse vcfs with unix newlines, convert to windows
    meta:
        scan_modules = "EXPLODE_RE_SUB(name=unix2dos,pattern_hex=283f3c215c783064295c783061,replacement_hex=5c725c6e)"
        file_type = "vcf_unix"
    condition:
        uint32(0) == 0x49474542 and uint32(4) == 0x43563a4e and uint32(8) == 0x0a445241
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
        uint16(0) == 0x8230 and uint8(4) == 0x30 and (uint8(5) == 0x82 or uint8(5) == 0x81)
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

/*-------------------------EXE File Grouping--------------------------------*/
rule type_is_mz
{
    meta:
        file_type = "pe"
    condition:
        uint16(0) == 0x5a4d
}

rule type_is_mz_top
{
//only run some modules on topmost PE layer
    meta:
        scan_modules = "META_PE"
    condition:
        type_is_mz and not ext_sourceModule contains "META_PE"
}

rule type_is_dotnet
{
    meta:
        scan_modules = "META_DOTNET"
        file_type = "dotnet"
    strings:
        $lib = "mscoree.dll"
        $func = "_CorExeMain"
    condition:
        type_is_mz and $lib and $func
}



rule type_is_elf
{
    meta:
        file_type = "elf"
    condition:
        uint32(0) == 0x464c457f
}

//generic shebang, could be shell script, could be other
rule type_is_sh
{
    condition:
        uint16(0) == 0x2123 and uint8(2) == 0x2f
}

/*_________________________________________________________________________*/

/*---------------------------Archive Grouping--------------------------------*/

/*------------------ Archiving Only ------------------*/

rule type_is_xps
{
    meta:
	file_type = "xps"
    condition:
        uint32(0) == 0x504B0304
}

rule type_is_msi
{
//based on ole directory entry names
    meta:
        file_type = "msi"
    strings:
        $msi_dentry_1 = { 40 48 0b 43 31 41 35 47  00 00 00 00 00 00 00 00 }
        $msi_dentry_2 = { 40 48 0d 43 35 42 e6 45  72 45 3c 48 00 00 00 00 }
        $msi_dentry_3 = { 40 48 0f 42 e4 45 78 45  28 3b 32 44 b3 44 31 42 }
        $msi_dentry_4 = { 40 48 0f 42 e4 45 78 45  28 48 00 00 00 00 00 00 }
        $msi_dentry_5 = { 40 48 0f 43 2f 42 00 00  00 00 00 00 00 00 00 00 }
        $msi_dentry_6 = { 40 48 16 42 27 43 24 48  00 00 00 00 00 00 00 00 }
        $msi_dentry_7 = { 40 48 3f 3b f2 43 38 44  b1 45 00 00 00 00 00 00 }
        $msi_dentry_8 = { 40 48 3f 3f 77 45 6c 44  6a 3b e4 45 24 48 00 00 }
        $msi_dentry_9 = { 40 48 3f 3f 77 45 6c 44  6a 3e b2 44 2f 48 00 00 }
        $msi_dentry_10 = { 40 48 52 44 f6 45 e4 43  af 3b 3b 42 26 46 37 42 }
        $msi_dentry_11 = { 40 48 59 45 f2 44 68 45  37 47 00 00 00 00 00 00 }
        $msi_dentry_12 = { 40 48 7f 3f 64 41 2f 42  36 48 00 00 00 00 00 00 }
        $msi_dentry_13 = { 40 48 8c 44 f0 44 72 44  68 44 37 48 00 00 00 00 }
        $msi_dentry_14 = { 40 48 ca 41 30 43 b1 3b  3b 42 26 46 37 42 1c 42 }
        $msi_dentry_15 = { 40 48 ca 41 f9 45 ce 46  a8 41 f8 45 28 3f 28 45 }
        $msi_dentry_16 = { 40 48 ff 3f e4 43 ec 41  e4 45 ac 44 31 48 00 00 }
    condition:
        uint32(0) == 0xE011CFD0 and uint32(4) == 0xE11AB1A1
        and 5 of ($msi_dentry_*)
}

rule type_is_tar
{
    meta:
        scan_modules = "EXPLODE_TAR(filelimit=1000)"
        file_type = "tar"
    strings:
        $c = { 75 73 74 61 72 }
    condition:
        uint16(0) == 0x9d1f or
        uint16(0) == 0xa01f or
        $c at 257
}

rule type_is_vhd
{
    meta:
        file_type = "vhd"
    condition:
        uint32(0) == 0x656e6f63 and uint32(4) == 0x78697463
}

rule type_is_vhdx
{
    meta:
        file_type = "vhdx"
    condition:
        uint32(0) == 0x78646876 and uint32(4) == 0x656c6966
}

/*----------------------------------------------------*/
/*----------------- Compression Only -----------------*/
rule type_is_bzip 
{
    meta:
        scan_modules = "EXPLODE_BZ2(bytelimit=100000)"
        file_type = "bzip"
    condition:
        uint8(0) == 0x42 and uint8(1) == 0x5A and uint8(2) == 0x68
}

rule type_is_gzip 
{
    meta:
        scan_modules = "EXPLODE_GZIP(bytelimit=100000)"
        file_type = "gzip"
    condition:
        uint8(0) == 0x1F and uint8(1) == 0x8B
}
/*----------------------------------------------------*/
/*-------------- Archive AND Compression--------------*/


rule type_is_7zip 
{
    meta:
        scan_modules = "EXPLODE_SEVENZIP(filelimit=1000,bytelimit=100000)"
        file_type = "7zip"
    condition:
        uint8(0) == 0x37 and uint8(1) == 0x7A and uint8(2) == 0xBC and uint8(3) == 0xAF and uint8(4) == 0x27 and uint8(5) == 0x1C
}

rule type_is_iso
{
    meta:
        scan_modules = "EXPLODE_SEVENZIP(filelimit=1000,bytelimit=100000) META_ISO EXPLODE_ISO(filelimit=1000)"
        file_type = "iso"
    strings:
        $a = { 01 43 44 30 30 31 01 00 }
    condition:
        $a and uint32(0) == 0 and uint32(4) == 0
}

rule type_is_ace
{
    meta:
        scan_modules = "EXPLODE_ACE(filelimit=1000,bytelimit=100000)"
        file_type = "ace"
    strings:
        $a = "**ACE**"
    condition:
        $a at 7
}

rule type_is_arj
{
    meta:
        file_type = "arj"
    condition:
        uint16(0) == 0xea60
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

rule scan_cab
{
    meta:
        scan_modules = "EXPLODE_CAB(filelimit=1000,bytelimit=100000)"
    condition:
        type_is_cab
}


rule type_is_zip
{
    meta:
        scan_modules = "META_ZIP EXPLODE_ZIP(filelimit=1000)"
        file_type = "zip"
    strings:
        $a = { 504b0506 }
    condition:
        uint32(0) == 0x04034b50
        or ($a and for any i in (1..#a):
            (@a[i] + 22 +  uint16(@a[i] + 20) == filesize )
        )

}

rule type_is_rar
{
    meta:
        scan_modules = "EXPLODE_RAR2(filelimit=1000,bytelimit=100000)"
        file_type = "rar"
    strings:
        $a = { 52 61 72 21 1A 07 00 }
        $b = { 52 61 72 21 1A 07 01 00 }
    condition:
        $a in (0..1048584) or
        $b in (0..1048584)
}

rule type_is_dmg
{
    meta:
        file_type = "dmg"
    strings:
        $k = "koly" //most, but not all, have a 512-byte trailer with these magic bytes
        $c = "encrcdsa" //encrypted DMG magic
        $c2 = "cdsaencr"
    condition:
        $k in ((filesize-512)..filesize) or ext_filename contains ".dmg" or
        $c at 0 or $c2 at 0
}

/*----------------------------------------------------*/

/*_________________________________________________________________________*/

/*-----------------------Document File Grouping----------------------------*/

rule type_is_msoffice2003
{
    meta:
        scan_modules = "EXPLODE_OLE(minFileSize=16) EXPLODE_MACRO META_OLE"
        file_type = "ole"
    strings:
        $a = { D0 CF 11 E0 A1 B1 1A E1 }
    condition:
        $a at 0
}

rule type_is_msoffice2007
{
    meta:
        file_type = "officex"
	scan_modules = "EXPLODE_ZIP"
    strings:
        $rels = { 50 4b 03 04 [22] 0b 00 [2] 5f 72 65 6c 73 ( 2f | 5c ) 2e 72 65 6c 73 }
        $core = { 50 4b 03 04 [22] 11 00 [2] 64 6f 63 50 72 6f 70 73 ( 2f | 5c ) 63 6f 72 65 2e 78 6d 6c }
        $app = { 50 4b 03 04 [22] 10 00 [2] 64 6f 63 50 72 6f 70 73 ( 2f | 5c ) 61 70 70 2e 78 6d 6c }
        $word = { 50 4b 03 04 [22] 11 00 [2] 77 6f 72 64 ( 2f | 5c ) 64 6f 63 75 6d  65 6e 74 2e 78 6d 6c }
        $xl = { 50 4b 03 04 [22] 0f 00 [2] 78 6c ( 2f | 5c ) 77 6f 72 6b 62 6f 6f 6b 2e 78  6d 6c }
        $ppt = { 50 4b 03 04 [22] 14 00 [2] 70 70 74 ( 2f | 5c ) 70 72 65 73 65  6e 74 61 74 69 6f 6e 2e 78 6d 6c }
    condition:
        uint32be(0) == 0x504B0304 and 2 of them
}

rule type_is_xml
{
    meta:
        file_type = "xml"
        scan_modules = "META_XML"
    condition:
        ext_filename contains ".xml"
}

rule type_is_officexml
{
    meta:
        scan_modules = "EXPLODE_OFFICEXML"
    strings:
        $msoapplication = { 3c 3f 6d 73 6f 2d 61 70 70 6c 69 63 61 74 69 6f 6e }
        $word2003 = { 3a 77 6f 72 64 44 6f 63 75 6d 65 6e 74 }
        $flatopc = { 3a 70 61 63 6b 61 67 65 }
    condition:
        type_is_xml and ($msoapplication in (0 .. 1024) or $word2003 in (0 .. 1024) or $flatopc in (0 .. 1024))
}

rule type_ole_encrypted
{
    meta:
        scan_modules = "EXPLODE_ENCRYPTEDOFFICE"
    strings:
        $a = { 45 00 6e 00 63 00 72 00  79 00 70 00 74 00 65 00 64 00 50 00 61 00 63 00  6b 00 61 00 67 00 65 00 }
        $b = { 45 00 6e 00 63 00 72 00  79 00 70 00 74 00 69 00 6f 00 6e 00 49 00 6e 00  66 00 6f 00 00 00 00 00 }
    condition:
        uint32(0) == 0xe011cfd0 and $a and $b
}

rule type_is_rtf
{
    meta:
        scan_modules = "EXPLODE_RTF META_RTF_CONTROLWORDS"
        file_type = "rtf"
    condition:
        uint32(0) == 0x74725c7b
}

rule type_is_pdf
{
    meta:
        scan_modules = "EXPLODE_PDF(filelimit=1000,totalbytelimit=100000) META_PDFURL EXPLODE_PDF_TEXT META_PDF_STRUCTURE(rawdims=1)"
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

rule type_is_eps
{
    meta:
        file_type = "eps"
        scan_modules = "META_PS_COMMANDS"
    strings:
        $a = "%!PS-Adobe-"
    condition:
        $a in (0..30) or uint32be(0) == 0xC5D0D3C6

}

rule type_is_ps
{
    meta:
        file_type = "ps"
        scan_modules = "META_PS_COMMANDS"
    condition:
        uint16be(0) == 0x2521 and not type_is_eps
}

rule type_is_dwg
{
    meta:
	file_type = "dwg"
    condition:
	uint32(0) == 0x30314341
}

rule type_is_ttf
{
    meta:
        file_type = "ttf"
    condition:
        uint32(0) == 0x00000100
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
        scan_modules = "META_LNK"
    strings:
        $a = { 4C 00 00 00 01 14 02 00 }
    condition:
        $a at 0
}

rule type_is_html
{
    meta:
        scan_modules = "SCAN_HTML"
        file_type = "html"
    strings:
        $a = "<html" nocase
        $b = "<!DOCTYPE HTML" nocase
    condition:
        ext_contentType contains "html" or $a at 0 or $b at 0 or ext_filename matches /.*(.html|.htm|.HTM|.HTML)$/
}

rule type_is_macro_stream
{
    meta:
        flags = "OLEContainsMacros"
    strings:
        $a = "\x00Attribut\x00e "
    condition:
        ( uint16be(0) == 0x0116 and uint8(3) == 0x00 )
        or ($a and ext_sourceModule contains "EXPLODE_OLE")
}

rule type_is_macro
{
//Attr     ibut     e VB
//41747472 69627574 65205642
    meta:
        scan_modules = "META_MACRO SCAN_VBA"
        file_type = "macro"

    condition:
        (uint32be(0) == 0x41747472 and uint32be(4) == 0x69627574
        and uint32be(8) == 0x65205642) or ext_sourceModule contains "EXPLODE_MACRO"
}

rule type_is_vba_project
{
    meta:
        file_type = "vba_proj"

    condition:
        uint16be(0) == 0xcc61
        and (uint16be(6) == 0x00ff or ext_filename contains "_VBA_PROJECT")
}

rule type_is_ooxml_rels
{
    meta:
        scan_modules = "META_OOXML_URLS META_OOXML_RELS"
    strings:
        $a = "<Relationship"
    condition:
        $a
        //currently not checking that parent is officex/ooxml file, could do in future if needed
}

rule type_is_dmarc
{
    meta:
        scan_modules = "META_DMARC"
    strings:
        $feedback = "<feedback>"
    condition:
        $feedback in (0..200) and
        (ext_filename contains "dmarc" or ext_filename contains "DMARC" or ext_filename contains "Dmarc") and
        ext_filename contains ".xml"
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
        $received2 = "Received: "
        $return = "\x0aReturn-Path:"
    condition:
        (not ext_sourceModule contains "EXPLODE_EMAIL") and
        (($from at 0) or ($received2 at 0) or
         ($received in (0 .. 2048)) or 
         ($return   in (0 .. 2048)))
}

rule type_is_msg
{
    meta:
        scan_modules = "EXPLODE_MSG"
        file_type = "msg"
    strings:
        $a = { d0 cf 11 e0 a1 b1 1a e1 }
        $substg = { 5f 00 5f 00 73 00 75 00  62 00 73 00 74 00 67 00 31 00 2e 00 30 00 5f 00 }
        $props = { 5f 00 5f 00 70 00 72 00  6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00  5f 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00  31 00 2e 00 30 00 }
        $recip = { 5f 00 5f 00 72 00 65 00  63 00 69 00 70 00 5f 00 76 00 65 00 72 00 73 00  69 00 6f 00 6e 00 31 00 2e 00 30 00 }
    condition:
        $a at 0 and ($substg or $props or $recip)
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
        scan_modules = "EXPLODE_TNEF"
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
//        scan_modules = ""
        file_type = "swf"
    condition:
        type_is_SWF_CWS or type_is_SWF_FWS or type_is_SWF_ZWS
}

/*_________________________________________________________________________*/

/*-----------------------Media File Grouping-------------------------------*/

rule type_is_png
{
    meta:
        file_type = "png"
        scan_modules = "EXPLODE_BINWALK(binwalk_extraction=(zip|tar|pdf|rar|cabinet|bzip2))"
    condition:
        ( uint32be(4) == 0x0d0a1a0a or uint32be(4) == 0xa1a0a0a )  and ( uint32be(0) == 0x89504e47 or uint32be(0) == 0x8a4d4e47 or uint32be(0) == 0x8b4a4e47 )
}

rule type_is_jpg
{
    meta:
        file_type = "jpg"
        scan_modules = "EXPLODE_BINWALK(binwalk_extraction=(zip|tar|pdf|rar|cabinet|bzip2))"
    condition:
        uint16be(0) == 0xffd8 and uint8(2) == 0xff
}

rule type_is_xmp
{
    meta:
        file_type = "xmp"
    condition:
        (uint32be(0) == 0x3c3f7870 and uint32be(4) == 0x61636b65) or
        (uint32be(0) == 0x3c783a78 and uint32be(4) == 0x6d706d65) or
        (uint32be(0) == 0xefbbbf3c and uint32be(4) == 0x3f787061) or
        (uint32be(0) == 0x0a3c3f78 and uint32be(4) == 0x7061636b) or
        (uint32be(0) == 0xfeff003c and uint32be(4) == 0x0078003a)
}

rule type_is_gif
{
    meta:
        file_type = "gif"
    condition:
        uint32be(0) == 0x47494638 and uint8(5) == 0x61
}

rule type_is_wmf16
{
    //exiftool can't process wmf
    meta:
        file_type = "wmf"
    condition:
        uint32be(0) == 0x01000900 and uint16be(4) == 0x0003
}


rule type_is_wmf32
{
    meta:
        file_type = "wmf"
    condition:
        uint32be(0) == 0xD7CDC69A
}

rule type_is_wav
{
    meta:
        file_type = "wav"
    condition:
        uint32be(0) == 0x52494646 and uint32be(8) == 0x57415645 and uint32be(12) == 0x666D7420
}

rule type_is_hdp
{
    meta:
        file_type = "hdp"
    condition:
        uint16be(0) == 0x4949 and uint8(2) == 0xbc
}

rule type_is_bmp
{
    meta:
        file_type = "bmp"
    condition:
        uint16be(0) == 0x424d and uint32be(6) == 0x00000000
        //and uint32(2) == filesize
}

rule type_is_tiff
{
    meta:
        scan_modules = "META_TIFF"
        file_type = "tiff"
    condition:
        uint32(0) == 0x002a4949 or uint32(0) == 0x2a004d4d
}

rule type_is_emf
{
    meta:
        scan_modules = "META_EMF"
        file_type = "emf"
    condition:
        uint32(0) == 0x000000001 and uint32(0x28) == 0x464d4520
}

rule type_is_mp3
{
    meta:
//        scan_modules = ""
        file_type = "mp3"
    condition:
        uint16(0) == 0x4449 and uint8(2) == 0x33
}

rule type_is_wmv
{
    meta:
//        scan_modules = ""
        file_type = "wmv"
    strings:
        $a = { 30 26 B2 75 8E 66 CF 11 A6 D9 00 AA 00 62 CE 6C }
    condition:
        $a at 0
}

rule type_is_avi
{
    meta:
//        scan_modules = ""
        file_type = "avi"
    strings:
        $a = { 52 49 46 46 ?? ?? ?? ?? 41 56 49 20 4C 49 53 54 }
    condition:
        $a at 0
}

rule type_is_mov
{
    meta:
//        scan_modules = ""
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


/*-------------------OT File Grouping--------------------------------------*/

rule type_is_fwl
{
    meta:
        file_type = "fwl"
    condition:
        ext_filename contains ".FWL" or
        ext_filename contains ".fwl"
}

rule type_is_cbi
{
    meta:
        file_type = "cbi"
    condition:
        ext_filename contains ".cbi"
}

rule type_is_srecord
{
    meta:
        file_type = "srec"
    strings:
        $s0 = /^S0([0-9A-F][0-9A-F])/
    condition:
        $s0
}


rule type_is_bin {
    meta:
        file_type = "bin"
    condition:
        ext_filename contains ".bin" or ext_filename contains ".BIN"
}


/*_________________________________________________________________________*/

/*-------------------Dispatcher Flag Grouping------------------------------*/

rule type_is_olenative
{
    meta:
        scan_modules = "EXPLODE_OLENATIVE"
        file_type = "olenative"
    condition:
        ext_parentModules contains "EXPLODE_OLE" and ext_filename contains "Ole" and ext_filename contains "Native"
}

rule exe_in_plist
{
    meta:
        flags = "PListEmbeddedExecutable"
    condition:
        ext_sourceModule contains "EXPLODE_PLIST" and
        type_is_mz 
}

private rule type_is_registry_edit
{
    strings:
        $a = "Windows Registry Editor Version"
        $b = "REGEDIT"
    condition:
        $a at 0 or $b at 0
}

rule type_is_script
{
    meta:
        flags = "ScriptWarning"
    strings:
        $a = "batch file"
    condition:
        type_is_sh or type_is_registry_edit or $a
}

rule html_attachment
{
    meta:
        flags = "html_attach"
    condition:
        ext_sourceModule contains "EXPLODE_EMAIL" and (ext_filename contains ".htm" or ext_filename contains ".html")
}


/*_________________________________________________________________________*/

/*-----------------------Apple File Grouping---------------------------------*/

rule type_is_plist
{
    meta:
        scan_modules = "EXPLODE_PLIST"
        file_type = "plist"
    strings:
        $a = "bplist"
    condition:
        $a at 0
}

/*_________________________________________________________________________*/


/*-----------------------EXIFTOOL Grouping---------------------------------*/
rule META_EXIFTOOL
{
    meta:
        scan_modules = "META_EXIFTOOL"
    condition:

//html
        ( type_is_html or
//media
        type_is_SWF_FWS or
        type_is_mov or
        type_is_avi or
        type_is_wmv or
        type_is_mp3 or
        type_is_wav or
//images
        type_is_tiff or
        type_is_bmp or
        type_is_emf or
        type_is_eps or
        type_is_gif or
        type_is_png or
        type_is_jpg or
        type_is_wmf16 or
        type_is_wmf32 or
        type_is_hdp or
//documents
        type_is_msoffice2003 or
        type_is_msoffice2007 or
        type_is_rtf or
        type_is_pdf or
        type_is_ttf or
        type_is_xml or
        type_is_xmp or
//archives        
        type_is_gzip or
        type_is_zip or
        type_is_rar or
//executables
        type_is_mz or
        type_is_elf or
        type_is_sh or
        type_is_7zip or        
//other
        type_is_lnk or        
        type_is_plist or        
        type_is_chm or
        type_is_vcard )
        
}

/*_________________________________________________________________________*/

/*-------------------------File Carving Grouping----------------------------*/

//rule binwalk_pe_extraction {
//    meta:
//        scan_modules = "EXPLODE_BINWALK(binwalk_extraction=(microsoft executable))"
//    condition:
//}

/*_________________________________________________________________________*/
