/*

Laika Dispatcher : 2nd pass

*Overview
    * This second pass dispatcher operates on the flags appended to the object during
      the first pass of scanning. These rules cruise through a buffer created by 
      joining (on space) the heretofore flags attached to this object. This is in 
      contrast to the first pass dispatcher where you are analyzing the buffer of the 
      object. Since the scanning is performed depth-first, you can be assured that 
      all first-pass processing is complete (including the processing of child 
      objects) before this dispatcher runs. You can configure this dispatcher to run 
      modules based on the contents of the flags as well as the external variables 
      provided to you.
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
    * ext_fileType (str)      : file type set by the first dispatcher (default: NONE)
    * ext_filename (str)      : filename set by client or a module (default: NONE)
    * ext_timestamp (str)     : timestamp set by client or a module (default: NONE)
    * ext_source (str)        : source set by client or a module (default: NONE) 
    * ext_size (int)          : the length of the buffer (default: 0)
    * ext_depth (int)         : the depth of the current object (root == 0)
    * ext_scanTime (int)      : timestamp of beginning of processing of current object
    * ext_parent_scanTime(int): timestamp of beginning of processing of parent object
    * ext_root_scanTime (int) : timestamp of begining of processing of root object
    * ext_time (int)          : current timestamp, similar to time.now() of yara 3.7+
    * ext_depth (int)         : depth of the current object + 1 (root == 1)
    * ext_args (str)          : args passed to this laikaboss job, flattened into a
      string and demarcated by '|' characters
*/

/*-----------------------Private Rule Grouping-----------------------------*/

private rule root_object
{
    condition:
        ext_sourceModule contains "NONE" 
}

/*_________________________________________________________________________*/
/*-----------------------Timeouts------------------------------------------*/

//timeout for whole scan
rule timeout_root
{
    meta:
        flags = "timeout_root"
    condition:
        (ext_time - ext_root_scanTime) > 900
}

//timeout for children of root
//timeout for grandchildren of root or lower
rule timeout_subtree
{
    meta:
        flags = "timeout_subtree"
    condition:
        ext_depth > 2 and (ext_time - ext_parent_scanTime) > 700 or
        ext_depth > 3 and (ext_time - ext_parent_scanTime) > 500
}

//use "not timeout" condition for modules that should be skipped after timeout
private rule timeout
{
    condition:
        timeout_root or timeout_subtree
}

/*_________________________________________________________________________*/
/*-----------------------Default Priority Modules--------------------------*/
//default priority (order)
rule JAR_FILE
{
    meta:
        file_type = "jar"
    strings:
        $misc_jar_file = "misc_jar_file"
    condition:
        any of them
}

rule scaninfo_end
{
    meta:
        scan_modules = "META_SCANINFO"
        priority = "49"
    condition:
        root_object
}

/*_________________________________________________________________________*/
/*-----------------------High Priority (Late) Modules----------------------*/

rule send_to_splunk
{
    meta:
        scan_modules = "LOG_SPLUNK(type=file,host=localhost,logfile=/var/log/laikaboss/laikaboss_splunk.log,split_log=False)"
        priority = "90"
    condition:
        root_object and (not ext_source contains "CLI" and not ext_source contains "webUI") or ext_args contains "|submit_to_splunk=True|"
}


/* no flags can be created after this call or they will be ignored */
rule DISPOSITION_FILE
{
    meta:
        scan_modules = "DISPOSITIONER"
        priority = "30"
    condition:
        true
}


/*_________________________________________________________________________*/
/*-----------------------High Priority (Late) Modules----------------------*/

rule send_to_storage_attachments_s3
{
    meta:
        scan_modules = "SUBMIT_STORAGE_S3(type=cache_file,bucket=email,interval=3)"
        priority = "45"
    condition:
        //for root object, depth=1 so it is 1 indexed, not 0 - weird - so ext_depth == 2, means it has attachments
        //when no flags, buffer = "EMPTY", so if there are flags filesize > 5
       not ext_source contains "CLI" and not ext_filename contains "e_email_hybrid" and 
        ((ext_depth == 2 or (ext_depth > 2 and filesize > 5)) or ext_filename contains "text_from_html") and
        (not ext_source contains "webUI-" or ext_args contains "|submit_to_storage=True|")
} 


rule send_to_storage_gui_s3
{
    meta:
        scan_modules = "SUBMIT_STORAGE_S3(type=cache_file,bucket=gui)"
        priority = "45"
    condition:
        ext_args contains "|save_all_subfiles=True|"
}

rule scaninfo_end_cli
{
    meta:
        scan_modules = "META_SCANINFO"
        priority = "85"
    condition:
        root_object
}

rule send_to_storage_email_json_s3
{
    meta:
        scan_modules = "SUBMIT_STORAGE_S3(clear_log_data=false,type=json,bucket=email)"
        priority = "99"
    condition:
        root_object and not ext_source contains "CLI" and (not ext_source contains "webUI-" or ext_args contains "|submit_to_storage=True|")
}
