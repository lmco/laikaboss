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

*/

/*-----------------------Private Rule Grouping-----------------------------*/

private rule root_object
{
    condition:
        ext_sourceModule contains "NONE" 
}

/*_________________________________________________________________________*/

rule JAR_FILE
{
    meta:
        file_type = "jar"
    strings:
        $misc_jar_file = "misc_jar_file"
    condition:
        any of them
}

rule send_to_fluent
{
    meta:
        scan_modules = "LOG_FLUENT"
        priority = "50"
    condition:
        root_object
}

rule DISPOSITION_FILE
{
    meta:
        scan_modules = "DISPOSITIONER"
        priority = "10"
    condition:
        true
}

