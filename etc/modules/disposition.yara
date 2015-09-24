/*

* Overview
    * This file is used by the DISPOSITIONER module to determine the outcome of a 
      scan. It takes all of the flags from the current object as well as any
      descendent objects and combines them into a space separated list. The rules
      in this file run against that list.
*/

rule Deny
{
    strings:
        $backdoor_family_1 = "backdoor_family_1"
        $exploit_CVE_2015_1337 = "exploit_CVE_2015_1337"
        $info_1 = "informational_sig_1"
        $susp_1 = "suspicious_sig_1"
    condition:
        any of ( $backdoor_* ) or 
        any of ( $exploit_* ) or
        ($info_1 and $susp_1)

}

rule Alert
{
    strings:
        $susp_1 = "suspicious_sig_1"
    condition:
        $susp_1
}
