/*
* Overview
    * This file contains the default rules the SCAN_YARA module will use unless 
      another ruleset is specified in the dispatcher.
*/

rule informational_sig_1
{
    strings:
        $ = "foo"
    condition:
        any of them
}

rule suspicious_sig_1
{
    strings:
        $ = "bar"
    condition:
        any of them
}

rule backdoor_family_1
{
    strings:
        $ = "baz"
    condition:
        any of them
}
