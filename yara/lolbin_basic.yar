// Placeholder for YARA rule 

rule LOLBin_Basic
{
    meta:
        description = "Detects basic LOLBin patterns in binaries or scripts"
        author = "Elastic LOLBin Pack"
        reference = "https://attack.mitre.org/"
    strings:
        $ps_enc = "-enc" ascii nocase
        $certutil = "certutil.exe" ascii nocase
        $wmi = "wmiprvse.exe" ascii nocase
    condition:
        any of them
}

// This rule could be used in Falco or ClamAV by scanning process memory or files for LOLBin patterns. 