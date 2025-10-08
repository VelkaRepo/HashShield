rule EICAR_Test_String : eicar antivirus_test test_file
{
    meta:
        description = "This is the standard EICAR antivirus test string."
        author = "HashShield Project"
        version = "1.1"
    strings:
        $eicar_text = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar_text and filesize == 68
}

rule GTUBE_Spam_Test_String : gtube spam_test test_file
{
    meta:
        description = "This is the standard GTUBE anti-spam test string."
        author = "HashShield Project"
        version = "1.0"
    strings:
        $gtube_text = "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X"
    condition:
        $gtube_text and filesize == 68
}

rule Dummy_Threat_Test_String : dummy_threat test_file
{
    meta:
        description = "A custom dummy threat for testing HashShield's engine."
        author = "HashShield Project"
        version = "1.0"
    strings:
        $dummy_text = "HASHSHIELD_DUMMY_THREAT_FILE_01"
    condition:
        $dummy_text
}

rule Is_Windows_Executable : pe executable windows
{
    meta:
        description = "Detects a Windows PE file (EXE, DLL, etc.) by its 'MZ' magic bytes."
        author = "HashShield Project"
    strings:
        $magic_bytes = { 4D 5A }
    condition:
        $magic_bytes at 0
}