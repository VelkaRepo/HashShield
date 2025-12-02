rule EICAR_Test_String : eicar antivirus_test test_file
{
    meta:
        description = "This is the standard EICAR antivirus test string."
        author = "HashShield Project"
        version = "1.2"
    strings:
        $eicar_text = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        // Allow up to 70 bytes to handle accidental newlines
        $eicar_text and filesize <= 70
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
        $gtube_text and filesize <= 70
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

// --- FIXED RULE: CATCHES YOUR GENERATED TROJANS ---
rule MSFVenom_Calc_Payload {
    meta:
        description = "Detects MSFVenom generated executables launching calc.exe"
        author = "Dion (HashShield)"
        date = "2025-12-01"
        threat_level = "High"
    
    strings:
        // 1. The payload command
        $payload_cmd = "calc.exe" nocase
        
        // 2. Suspicious API calls
        $api1 = "VirtualProtect"
        $api2 = "KERNEL32.dll"
        
        // 3. The PE Section names
        $sec1 = ".text"
        $sec2 = ".rdata"
        $sec3 = ".data"
        
    condition:
        // Must start with 'MZ' (Windows EXE)
        uint16(0) == 0x5A4D 
        
        // Must contain the payload string OR (the suspicious APIs AND all 3 sections)
        and (
            $payload_cmd or 
            ($api1 and $api2 and $sec1 and $sec2 and $sec3)
        )
        
        // Filter: Generated stagers are typically small (< 200KB)
        and filesize < 200KB
}