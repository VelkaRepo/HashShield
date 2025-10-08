rule EICAR_Test_String
{
    meta:
        description = "This is the standard EICAR antivirus test string."
        author = "HashShield Project"
        version = "1.1"
        tags = "eicar" "antivirus_test" "test_file"

    strings:
        $eicar_text = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        // The rule now only matches if the string is found AND the file is exactly 68 bytes.
        $eicar_text and filesize == 68
}