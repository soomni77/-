rule Suspicious_Pattern
{
    meta:
        description = "Detect suspicious binary patterns"
        author = "YourName"
        last_modified = "2025-03-25"
    
    strings:
        $suspicious_pattern_1 = { 61 61 15 14 15 90 14 00 }
        $suspicious_pattern_2 = { 67 70 2a 00 00 00 }

    condition:
        any of ($suspicious_pattern_1, $suspicious_pattern_2)
}

rule Section_Names
{
    meta:
        description = "Detect known sections in PE files"
        author = "YourName"
        last_modified = "2025-03-25"
    
    strings:
        $text_section = ".text" ascii
        $rdata_section = ".rdata" ascii
        $data_section = ".data" ascii
        $pdata_section = ".pdata" ascii

    condition:
        any of ($text_section, $rdata_section, $data_section, $pdata_section)
}

rule Malicious_API_Calls
{
    meta:
        description = "Detect suspicious API calls"
        author = "YourName"
        last_modified = "2025-03-25"
    
    strings:
        $create_process = "CreateProcessW" ascii
        $terminate_process = "TerminateProcess" ascii
        $exit_process = "ExitProcess" ascii
        $get_proc_address = "GetProcAddress" ascii

    condition:
        any of ($create_process, $terminate_process, $exit_process, $get_proc_address)
}

rule Suspicious_Binary_Pattern
{
    meta:
        description = "Detect suspicious binary patterns"
        author = "YourName"
        last_modified = "2025-03-25"
    
    strings:
        $pattern_1 = { E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? }
        $pattern_2 = { 89 45 FC 83 7D 08 00 }
    
    condition:
        any of ($pattern_1, $pattern_2)
}

rule PE_File_Analysis
{
    meta:
        description = "Detect PE file based on its header"
        author = "YourName"
        last_modified = "2025-03-25"
    
    condition:
        // PE Header (0x4D5A = MZ) and PE signature (0x4550 = PE)
        uint16(0) == 0x5A4D and
        uint32(0x3C) == 0x4550
}