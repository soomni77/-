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