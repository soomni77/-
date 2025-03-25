rule PE_Signature
{
    meta:
        description = "Detect PE file signature (MZ and PE)"
        author = "YourName"
        last_modified = "2025-03-25"
    
    strings:
        // DOS Header Magic: "This program cannot be run in DOS mode"
        $dos_header = "This program cannot be run in DOS mode" ascii
        // PE Signature (DOS MZ header + PE header magic "PE")
        $pe_signature = { 4D 5A 00 00 00 00 00 00 00 00 50 45 00 00 }

    condition:
        $dos_header or $pe_signature
}