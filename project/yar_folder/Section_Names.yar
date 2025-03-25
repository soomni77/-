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