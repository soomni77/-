rule Rich_String
{
    meta:
        description = "Detect Rich string in PE header"
        author = "YourName"
        last_modified = "2025-03-25"
    
    strings:
        $rich = "Rich" ascii

    condition:
        $rich
}