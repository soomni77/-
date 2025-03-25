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