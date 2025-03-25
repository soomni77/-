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





