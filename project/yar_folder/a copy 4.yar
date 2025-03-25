rule Excel_Macro_Disable_UAC
{
    meta:
        description = "Detects Excel macro that disables UAC"
        author = "Your Name"
        date = "2025-03-25"
    
    strings:
        $reg_key_pattern = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA" nocase

    condition:
        $reg_key_pattern
}