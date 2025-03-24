rule uac_registry_change
{
    meta:
        description = "Detects changes to UAC registry settings"
        author = "ChatGPT"
        last_modified = "2025-03-24"
    
    strings:
        $uac_key = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
        $uac_disable = "EnableLUA"
        $uac_value = "0"
    
    condition:
        $uac_key and $uac_disable and $uac_value
}
