rule admin_restart_detection
{
    meta:
        description = "Detects files attempting to run with admin privileges"
        author = "ChatGPT"
        last_modified = "2025-03-24"
    
    strings:
        $runas = "runas"
        $cmd = "cmd.exe /c start"
        $elevated = "runas /user:Administrator"
    
    condition:
        $runas or $cmd or $elevated
}
