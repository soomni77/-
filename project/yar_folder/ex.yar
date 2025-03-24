rule excel_malicious_macro
{
    meta:
        description = "Detects malicious Excel macros with specific shell commands"
        author = "ChatGPT"
        last_modified = "2025-03-24"
    
    strings:
        $runas = "runas"
        $cmd = "cmd.exe /c start"
        $shell = "CreateObject(\"WScript.Shell\")"
        $regwrite = "RegWrite"
        $url = "drive.google.com"
        $exe = ".exe"
    
    condition:
        ($runas or $cmd or $shell or $regwrite or $url) and $exe
}
