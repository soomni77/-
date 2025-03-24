rule excel_restart_admin
{
    meta:
        description = "Detects when Excel is being executed with administrator privileges"
        author = "ChatGPT"
        last_modified = "2025-03-24"
    
    strings:
        $runas = "runas"
        $cmd = "cmd.exe /c start"
        $excel = "excel.exe"
    
    condition:
        $runas and $cmd and $excel
}
