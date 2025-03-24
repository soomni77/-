rule malicious_excel_macro
{
    meta:
        description = "Detects malicious Excel macro behaviors including re-executing Excel as admin, UAC bypass, downloading and executing files"
        author = "ChatGPT"
        last_modified = "2025-03-24"
    
    strings:
        $runas = "runas"
        $cmd = "cmd.exe /c start"
        $excel = "excel.exe"
        $uac_key = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
        $uac_disable = "EnableLUA"
        $uac_value = "0"
        $google_drive = "drive.google.com"
        $exe_extension = ".exe"
    
    condition:
        ( 
            $runas and $cmd and $excel or
            ($uac_key and $uac_disable and $uac_value) or
            ($google_drive and $exe_extension)
        )
}
