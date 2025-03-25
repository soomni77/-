rule Excel_Macro_Relaunch_As_Admin
{
    meta:
        description = "Detects Excel macro that relaunches as admin"
        author = "Your Name"
        date = "2025-03-25"
    
    strings:
        $relaunch_as_admin_pattern = "shell.ShellExecute \"excel.exe\", \"\"\" & ThisWorkbook.FullName & \"\"\", \"\", \"runas\"" nocase

    condition:
        $relaunch_as_admin_pattern
}