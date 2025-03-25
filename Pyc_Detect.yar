rule registry_modification_rule
{
    meta:
        description = "Detects registry changes used for persistence or disabling security"
    strings:
        $r1 = "EnableSmartScreen"
        $r2 = "EnableLUA"
        $r3 = "DisableTaskMgr"
        $r4 = "DisableRegistryTools"
        $r5 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $r6 = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\MyMalService"
    condition:
        any of ($r*)
}

rule powershell_encoded_command_rule
{
    meta:
        description = "Detects use of PowerShell with -EncodedCommand"
    strings:
        $p1 = "powershell -EncodedCommand"
        $p2 = "ExecutionPolicy Bypass"
    condition:
        any of ($p*)
}

rule info_collection_rule
{
    meta:
        description = "Detects system information gathering commands"
    strings:
        $i1 = "systeminfo"
        $i2 = "ipconfig /all"
        $i3 = "tasklist"
        $i4 = "netstat -an"
        $i5 = "net user"
    condition:
        any of ($i*)
}

rule startup_persistence_rule
{
    meta:
        description = "Detects persistence via startup registry keys or scheduled behavior"
    strings:
        $s1 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $s2 = "cmd.exe /c echo pwned"
        $s3 = ".mal"
    condition:
        any of ($s*)
}

rule user_account_creation_rule
{
    meta:
        description = "Detects creation of unauthorized user accounts"
    strings:
        $u1 = "net user backdooruser"
        $u2 = "net localgroup administrators backdooruser"
    condition:
        any of ($u*)
}