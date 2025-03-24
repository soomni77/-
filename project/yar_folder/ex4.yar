rule excel_admin_restart
{
    meta:
        description = "Detects Excel macro attempting to restart Excel with admin privileges"
        author = "ChatGPT"
        last_modified = "2025-03-24"
    
    strings:
        $runas = "runas"  // 관리자 권한으로 실행하려는 명령어
        $cmd = "cmd.exe /c start"  // cmd 명령어를 통해 실행
        $excel = "excel.exe"  // 엑셀 실행 파일
        $elevated = "runas /user:Administrator"  // 관리자 권한으로 엑셀 실행
        
    condition:
        $runas and $cmd and $excel and $elevated
}
