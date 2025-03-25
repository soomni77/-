rule Excel_Macro_Download_And_Run_Exe
{
    meta:
        description = "Detects Excel macro that downloads and runs EXE file"
        author = "Your Name"
        date = "2025-03-25"
    
    strings:
        // HTTP로 EXE 파일을 다운로드하는 코드
        $http_request = "WinHttp.WinHttpRequest" nocase
        $download_url = "http" nocase
        $exe_download_path = "SaveToFile" nocase
        $exe_run_command = "cmd.exe /c" nocase
        $exe_extension = ".exe" nocase

    condition:
        $http_request and $download_url and $exe_download_path and $exe_run_command and $exe_extension
}
