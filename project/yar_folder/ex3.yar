rule google_drive_download
{
    meta:
        description = "Detects downloading an executable file from Google Drive"
        author = "ChatGPT"
        last_modified = "2025-03-24"
    
    strings:
        $google_drive = "drive.google.com"
        $exe_extension = ".exe"
    
    condition:
        $google_drive and $exe_extension
}
