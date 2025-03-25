rule Malicious_API_Calls
{
    meta:
        description = "Detect suspicious API calls"
        author = "YourName"
        last_modified = "2025-03-25"
    
    strings:
        $create_process = "CreateProcessW" ascii
        $terminate_process = "TerminateProcess" ascii
        $exit_process = "ExitProcess" ascii
        $get_proc_address = "GetProcAddress" ascii

    condition:
        any of ($create_process, $terminate_process, $exit_process, $get_proc_address)
}
