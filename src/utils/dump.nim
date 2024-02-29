import winim
proc NtOpenProcess(
    ProcessHandle: PHANDLE,
    DesiredAccess: ACCESS_MASK,
    ObjectAttributes: POBJECT_ATTRIBUTES,
    ClientId: PCLIENT_ID
): NTSTATUS {.importc, dynlib: "ntdll", stdcall.}

proc toString(wca : array[0..259,WCHAR]): string =
    var final : string = ""
    for byte in wca:
        add(final , chr(byte))
    return final

proc findProcessPIDS*(procname: string): seq[DWORD] =
    var pe32: PROCESSENTRY32
    var pids: seq[DWORD]
    pe32.dwSize = sizeof(PROCESSENTRY32).DWORD
    let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS , 0)
    Process32First(snapshot , &pe32)
    while Process32Next(snapshot , &pe32):
        let pid = pe32.th32ProcessID
        let name = pe32.szExeFile.toString.LPCSTR
        if lstrcmpA(name, procname.LPCSTR) == 0:
            pids.add(pid)
    return pids

proc getHandleNatively*(PID: DWORD): HANDLE =
    var hProc: HANDLE
    var objAtt: OBJECT_ATTRIBUTES
    var clientId: CLIENT_ID
    clientId.UniqueProcess = PID
    clientId.UniqueThread = 0.DWORD
    InitializeObjectAttributes(&objAtt, NULL , 0 , cast[HANDLE](NULL) , cast[PSECURITY_DESCRIPTOR](NULL))
    let res = NtOpenProcess(&hProc , PROCESS_VM_READ or PROCESS_QUERY_INFORMATION, &objAtt, &clientId)
    if res == STATUS_SUCCESS:
        return hProc
