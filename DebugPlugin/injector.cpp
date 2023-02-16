#include "injector.h"
#include "log.h"
#include "common.h"
#include "debugStruct.h"

char ConfigName[256];

#pragma pack(push, 1)
struct RemoteInjectShellCode
{
#ifdef _WIN64
    DWORD   sub_rsp_0x28;
    WORD    mov_rcx;
    DWORD64 Arg_1;
    WORD    call_FF15;
    DWORD   call_offset;
    WORD    jmp_8;
    DWORD64 pLoadLibraryA;
    DWORD   add_rsp_0x28;
    char    testRax[3];
    WORD    jmp_6;
    BYTE    Register_eax1;
    DWORD   nResust1;
    BYTE    Ret1;
    WORD    mov_rcx1;
    DWORD64 pDllBase;
    char    movRcxRax[3];
    BYTE    Register_eax2;
    DWORD   nResust2;
    BYTE    Ret2;
    DWORD64 n[4];
#else
    BYTE    push;
    DWORD   arg;
    BYTE    call;
    DWORD   call_offset;
    WORD    test_eax;
    WORD    jne_6;
    BYTE    Register_eax1;
    DWORD   nResust1;
    BYTE    Ret1;

    BYTE    mov_rcx;
    DWORD   pDllBase;
    WORD   movEcxEax;

    BYTE    Register_eax2;
    DWORD   nResust2;
    BYTE    Ret2;
    DWORD   n[4];
#endif


};
#pragma pack(pop)
BOOL InjectEx_32(HANDLE ProcessHandle, ULONG nPid, const char* szDllPath);
BOOL InjectEx(HANDLE ProcessHandle, ULONG nPid, const char* szDllPath);
BOOL InjectDll(HANDLE ProcessHandle, const char* szDllPath, PVOID* pDllBase);
PVOID CreateInjectCode(HANDLE ProcessHandle, const char* szDllPath, PVOID* pDllBase);
PVOID CreateInjectCode(HANDLE ProcessHandle, const char* szDllPath, PVOID* pDllBase)
{
    ULONG_PTR nOffset = 0;
    PVOID pAllocate = VirtualAllocEx(ProcessHandle, NULL, 1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!pAllocate)return NULL;

    nOffset = (ULONG_PTR)pAllocate + sizeof(RemoteInjectShellCode);
    char szCode[0x1000] = { 0 };
    strcpy((char*)((ULONG_PTR)szCode + sizeof(RemoteInjectShellCode)), szDllPath);

    RemoteInjectShellCode code;
#ifdef _WIN64
    code.sub_rsp_0x28 = '\x48\x83\xec\x28';
    code.mov_rcx = '\x48\xb9';
    code.Arg_1 = (DWORD64)nOffset;
    code.call_FF15 = '\xff\x15';
    code.call_offset = 2;
    code.jmp_8 = '\xeb\x08';
    code.pLoadLibraryA = (DWORD64)LoadLibraryA;
    code.add_rsp_0x28 = '\x48\x83\xc4\x28';
    code.testRax[0] = '\x48';
    code.testRax[1] = '\x85';
    code.testRax[2] = '\xc0';
    code.jmp_6 = '\x75\x06';
    code.Register_eax1 = '\xb8';
    code.nResust1 = 2;
    code.Ret1 = '\xc3';
    code.mov_rcx1 = '\x48\xb9';
    code.pDllBase = ((DWORD64)&code.n - (DWORD64)&code + (DWORD64)pAllocate);
    code.movRcxRax[0] = '\x48';
    code.movRcxRax[1] = '\x89';
    code.movRcxRax[2] = '\x01';
    code.Register_eax2 = '\xb8';
    code.nResust2 = 1;
    code.Ret2 = '\xc3';
#else
    code.push = '\x68';
    code.arg = (DWORD)nOffset;
    code.call = '\xe8';
    code.call_offset = (DWORD)LoadLibraryA - ((DWORD)&code.test_eax - (DWORD)&code + (DWORD)pAllocate);
    code.test_eax = '\x85\xc0';
    code.jne_6 = '\x75\x06';
    code.Register_eax1 = '\xb8';
    code.nResust1 = 2;
    code.Ret1 = '\xc3';

    code.mov_rcx = '\xb9';
    code.pDllBase = ((DWORD)&code.n - (DWORD)&code + (DWORD)pAllocate);
    code.movEcxEax = '\x89\x01';

    code.Register_eax2 = '\xb8';
    code.nResust2 = 1;
    code.Ret2 = '\xc3';
#endif
    RtlCopyMemory((void*)szCode, &code, sizeof(code));

    if (WriteProcessMemory(ProcessHandle, pAllocate, szCode, 0x1000, NULL)) {

        *pDllBase = (PVOID)code.pDllBase;
    }

    return pAllocate;
}
BOOL InjectDll(HANDLE ProcessHandle, const char* szDllPath, PVOID* pDllBase)
{
    BOOL bRet = FALSE;
    HMODULE h = LoadLibraryA(szDllPath);
    if (!h)return FALSE;

    PVOID InitializeVEH = NULL;
    PVOID  ConfigNameOffset = NULL;

    PVOID pTemp = NULL;
    PVOID pAllcoate = CreateInjectCode(ProcessHandle, szDllPath, pDllBase);
    if (pAllcoate)
    {
        HANDLE hRemote = CreateRemoteThread(ProcessHandle, NULL, 0, (LPTHREAD_START_ROUTINE)pAllcoate, NULL, 0, 0);
        if (hRemote)
        {
            DWORD ExitCode = 0;
            WaitForSingleObject(hRemote, 5000);
            if (GetExitCodeThread(hRemote, &ExitCode)) {

                switch (ExitCode)
                {
                case 1:
                {
                    if (ReadProcessMemory(ProcessHandle, *pDllBase, &pTemp, sizeof(ULONG_PTR), NULL)) {
                        *pDllBase = pTemp;

                        InitializeVEH = GetProcAddress(h, "InitializeVEH");
                        ConfigNameOffset = GetProcAddress(h, "ConfigName");
                        if (InitializeVEH && ConfigNameOffset) {

                            if (WriteProcessMemory(ProcessHandle, (PVOID)((ULONG_PTR)ConfigNameOffset - (ULONG_PTR)h + (ULONG_PTR)pTemp), ConfigName,
                                256, NULL))
                            {

                                HANDLE hRemote = CreateRemoteThread(ProcessHandle, NULL, 0, (LPTHREAD_START_ROUTINE)((ULONG_PTR)InitializeVEH - (ULONG_PTR)h + (ULONG_PTR)pTemp),
                                    NULL, 0, 0);
                                if (hRemote) {
                                    bRet = TRUE;
                                    CloseHandle(hRemote);
                                }
                            }
                        }
                    }
                    break;
                }
                case 2:
                {
                    break;
                }
                default:
                    break;
                }
            }


            CloseHandle(hRemote);
        }

        VirtualFreeEx(ProcessHandle, pAllcoate, 0, MEM_FREE);
    }

    FreeLibrary(h);

    return bRet;
}



BOOL InjectEx(HANDLE ProcessHandle, ULONG nPid, const char* szDllPath)
{
    BOOL bRet = FALSE;
    PVOID pImageFileBuffer = NULL;
    DWORD nSizeOfImage = 0;
    PVOID InitializeVEH = NULL;
    PVOID  ConfigNameOffset = NULL;

    typedef PVOID(*t_RtlFindExportedRoutineByName)(PVOID BaseOfImage, char* RoutineName);
    t_RtlFindExportedRoutineByName RtlFindExportedRoutineByName = (t_RtlFindExportedRoutineByName)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlFindExportedRoutineByName");
    if (!RtlFindExportedRoutineByName)return FALSE;
    pImageFileBuffer = file_to_image_buffer(stringToWstring(szDllPath).c_str(), nSizeOfImage);
    if (pImageFileBuffer)
    {
        InitializeVEH = (PVOID)((ULONG_PTR)RtlFindExportedRoutineByName((HMODULE)pImageFileBuffer, "InitializeVEH") - (ULONG_PTR)pImageFileBuffer);
        // ConfigNameOffset = (PVOID)((ULONG_PTR)RtlFindExportedRoutineByName((HMODULE)pImageFileBuffer, "ConfigName") - (ULONG_PTR)pImageFileBuffer);
        ConfigNameOffset = (PVOID)RtlFindExportedRoutineByName((HMODULE)pImageFileBuffer, "ConfigName");
        if (InitializeVEH && ConfigNameOffset)
        {
            RtlCopyMemory(ConfigNameOffset, ConfigName, 256);
            PVOID pAllocateAddress = NULL;
            pAllocateAddress = VirtualAllocEx(ProcessHandle, NULL, nSizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if (!pAllocateAddress || !fixed_image_buffer(pImageFileBuffer, (ULONG_PTR)pAllocateAddress)) {
                goto _End;
            }
            InitializeVEH = (PVOID)((ULONG_PTR)InitializeVEH + (ULONG_PTR)pAllocateAddress);
            // ConfigNameOffset = (PVOID)((ULONG_PTR)ConfigNameOffset + (ULONG_PTR)pAllocateAddress);

            PVOID pAddTable = (PVOID)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlAddFunctionTable");
            if (pAddTable)
            {
                PIMAGE_NT_HEADERS pNtHeaders = NULL;
                PVOID pPEBuffer = pImageFileBuffer;
                PIMAGE_DOS_HEADER       pDosHdr = (PIMAGE_DOS_HEADER)pPEBuffer;
                pNtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)pPEBuffer + pDosHdr->e_lfanew);
                ULONG dirSize = 0;
                ULONG_PTR pExpTable = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
                dirSize = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;

                *(PULONG64)&mapInjectShellcode64[15] = (ULONG_PTR)pAllocateAddress + (ULONG_PTR)pExpTable;

                *(PULONG64)&mapInjectShellcode64[25] = (ULONG_PTR)(dirSize / sizeof(_IMAGE_RUNTIME_FUNCTION_ENTRY));
                *(PULONG64)&mapInjectShellcode64[35] = (ULONG_PTR)pAllocateAddress;
                *(PULONG64)&mapInjectShellcode64[45] = (ULONG_PTR)pAddTable;

                *(PULONG64)&mapInjectShellcode64[0x1c + 50] = (ULONG_PTR)pAllocateAddress;
                *(PULONG64)&mapInjectShellcode64[0x26 + 50] = (ULONG_PTR)pNtHeaders->OptionalHeader.AddressOfEntryPoint + (ULONG_PTR)pAllocateAddress;

                RtlCopyMemory((PVOID*)((ULONG_PTR)pImageFileBuffer + nSizeOfImage - 0x100), mapInjectShellcode64, sizeof(mapInjectShellcode64));

                PVOID shellcodeExcuteAddress = (PVOID)((ULONG_PTR)pAllocateAddress + nSizeOfImage - 0x100);

                RtlFillMemory(pImageFileBuffer, pNtHeaders->OptionalHeader.SizeOfHeaders, 0xcd);
                SIZE_T dwRetSize = 0;

                if (WriteProcessMemory(ProcessHandle, (PVOID)pAllocateAddress, pImageFileBuffer, nSizeOfImage, &dwRetSize))
                {

                    if (RemoteExec(ProcessHandle, nPid, shellcodeExcuteAddress))
                    {
                        bRet = RemoteExec(ProcessHandle, nPid, InitializeVEH);
                    }
                }


            }

        }
    }

_End:
    if (pImageFileBuffer)
    {
        free(pImageFileBuffer);
        pImageFileBuffer = NULL;
    }

    return bRet;
}


BOOL InjectEx_32(HANDLE ProcessHandle, ULONG nPid, const char* szDllPath)
{
    BOOL bRet = FALSE;
    PVOID pImageFileBuffer = NULL;
    DWORD nSizeOfImage = 0;
    PVOID InitializeVEH = NULL;
    PVOID  ConfigNameOffset = NULL;
    DWORD pJmpAddress = NULL;
    UCHAR code[] =
    {
        0x83,0x3d,0,0,0,0,0, //cmp dword ptr[xxx],00   5
        0x75,0x30,           //jne  
        0xff,0x05,0,0,0,0, // inc [xxxxx]
        0x60,               // //pushad
        0x9c,             //pushfd
        0x68,0,0,0,0,   //push 参数1
        0x68,0,0,0,0,   //push 参数1
        0x68,0,0,0,0,   //push 参数1
        0xe8,0,0,0,0,  //call xxxx
        0xe8,0,0,0,0,  //call xxxx
        0x64,0xA1 ,0x30 ,0x00 ,0x00 ,0x00 , //mov eax,fs:[30]
        0xC7 ,0x40 ,0x2C,0,0,0,0,           //mov [eax+0x2c],xxxx
        0x9d,          //popfd
        0x61,          //popad
        0xe9,0,0,0,0 //jmp xxxxx
    };

    typedef PVOID(WINAPI* t_RtlFindExportedRoutineByName)(PVOID BaseOfImage, char* RoutineName);
    t_RtlFindExportedRoutineByName RtlFindExportedRoutineByName = (t_RtlFindExportedRoutineByName)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlFindExportedRoutineByName");
    if (!RtlFindExportedRoutineByName)return FALSE;
    pImageFileBuffer = file_to_image_buffer(stringToWstring(szDllPath).c_str(), nSizeOfImage);
    if (pImageFileBuffer)
    {
        InitializeVEH = (PVOID)((ULONG_PTR)RtlFindExportedRoutineByName((HMODULE)pImageFileBuffer, "InitializeVEH") - (ULONG_PTR)pImageFileBuffer);
        ConfigNameOffset = (PVOID)RtlFindExportedRoutineByName((HMODULE)pImageFileBuffer, "ConfigName");
        if (InitializeVEH && ConfigNameOffset)
        {
            RtlCopyMemory(ConfigNameOffset, ConfigName, 256);
            PVOID pAllocateAddress = NULL;
            pAllocateAddress = VirtualAllocEx(ProcessHandle, NULL, nSizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if (!pAllocateAddress || !fixed_image_buffer(pImageFileBuffer, (ULONG_PTR)pAllocateAddress)) {
                goto _End;
            }
            InitializeVEH = (PVOID)((ULONG_PTR)InitializeVEH + (ULONG_PTR)pAllocateAddress);


            PIMAGE_NT_HEADERS pNtHeaders = NULL;
            PVOID pPEBuffer = pImageFileBuffer;
            PIMAGE_DOS_HEADER       pDosHdr = (PIMAGE_DOS_HEADER)pPEBuffer;
            pNtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)pPEBuffer + pDosHdr->e_lfanew);
            ULONG_PTR nTargetAddress = (ULONG_PTR)pNtHeaders->OptionalHeader.AddressOfEntryPoint + (ULONG_PTR)pAllocateAddress;
            PROCESS_BASIC_INFORMATION pbi = { 0 };
            if (!NT_SUCCESS(NtQueryInformationProcess(ProcessHandle, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr))) {
                goto _End;
            }
            char* dispatch_table_ptr = (char*)pbi.PebBaseAddress + 0x2c;
            char* dispatch_table = nullptr;
            if (!ReadProcessMemory(ProcessHandle, dispatch_table_ptr, &dispatch_table, sizeof(PVOID), nullptr) || !dispatch_table) {
                goto _End;
            }
            char* tab[128] = { 0 };
            SIZE_T lpNumberOfBytesRead = 0;
            if (!ReadProcessMemory(ProcessHandle, dispatch_table, tab, sizeof(tab), &lpNumberOfBytesRead))
            {
                goto _End;
            }



            PVOID pCallAddress = (PVOID)((ULONG_PTR)pImageFileBuffer + nSizeOfImage - 0x100);
            PVOID pCallAddress2 = (PVOID)((ULONG_PTR)pAllocateAddress + nSizeOfImage - 0x100);


            *(PULONG)&code[2] = (ULONG_PTR)pCallAddress2 + 0x50;
            *(PULONG)&code[0xb] = (ULONG_PTR)pCallAddress2 + 0x50;
            *(PULONG)&code[0x12] = (ULONG_PTR)pAllocateAddress;
            *(PULONG)&code[0x17] = (ULONG_PTR)1;
            *(PULONG)&code[0x1c] = (ULONG_PTR)0;
            *(PULONG)&code[0x21] = (ULONG_PTR)nTargetAddress - ((ULONG_PTR)pCallAddress2 + 0x20) - 5;
            *(PULONG)&code[0x26] = (ULONG_PTR)InitializeVEH - ((ULONG_PTR)pCallAddress2 + 0x25) - 5;
            *(PULONG)&code[0x33] = (ULONG_PTR)dispatch_table;
            //0xe9, 0, 0, 0, 0 //jmp xxxxx
            *(PULONG)&code[0x3a] = (ULONG_PTR)tab[2] - ((ULONG_PTR)pCallAddress2 + 0x39) - 5;

            tab[2] = (char*)pCallAddress2;
            RtlCopyMemory(pCallAddress, code, sizeof(code));
            RtlCopyMemory(pImageFileBuffer, tab, sizeof(tab));

            SIZE_T dwRetSize = 0;
            char* fdt = (char*)pAllocateAddress;
            if (WriteProcessMemory(ProcessHandle, (PVOID)pAllocateAddress, pImageFileBuffer, nSizeOfImage, &dwRetSize)
                )
            {
                bRet = WriteProcessMemory(ProcessHandle, dispatch_table_ptr, &fdt, sizeof(PVOID), &lpNumberOfBytesRead);
            }


        }

    }
_End:
    if (pImageFileBuffer)
    {
        free(pImageFileBuffer);
        pImageFileBuffer = NULL;
    }

    return bRet;
}
BOOL injector::Inject(HANDLE ProcessHandle, const char* szDllPath)
{
    BOOL bRet = FALSE;
    ULONG nPid = 0;
    BOOL nInjectEx = FALSE;
    auto p = debugStruct::GetDebugStructPointer();
    if (!p)
    {
        return false;
    }
    nPid = (ULONG)p->nCurDebuggerPid;
    nInjectEx = p->pGui->IsMapInject();
    RtlCopyMemory(ConfigName, p->ConfigName[0], 256);
    
    if (nInjectEx && CheackProcessHaveWnd(nPid))
    {
#ifdef _WIN64
        bRet = InjectEx(ProcessHandle, nPid, szDllPath);
#else
        bRet = InjectEx_32(ProcessHandle, nPid, szDllPath);
#endif
    }
    else {
        PVOID DllBase = NULL;
        bRet = InjectDll(ProcessHandle, szDllPath, &DllBase);
    }
    logs.addLog("Core InjectDll:%d", bRet);

    return bRet;
}
