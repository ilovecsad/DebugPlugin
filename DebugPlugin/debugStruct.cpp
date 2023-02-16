#include "debugStruct.h"
#include <string>
#include "log.h"
#include "common.h"
#include <algorithm>
#include "DriverIo.h"
#include <PSAPI.h>
#include <algorithm>

std::string GuidToString(const GUID& guid)
{
    char buf[64] = { 0 };
    sprintf_s(buf, sizeof(buf),
        "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
        guid.Data1, guid.Data2, guid.Data3,
        guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
        guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
    return std::string(buf);
}
namespace debugStruct {

    BOOL PostFakeProcessAllEventMessages(HANDLE hProcess);
    BOOL ListProcessModulesByPeb(HANDLE hProcess);
    BOOL ListProcessModulesByApi(HANDLE nPid);
    //初始化被调试进程的模块
    bool InitDebuggerProcessModules();
    DWORD GetDebugEventThread(PVOID pArg);
    DebugStruct* g_DebugStruct = nullptr;
    std::vector<RecordException> m_RecordException;

    void RecordExceptionMarkValid(ExceptionType nType, ULONG_PTR nAddress)
    {
        g_DebugStruct->handler_cs.Enter();
        auto found = std::find_if(m_RecordException.begin(), m_RecordException.end(), [nAddress, nType]( RecordException& info) {
            return ((nAddress == info.nExceptionAddress)&& (nType == info.nExceptionType));
            });
        if (found == m_RecordException.end())
        {
            m_RecordException.push_back({ nType ,ExceptionState::eValid,nAddress });
        }
        else 
        {
            found->nState = ExceptionState::eValid;
        }
        g_DebugStruct->handler_cs.Leave();
    }
    void SetExceptionMarkRemove(ExceptionType nType, ULONG_PTR nAddress)
    {
        g_DebugStruct->handler_cs.Enter();
        auto found = std::find_if(m_RecordException.begin(), m_RecordException.end(), [nAddress, nType](RecordException& info) {
            return ((nAddress == info.nExceptionAddress) && (nType == info.nExceptionType));
            });
        if (found != m_RecordException.end())
        {
            found->nState = ExceptionState::eRemove;
        }
        g_DebugStruct->handler_cs.Leave();
    }

    BOOL FindRemoveStateRecordException(ExceptionType nType, ULONG_PTR nAddress)
    {
        
        g_DebugStruct->handler_cs.Enter();
        auto found = std::find_if(m_RecordException.begin(), m_RecordException.end(), [nAddress, nType](RecordException& info) {
            return ((nAddress == info.nExceptionAddress) && (nType == info.nExceptionType));
            });
        if (found != m_RecordException.end() && found->nState == ExceptionState::eRemove)
        {
            g_DebugStruct->handler_cs.Leave();
            return TRUE;

        }
        g_DebugStruct->handler_cs.Leave();

        return FALSE;
    }


    bool InitDebugStruct(PVOID pThis)
    {
        m_RecordException.reserve(0x1000);
        g_DebugStruct = new DebugStruct();
        g_DebugStruct->handler_cs.Init();
        g_DebugStruct->handler_cs.Enter();
        g_DebugStruct->handler_cs.Leave();

        GUID guid[3] = { 0,0,0 };

        for (int i = 0; i < 3; i++) {
            HRESULT h = CoCreateGuid(&guid[i]);
            if (h == S_OK) {
                strcpy(g_DebugStruct->ConfigName[i], GuidToString(guid[i]).c_str());
            }
            else {
                return false;
            }
        }
        HANDLE HasDebugEvent = CreateEventA(NULL, FALSE, FALSE, g_DebugStruct->ConfigName[1]);
        HANDLE HasHandledDebugEvent = CreateEventA(NULL, FALSE, FALSE, g_DebugStruct->ConfigName[2]);
        HANDLE hNotifyEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
        if (!HasDebugEvent || !HasHandledDebugEvent || !hNotifyEvent) {
            return false;
        }
        g_DebugStruct->HasDebugEvent = HasDebugEvent;
        g_DebugStruct->HasHandledDebugEvent = HasHandledDebugEvent;
        g_DebugStruct->hNotifyEvent = hNotifyEvent;
        logs.addLog("HasDebugEvent:%x HasHandledDebugEvent:%x hNotifyEvent:%x\n", HasDebugEvent, HasHandledDebugEvent, hNotifyEvent);

        SECURITY_ATTRIBUTES sa = { 0 };
        SECURITY_DESCRIPTOR sd = { 0 };
        InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
        SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
        sa.bInheritHandle = FALSE;
        sa.lpSecurityDescriptor = &sd;
        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        HANDLE hFileMapping = CreateFileMappingA(INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE, 0, sizeof(VEHDebugSharedMem), g_DebugStruct->ConfigName[0]);
        
        g_DebugStruct->hFileMapping = hFileMapping;
        if (!hFileMapping) {

            CloseHandle(HasDebugEvent);
            CloseHandle(HasHandledDebugEvent);
            CloseHandle(hNotifyEvent);
            return false;
        }
        PVOID  pShareMem = MapViewOfFile(hFileMapping, FILE_MAP_WRITE | FILE_MAP_READ, 0, 0, 0);
        if (!pShareMem) {

            CloseHandle(HasDebugEvent);
            CloseHandle(HasHandledDebugEvent);
            CloseHandle(hNotifyEvent);
            CloseHandle(hFileMapping);
            return false;
        }
        RtlZeroMemory(pShareMem, sizeof(VEHDebugSharedMem));
        g_DebugStruct->pShareMem = (PVEHDebugSharedMem)pShareMem;
        strcpy(g_DebugStruct->pShareMem->ConfigName[0], g_DebugStruct->ConfigName[1]);
        strcpy(g_DebugStruct->pShareMem->ConfigName[1], g_DebugStruct->ConfigName[2]);
        HANDLE hGetDebugEventThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)GetDebugEventThread, g_DebugStruct, 0, NULL);
        g_DebugStruct->hGetDebugEventThread = hGetDebugEventThread;
        g_DebugStruct->pGui = (gui*)pThis;
        return true;
    }

    bool InitDebuggerProcessModules()
    {
        m_RecordException.clear();
        g_DebugStruct->m_moduleInfo.clear();
        bool bRet = false;
        switch (g_DebugStruct->pGui->GetEnumModuleTypes())
        {
        case eApi:
        {
            bRet = ListProcessModulesByApi(g_DebugStruct->nCurDebuggerPid);
            break;
        }
        case ePeb:
        {
            bRet = ListProcessModulesByPeb(g_DebugStruct->hCurDebuggerHandle);
            break;
        }
        case eVad:
        {
           // bRet = ListProcessModulesByVad_fail(hProcess);
            break;
        }
        default:
            break;
        }


        return bRet;
    }

    BOOL GetDebugEvent()
    {
        BOOL bRet = FALSE;
        DEBUG_EVENT event = { 0 };
        if (!g_DebugStruct)return bRet;
        RtlZeroMemory(g_DebugStruct->DebugEvent, sizeof(g_DebugStruct->DebugEvent));
        bRet = DeviceIoControl(g_DebugStruct->hDevice, IOCTROL_GET_DEBUGEVENT,
            nullptr, 0,
            g_DebugStruct->DebugEvent, sizeof(g_DebugStruct->DebugEvent),
            nullptr, nullptr);
        if (bRet)
        {

            for (int i = 0; i < ARRAYSIZE(g_DebugStruct->DebugEvent); i++) {
                if (g_DebugStruct->DebugEvent[i].dwDebugEventCode)
                {
                    event = { 0 };
                    switch (g_DebugStruct->DebugEvent[i].dwDebugEventCode)
                    {
                    case CREATE_THREAD_DEBUG_EVENT:
                    {
                        event.dwDebugEventCode = g_DebugStruct->DebugEvent[i].dwDebugEventCode;
                        event.dwProcessId = g_DebugStruct->DebugEvent[i].dwProcessId;
                        event.dwThreadId = g_DebugStruct->DebugEvent[i].dwThreadId;
                        event.u.CreateThread.hThread = (HANDLE)g_DebugStruct->DebugEvent[i].u.CreateThread.hThread;
                        event.u.CreateThread.lpStartAddress = (LPTHREAD_START_ROUTINE)g_DebugStruct->DebugEvent[i].u.CreateThread.lpStartAddress;
                        if (!event.u.CreateThread.hThread) {
                            event.u.CreateThread.hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, event.dwThreadId);
                        }
                        if (!event.u.CreateThread.lpStartAddress) {
                            event.u.CreateThread.lpStartAddress = (LPTHREAD_START_ROUTINE)GetThreadStartAddress(event.u.CreateThread.hThread);
                        }

                        CONTEXT ct = { 0 };
                        ct.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                        if (g_DebugStruct->dr7) {
                            ct.Dr0 = g_DebugStruct->dr0;
                            ct.Dr1 = g_DebugStruct->dr1;
                            ct.Dr2 = g_DebugStruct->dr2;
                            ct.Dr3 = g_DebugStruct->dr3;
                            ct.Dr6 = g_DebugStruct->dr6;
                            ct.Dr7 = g_DebugStruct->dr7;
                            SetThreadContext(event.u.CreateThread.hThread, &ct);
                        }

                        g_DebugStruct->m_SuspendThread.push_back({ event.u.CreateThread.hThread, (HANDLE)event.dwThreadId });
                        break;
                    }
                    case EXIT_THREAD_DEBUG_EVENT:
                    {
                        event.dwDebugEventCode = g_DebugStruct->DebugEvent[i].dwDebugEventCode;
                        event.dwProcessId = g_DebugStruct->DebugEvent[i].dwProcessId;
                        event.dwThreadId = g_DebugStruct->DebugEvent[i].dwThreadId;
                        event.u.ExitThread.dwExitCode = g_DebugStruct->DebugEvent[i].u.ExitThread.dwExitCode;
                        break;
                    }
                    case LOAD_DLL_DEBUG_EVENT:
                    {
                        WCHAR szBuffer[MAX_PATH * 2] = { 0 };
                        event.dwDebugEventCode = g_DebugStruct->DebugEvent[i].dwDebugEventCode;
                        event.dwProcessId = g_DebugStruct->DebugEvent[i].dwProcessId;
                        event.dwThreadId = g_DebugStruct->DebugEvent[i].dwThreadId;
                        event.u.LoadDll.hFile = (HANDLE)g_DebugStruct->DebugEvent[i].u.LoadDll.hFile;
                        event.u.LoadDll.lpBaseOfDll = (PVOID)g_DebugStruct->DebugEvent[i].u.LoadDll.lpBaseOfDll;

                        if (GetMappedFileNameW(g_DebugStruct->hCurDebuggerHandle, event.u.LoadDll.lpBaseOfDll, szBuffer, sizeof(szBuffer) / sizeof(WCHAR)))
                        {
                            HANDLE hFile = 0;
                            UNICODE_STRING us = { 0 };
                            OBJECT_ATTRIBUTES	oa = { 0 };
                            RtlInitUnicodeString(&us, szBuffer);
                            IO_STATUS_BLOCK io_status = { 0 };
                            InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);

                            NTSTATUS nt = NtCreateFile(&hFile,								// 获得文件句柄
                                GENERIC_READ | SYNCHRONIZE,									// 同步读
                                &oa,														// 文件绝对路径
                                &io_status,
                                NULL,
                                FILE_ATTRIBUTE_NORMAL,
                                FILE_SHARE_READ,
                                FILE_OPEN,
                                FILE_SYNCHRONOUS_IO_NONALERT,
                                NULL,
                                0
                            );

                            if (NT_SUCCESS(nt))
                            {
                                event.u.LoadDll.hFile = hFile;
                            }
                        }


                        break;
                    }
                    default:
                        break;
                    }

                    g_DebugStruct->m_event.push_back(event);

                }
            }

        }
        return bRet;
    }
    DWORD GetDebugEventThread(PVOID pArg)
    {

        auto debug = (DebugStruct*)pArg;

        logs.addLog("EventThread already created");
        HANDLE handles = debug->hNotifyEvent;
        while (1)
        {
            if (debug->bStop) {
                logs.addLog("GetDebugEventThread already stop");
                break;
            }

            DWORD nResult = WaitForSingleObject(handles, 5000);

            if (nResult == WAIT_OBJECT_0)
            {
                debug->handler_cs.Enter();

                GetDebugEvent();

                debug->handler_cs.Leave();
            }



        }

        return 0;
    }

    DebugStruct* GetDebugStructPointer()
    {
        return g_DebugStruct;
    }

    bool InitDebuggerInfo(HANDLE nPid)
    {
        bool bRet = false;
        HANDLE hProcess = 0;
        if (!g_DebugStruct)return bRet;

        //do not close this handle
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)nPid);
        if (!hProcess || hProcess == INVALID_HANDLE_VALUE) {
            return bRet;
        }
        g_DebugStruct->hCurDebuggerHandle = hProcess;
        g_DebugStruct->nCurDebuggerPid = nPid;
        if (InitDebuggerProcessModules() && PostFakeProcessAllEventMessages(hProcess)) {
            bRet = true;
        }
        return bRet;
    }

    void FreeDebugStruct()
    {
        g_DebugStruct->bStop = true;

        WaitForSingleObject(g_DebugStruct->hGetDebugEventThread, 100);
        CloseHandle(g_DebugStruct->HasDebugEvent);
        CloseHandle(g_DebugStruct->HasHandledDebugEvent);
        CloseHandle(g_DebugStruct->hCurDebuggerHandle);
        CloseHandle(g_DebugStruct->hFileMapping);
        CloseHandle(g_DebugStruct->hNotifyEvent);
        CloseHandle(g_DebugStruct->hGetDebugEventThread);
        UnmapViewOfFile(g_DebugStruct->pShareMem);

        if (g_DebugStruct->pGui) {
            g_DebugStruct->pGui->FreeGui();
            delete g_DebugStruct->pGui;
        }

        delete g_DebugStruct;
        g_DebugStruct = nullptr;

    }
    BOOL ListProcessModulesByApi(HANDLE nPid)
    {

        HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
        MODULEENTRY32W me32;

        // Take a snapshot of all modules in the specified process.
        hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, (DWORD)nPid);
        if (hModuleSnap == INVALID_HANDLE_VALUE)
        {
            return(FALSE);
        }

        // Set the size of the structure before using it.
        me32.dwSize = sizeof(MODULEENTRY32);

        // Retrieve information about the first module,
        // and exit if unsuccessful
        if (!Module32First(hModuleSnap, &me32))
        {
            CloseHandle(hModuleSnap);           // clean the snapshot object
            return(FALSE);
        }

        // Now walk the module list of the process,
        // and display information about each module


        do
        {

            g_DebugStruct->m_moduleInfo.push_back(me32);

        } while (Module32Next(hModuleSnap, &me32));

        CloseHandle(hModuleSnap);
        return(TRUE);
    }
    BOOL ListProcessModulesByPeb(HANDLE hProcess)
    {

        BOOL bRet = FALSE;
        PROCESS_BASIC_INFORMATION pbi = { 0 };
        SIZE_T n = 0;
        MODULEENTRY32W dwInfo = { 0 };
        std::wstring szTemp;
        wchar_t sz[256] = { 0 };
        DWORD nPid = 0;
        if (NT_SUCCESS(NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL)))
        {
            nPid = HandleToPid(hProcess);

#ifdef _WIN64
            DWORD64 Ldr64 = 0;
            LIST_ENTRY64 ListEntry64 = { 0 };
            LDR_DATA_TABLE_ENTRY64 LDTE64 = { 0 };
            if (ReadProcessMemory(hProcess, (PVOID64)((ULONG_PTR)pbi.PebBaseAddress + offsetof(PEB64, Ldr)), &Ldr64, sizeof(Ldr64), &n))
            {
                if (ReadProcessMemory(hProcess, (PVOID64)(Ldr64 + offsetof(PEB_LDR_DATA64, InLoadOrderModuleList)), &ListEntry64, sizeof(LIST_ENTRY64), &n))
                {
                    if (ReadProcessMemory(hProcess, (PVOID64)(ListEntry64.Flink), &LDTE64, sizeof(_LDR_DATA_TABLE_ENTRY64), &n))
                    {
                        while (1)
                        {
                            if ((ULONG_PTR)LDTE64.InLoadOrderLinks.Flink == ListEntry64.Flink) break;

                            if (ReadProcessMemory(hProcess, (PVOID64)LDTE64.FullDllName.Buffer, sz, sizeof(sz), &n))
                            {
                                RtlSecureZeroMemory(&dwInfo, sizeof(MODULEENTRY32W));

                                dwInfo.dwSize = sizeof(MODULEENTRY32W);
                                dwInfo.th32ModuleID = 1;
                                dwInfo.th32ProcessID = nPid;
                                dwInfo.GlblcntUsage = 0xFFFF;
                                dwInfo.ProccntUsage = 0xFFFF;
                                dwInfo.modBaseAddr = (BYTE*)LDTE64.DllBase;
                                dwInfo.modBaseSize = LDTE64.SizeOfImage;
                                dwInfo.hModule = (HMODULE)LDTE64.DllBase;

                                szTemp = sz;

                                lstrcpy(dwInfo.szExePath, szTemp.c_str());
                                if (!szTemp.empty())
                                {
                                    int a = szTemp.rfind(L"\\");
                                    if (a != -1)
                                    {
                                        szTemp = szTemp.substr(a + 1, szTemp.length() - a);
                                        lstrcpy(dwInfo.szModule, szTemp.c_str());
                                    }
                                }


                                g_DebugStruct->m_moduleInfo.push_back(dwInfo);
                                bRet = TRUE;
                            }
                            if (!ReadProcessMemory(hProcess, (PVOID64)LDTE64.InLoadOrderLinks.Flink, &LDTE64, sizeof(_LDR_DATA_TABLE_ENTRY64), &n)) break;
                        }
                    }
                }
            }
#define peb_32_offset 0x1000
#else
#define peb_32_offset 0
            DWORD Ldr32 = 0;
            LIST_ENTRY32 ListEntry32 = { 0 };
            LDR_DATA_TABLE_ENTRY32 LDTE32 = { 0 };

            if (ReadProcessMemory(hProcess, (PVOID)((ULONG_PTR)pbi.PebBaseAddress + peb_32_offset + offsetof(PEB32, Ldr)), &Ldr32, sizeof(Ldr32), &n))
            {
                if (ReadProcessMemory(hProcess, (PVOID)(Ldr32 + offsetof(PEB_LDR_DATA32, InLoadOrderModuleList)), &ListEntry32, sizeof(LIST_ENTRY32), &n))
                {
                    if (ReadProcessMemory(hProcess, (PVOID)(ListEntry32.Flink), &LDTE32, sizeof(_LDR_DATA_TABLE_ENTRY32), &n))
                    {
                        while (1)
                        {
                            if (LDTE32.InLoadOrderLinks.Flink == ListEntry32.Flink) break;
                            RtlSecureZeroMemory(sz, sizeof(sz));
                            if (ReadProcessMemory(hProcess, (PVOID)LDTE32.FullDllName.Buffer, sz, sizeof(sz), &n))
                            {
                                RtlSecureZeroMemory(&dwInfo, sizeof(dwInfo));

                                dwInfo.dwSize = sizeof(MODULEENTRY32W);
                                dwInfo.th32ModuleID = 1;
                                dwInfo.th32ProcessID = nPid;
                                dwInfo.GlblcntUsage = 0xFFFF;
                                dwInfo.ProccntUsage = 0xFFFF;
                                dwInfo.modBaseAddr = (BYTE*)LDTE32.DllBase;
                                dwInfo.modBaseSize = LDTE32.SizeOfImage;
                                dwInfo.hModule = (HMODULE)LDTE32.DllBase;

                                szTemp = sz;

                                transform(szTemp.begin(), szTemp.end(), szTemp.begin(), ::tolower);

                                int b = szTemp.rfind(L"system32");
                                if ((HMODULE)LDTE32.SizeOfImage < (HMODULE)0x80000000) {
                                    if (b != -1)
                                    {
                                        szTemp = szTemp.replace(b, lstrlen(L"SysWOW64"), L"SysWOW64");
                                    }
                                }

                                lstrcpy(dwInfo.szExePath, szTemp.c_str());
                                if (!szTemp.empty())
                                {
                                    int a = szTemp.rfind(L"\\");
                                    if (a != -1)
                                    {
                                        szTemp = szTemp.substr(a + 1, szTemp.length() - a);
                                        lstrcpy(dwInfo.szModule, szTemp.c_str());
                                    }
                                }
                                g_DebugStruct->m_moduleInfo.push_back(dwInfo);
                                bRet = TRUE;
                            }
                            if (!ReadProcessMemory(hProcess, (PVOID)LDTE32.InLoadOrderLinks.Flink, &LDTE32, sizeof(_LDR_DATA_TABLE_ENTRY32), &n)) break;
                        }
                    }
                }
            }

#endif
        }
        return bRet;
    }
    BOOL PostFakeProcessAllEventMessages(HANDLE hProcess)
    {
        g_DebugStruct->m_event.clear();
        HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
        THREADENTRY32 te32;
        DWORD hMainThreadId = 0;
        // Take a snapshot of all running threads  
        DWORD dwOwnerPID = 0;
        dwOwnerPID = HandleToPid(hProcess);
        if (!dwOwnerPID)return FALSE;

        HANDLE hFile = 0;
        for (auto it = g_DebugStruct->m_moduleInfo.begin(); it != g_DebugStruct->m_moduleInfo.end(); ++it)
        {
            if (wcsstr(it->szModule, L".exe"))
            {
                hFile = CreateFileW(it->szExePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
                break;
            }
        }
        if (!hFile) return FALSE;

        hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hThreadSnap == INVALID_HANDLE_VALUE)
            return(FALSE);

        // Fill in the size of the structure before using it. 
        te32.dwSize = sizeof(THREADENTRY32);

        // Retrieve information about the first thread,
        // and exit if unsuccessful
        if (!Thread32First(hThreadSnap, &te32))
        {

            CloseHandle(hThreadSnap);          // clean the snapshot object
            return(FALSE);
        }

        // Now walk the thread list of the system,
        // and display information about each thread
        // associated with the specified process
        DEBUG_EVENT event = { 0 };
        static BOOL bFirst = TRUE;
        do
        {
            if (te32.th32OwnerProcessID == dwOwnerPID)
            {
                RtlZeroMemory(&event, sizeof(DEBUG_EVENT));
                if (bFirst)
                {
                    bFirst = FALSE;
                    event.dwDebugEventCode = CREATE_PROCESS_DEBUG_EVENT;
                    event.dwProcessId = dwOwnerPID;
                    event.dwThreadId = te32.th32ThreadID;
                    hMainThreadId = event.dwThreadId;
                    event.u.CreateProcessInfo.hFile = hFile;
                    event.u.CreateProcessInfo.hProcess = g_DebugStruct->hCurDebuggerHandle;
                    event.u.CreateProcessInfo.hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, event.dwThreadId);
                    event.u.CreateProcessInfo.lpBaseOfImage = GetDebuggerProcessModuleBase(NULL);
                    event.u.CreateProcessInfo.fUnicode = 1;
                    g_DebugStruct->m_event.push_back(event);


                }
                else
                {
                    event.dwDebugEventCode = CREATE_THREAD_DEBUG_EVENT;
                    event.dwProcessId = dwOwnerPID;
                    event.dwThreadId = te32.th32ThreadID;
                    event.u.CreateThread.hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, event.dwThreadId);
                    event.u.CreateThread.lpStartAddress = (LPTHREAD_START_ROUTINE)GetThreadStartAddress(event.u.CreateThread.hThread);
                    event.u.CreateProcessInfo.fUnicode = 1;
                    g_DebugStruct->m_event.push_back(event);
                }
            }
        } while (Thread32Next(hThreadSnap, &te32));
        CloseHandle(hThreadSnap);

        for (auto it = g_DebugStruct->m_moduleInfo.begin(); it != g_DebugStruct->m_moduleInfo.end(); ++it)
        {
            if (!wcsstr(it->szModule, L".exe"))
            {
                RtlZeroMemory(&event, sizeof(DEBUG_EVENT));
                event.dwDebugEventCode = LOAD_DLL_DEBUG_EVENT;
                event.dwProcessId = dwOwnerPID;
                event.dwThreadId = hMainThreadId;
                event.u.CreateProcessInfo.fUnicode = 1;
                event.u.LoadDll.hFile = CreateFileW(it->szExePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
                event.u.LoadDll.lpBaseOfDll = it->modBaseAddr;
                g_DebugStruct->m_event.push_back(event);
            }
        }



        bFirst = TRUE;
        return(TRUE);
    }
    PVOID GetDebuggerProcessModuleBase(WCHAR* szModule)
    {

        for (auto it = g_DebugStruct->m_moduleInfo.begin(); it != g_DebugStruct->m_moduleInfo.end(); ++it)
        {
            if (!szModule)
            {
                if (wcsstr(it->szModule, L".exe"))
                {
                    return it->modBaseAddr;
                }
            }
            else {
                if (wcsstr(it->szModule, szModule))
                {
                    return it->modBaseAddr;
                }
            }
        }

        return NULL;
    }
}


