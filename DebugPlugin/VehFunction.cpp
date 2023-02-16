#include "VehFunction.h"
#include "common.h"
#include "debugStruct.h"
#include <algorithm>
#include "DriverIo.h"
#include "injector.h"
#include "log.h"

DWORD HandleUnexpectedException(DebugStruct* p, DWORD orgContinueStatus);
ULONG hNoExceptionEvent = 0; //标志是否是 异常事件还是其他事件
BOOL VehFunction::IsTargetException(HANDLE hThread)
{
    BOOL bRet = FALSE;
    auto p = debugStruct::GetDebugStructPointer();
    if (!p)return bRet;
    auto pShareMem = p->pShareMem;
    if (!pShareMem)return bRet;
    auto n = ThreadHandleToPid(hThread);
    if (n.UniqueProcess != (HANDLE)pShareMem->DebugEvent.dwProcessId || n.UniqueThread != (HANDLE)pShareMem->DebugEvent.dwThreadId)return bRet;
    __try
    {
        if (pShareMem->DebugEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            bRet = TRUE;
        }
    }
    __except (1)
    {

    }
    return bRet;
}

NTSTATUS VehFunction::VehDebugActiveProcess(HANDLE ProcessHandle, HANDLE DebugObjectHandle)
{
    NTSTATUS ntStaus = STATUS_ACCESS_VIOLATION;
    auto pid = HandleToPid(ProcessHandle);
    if (!pid) return ntStaus;
    if (!debugStruct::InitDebuggerInfo((HANDLE)pid))return ntStaus;

    std::string sz;
    char szbuf[MAX_PATH] = { 0 };
    GetCurrentDirectoryA(MAX_PATH, szbuf);
    if (!strlen(szbuf))return ntStaus;

    sz = szbuf;
    sz = sz + DLL_PATH;

#ifdef _WIN64
    sz = "e:\\release\\x64\\plugins\\vehdebug64.dll";

#else
    sz = "e:\\release\\x32\\plugins\\vehdebug86.dll";
#endif 
  

    auto p = debugStruct::GetDebugStructPointer();
    auto pShareMem = debugStruct::GetDebugStructPointer()->pShareMem;
    strcpy_s(pShareMem->ConfigName[0], p->ConfigName[1]);
    strcpy_s(pShareMem->ConfigName[1], p->ConfigName[2]);
    DuplicateHandle(GetCurrentProcess(), p->HasDebugEvent, p->hCurDebuggerHandle, &pShareMem->HasDebugEvent, 0, false, DUPLICATE_SAME_ACCESS);
    DuplicateHandle(GetCurrentProcess(), p->HasHandledDebugEvent, p->hCurDebuggerHandle, &pShareMem->HasHandledDebugEvent, 0, false, DUPLICATE_SAME_ACCESS);
    DuplicateHandle(GetCurrentProcess(), p->hDevice, p->hCurDebuggerHandle, &pShareMem->hDevice, 0, false, DUPLICATE_SAME_ACCESS);
   
    if (injector::Inject(p->hCurDebuggerHandle, sz.c_str())) {

        pShareMem->veh_debug_active = DriverIo::SetSystemNotify(GetCurrentProcessId(), pid, p->hNotifyEvent);
        ntStaus = 0;
    }
    ntStaus = 0;
    return ntStaus;
}


BOOL VehFunction::VehWaitForDebugEvent(LPDEBUG_EVENT lpDebugEvent, DWORD dwMilliseconds)
{
    BOOL bRet = FALSE;
    auto p = debugStruct::GetDebugStructPointer();
    p->handler_cs.Enter();
    if (!p->m_event.empty())
    {
        RtlCopyMemory(lpDebugEvent, &p->m_event.front(), sizeof(DEBUG_EVENT));
       
        p->m_event.pop_front();
        bRet = TRUE;
        InterlockedExchange(&hNoExceptionEvent, 1);

        p->handler_cs.Leave();

        return bRet;
    }
    p->handler_cs.Leave();


    DWORD nResult = WaitForSingleObject(p->HasDebugEvent, dwMilliseconds);
    if (nResult == WAIT_OBJECT_0)
    {
       
        DriverIo::DbkSuspendProcess((ULONG)lpDebugEvent->dwProcessId, NULL);
        RtlCopyMemory(lpDebugEvent, &p->pShareMem->DebugEvent, sizeof(DEBUG_EVENT));
     
        switch (lpDebugEvent->dwDebugEventCode)
        {
        case EXCEPTION_DEBUG_EVENT:
        {

            switch (lpDebugEvent->u.Exception.ExceptionRecord.ExceptionCode)
            {
            case EXCEPTION_BREAKPOINT:
            {
#ifdef _WIN64
                p->pShareMem->CurrentContext.Rip++;
#else
                p->pShareMem->CurrentContext.Eip++;
#endif 
                break;
            }

            default:
                break;
            }
            break;
        }
        default:
            break;
        }

        bRet = TRUE;
    }


    return bRet;
}
BOOL VehFunction::VehContinueDebugEvent(DWORD dwProcessId, DWORD dwThreadId, DWORD dwContinueStatus)
{
    BOOL bRet = FALSE;
    auto p = debugStruct::GetDebugStructPointer();

    if (InterlockedCompareExchange(&hNoExceptionEvent, 0, 1) == 1)
    {
        p->handler_cs.Enter();
        const auto found  = std::find_if(p->m_SuspendThread.cbegin(), p->m_SuspendThread.cend(), [dwThreadId](const SUSUPENTHREAD_DATA& info) {
            return (dwThreadId == (DWORD)info.nTid);
        });
        if (found != p->m_SuspendThread.cend())
        {
            ResumeThread(found->hThread);
            p->m_SuspendThread.erase(found);
        }

        p->handler_cs.Leave();
        return TRUE;
    }
   

   // logs.addLog("VehContinueDebugEvent: tid:%d  dwContinueStatus:%x", dwThreadId, dwContinueStatus);

    if (p->pShareMem->DebugEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT && p->pShareMem->DebugEvent.dwThreadId == dwThreadId)
    {
        if (dwContinueStatus != DBG_CONTINUE)
        {
            dwContinueStatus = HandleUnexpectedException(p, dwContinueStatus);
        }
        p->pShareMem->dwContinueStatus = dwContinueStatus;
        bRet = SetEvent(p->HasHandledDebugEvent);
        DriverIo::DbkResumeProcess(dwProcessId);
        p->pShareMem->DebugEvent.dwDebugEventCode = 0;
    }
    bRet = TRUE;


    return bRet;
}

DWORD HandleUnexpectedException(DebugStruct* p,DWORD orgContinueStatus)
{
    DWORD dwContinueStatus = orgContinueStatus;

    const auto pShareMem = p->pShareMem;

    switch (pShareMem->DebugEvent.u.Exception.ExceptionRecord.ExceptionCode)
    {

    case STATUS_WX86_SINGLE_STEP:
    case EXCEPTION_SINGLE_STEP:
    {
        //必须接管单步异常
        DR6 dr6;
        dr6.all = pShareMem->CurrentContext.Dr7;
        if (dr6.fields.B0 || dr6.fields.B1 || dr6.fields.B2 || dr6.fields.B3)
        {
            pShareMem->CurrentContext.Dr7 = 0;
        }
        pShareMem->CurrentContext.EFlags |= UE_RESUME_FLAG;
        dwContinueStatus = DBG_CONTINUE;
        break;
    }
    case EXCEPTION_BREAKPOINT:
    {
        ULONG_PTR nExceptionAddress = 0;
#ifdef _WIN64
        nExceptionAddress = (ULONG_PTR)pShareMem->DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress;
        pShareMem->CurrentContext.Rip--;

#else
        nExceptionAddress = (ULONG_PTR)pShareMem->DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress;
        pShareMem->CurrentContext.Eip--;
#endif 

        if (debugStruct::FindRemoveStateRecordException(ExceptionType::eBreakPoint, nExceptionAddress))
        {
            dwContinueStatus = DBG_CONTINUE;
            pShareMem->CurrentContext.EFlags &= ~UE_TRAP_FLAG;
        }
        break;
    }

    default:
        break;
    }




    return dwContinueStatus;
}


BOOL VehFunction::VehSetThreadContext(HANDLE hThread, const CONTEXT* lpContext)
{
    BOOL bRet = FALSE;
    auto p = debugStruct::GetDebugStructPointer();
    if (!p)return bRet;
    if (IsTargetException(hThread))
    {
        __try
        {
            RtlCopyMemory(&p->pShareMem->CurrentContext, lpContext, sizeof(CONTEXT));
            bRet = TRUE;
        }
        __except (1)
        {

        }
        if (lpContext && (lpContext->ContextFlags & CONTEXT_DEBUG_REGISTERS))
        {
            p->dr0 = lpContext->Dr0;
            p->dr1 = lpContext->Dr1;
            p->dr2 = lpContext->Dr2;
            p->dr3 = lpContext->Dr3;
            p->dr6 = lpContext->Dr6;
            p->dr7 = lpContext->Dr7;
        }
    }


    return bRet;
}

BOOL VehFunction::VehGetThreadContext(HANDLE hThread, const CONTEXT* lpContext)
{
    BOOL bRet = FALSE;
    auto p = debugStruct::GetDebugStructPointer();
    if (!p)return bRet;
    if (IsTargetException(hThread))
    {
        __try
        {
            RtlCopyMemory((void*)lpContext, &p->pShareMem->CurrentContext, sizeof(CONTEXT));
            bRet = TRUE;
        }
        __except (1)
        {

        }
    }

    return bRet;
}
