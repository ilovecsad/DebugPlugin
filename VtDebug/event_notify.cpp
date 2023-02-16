#include "event_notify.h"
#include "stl.h"
#include "struct.h"
#include "utl.h"
#include "symbol.h"

#define EVENT_MAX 50
struct Event_Info
{
    HANDLE nDebuggerProcessPid = 0; //调试器PID
    HANDLE nWatchPid = 0; //被监控进程的Pid
    PKEVENT DebugEvent = nullptr;  //事件结构体
    ERESOURCE EventlistR;
    std::vector<DEBUG_EVENT_EX> debugEventData;
};

 Event_Info* eventInfo = nullptr;

VOID ThreadNotify( _In_ HANDLE ProcessId,_In_ HANDLE ThreadId,_In_ BOOLEAN Create)
{
    if (KeGetCurrentIrql() == PASSIVE_LEVEL && eventInfo)
    {
        if (ExAcquireResourceExclusiveLite(&eventInfo->EventlistR, TRUE))
        {

            if (eventInfo->nWatchPid && eventInfo->nDebuggerProcessPid && eventInfo->debugEventData.size() < EVENT_MAX)
            {
                DEBUG_EVENT_EX debugEventData = { 0 };
                if (ProcessId == eventInfo->nWatchPid)
                {
                    // PsGetCurrentProcessId 的来源是 创建这个线程的进程，与ProcessId 无关
                    //也就是说 PsGetCurrentProcessId 不一定等于 ProcessId 谨记！！！
                    if (Create)
                    {
                        debugEventData.dwDebugEventCode = CREATE_THREAD_DEBUG_EVENT;
                        debugEventData.dwProcessId = reinterpret_cast<ULONG64>(ProcessId);
                        debugEventData.dwThreadId = reinterpret_cast<ULONG64>(ThreadId);
                        debugEventData.u.CreateThread.hThread = NULL;
                        debugEventData.u.CreateThread.lpStartAddress = NULL;

                        PKTHREAD pNewCreateThread = NULL;
                        if (NT_SUCCESS(PsLookupThreadByThreadId(ThreadId, &pNewCreateThread)))
                        {
                            //暂停线程
                            t_PsSuspendThread PsSuspendThread = (t_PsSuspendThread)symbol::MmGetSymbolRoutineAddress(FunctionType::ePsSuspendThread);
                            if (PsSuspendThread)
                            {
                                NTSTATUS ntStatus;
                                ULONG n = 0;
                                ntStatus = PsSuspendThread(pNewCreateThread, &n);
                            }
                            ObDereferenceObject(pNewCreateThread);
                            pNewCreateThread = NULL;

                        }
                    }
                    else
                    {

                        debugEventData.dwDebugEventCode = EXIT_THREAD_DEBUG_EVENT;
                        debugEventData.dwProcessId = reinterpret_cast<ULONG64>(ProcessId);
                        debugEventData.dwThreadId = reinterpret_cast<ULONG64>(ThreadId);
                        debugEventData.u.ExitThread.dwExitCode = NULL;
                    }
                    eventInfo->debugEventData.push_back(std::move(debugEventData));

                    if (eventInfo->DebugEvent)
                    {
                        KeSetEvent(eventInfo->DebugEvent, 0, FALSE);
                        KeClearEvent(eventInfo->DebugEvent);
                
                    }
                    
                }
            }
        }
        ExReleaseResourceLite(&eventInfo->EventlistR);
    }
}

VOID ImageNotify(_In_opt_ PUNICODE_STRING FullImageName, _In_ HANDLE ProcessId, _In_ PIMAGE_INFO ImageInfo)
{
    UNREFERENCED_PARAMETER(FullImageName);
    if (KeGetCurrentIrql() == PASSIVE_LEVEL && eventInfo)
    {
        if (ExAcquireResourceExclusiveLite(&eventInfo->EventlistR, TRUE))
        {
            if (eventInfo->nWatchPid && eventInfo->nDebuggerProcessPid && eventInfo->debugEventData.size() < EVENT_MAX)
            {

                if (ProcessId == eventInfo->nWatchPid)
                {
                    DEBUG_EVENT_EX debugEventData = { 0 };
                    debugEventData.dwDebugEventCode = LOAD_DLL_DEBUG_EVENT;
                    debugEventData.dwProcessId = reinterpret_cast<ULONG64>(ProcessId);
                    debugEventData.dwThreadId = reinterpret_cast<ULONG64>(PsGetCurrentThreadId());
   
                    debugEventData.u.LoadDll.lpBaseOfDll = (ULONG64)ImageInfo->ImageBase;
                    debugEventData.u.LoadDll.hFile = NULL;
                    debugEventData.u.LoadDll.nImageSize = ImageInfo->ImageSize;
                    eventInfo->debugEventData.push_back(std::move(debugEventData));
                }
            }
        }
        ExReleaseResourceLite(&eventInfo->EventlistR);

    }
}
VOID ProcessNotify(_In_ HANDLE ParentId, _In_ HANDLE ProcessId, _In_ BOOLEAN Create)
{
    UNREFERENCED_PARAMETER(ParentId);
    if (KeGetCurrentIrql() == PASSIVE_LEVEL && eventInfo)
    {
        if (ExAcquireResourceExclusiveLite(&eventInfo->EventlistR, TRUE))
        {
            if (!Create)
            {
                //有意思的步骤 在调用这个函数 之前 他会先ThreadNotify 创建 线程，然后在调用这里
                // 创建线程的原因 估计是要需要线程回收资源
                if (ProcessId == eventInfo->nDebuggerProcessPid || ProcessId == eventInfo->nWatchPid)
                {
                    //调试器 关闭了
                    if (eventInfo->DebugEvent) 
                    {
                        ObDereferenceObject(eventInfo->DebugEvent);
                        eventInfo->DebugEvent = nullptr;
                    }
                    eventInfo->nWatchPid = 0;
                    eventInfo->nDebuggerProcessPid = 0;
                    eventInfo->debugEventData.clear();
                }
            }
        }
        ExReleaseResourceLite(&eventInfo->EventlistR);
    }
}



namespace notify
{
    NTSTATUS RegisterNotify()
    {
        auto nt = STATUS_SUCCESS;
        if (!eventInfo) 
        {
            eventInfo = new Event_Info();

            ExInitializeResourceLite(&eventInfo->EventlistR);
            eventInfo->debugEventData.reserve(EVENT_MAX);

            nt |= PsSetCreateThreadNotifyRoutine(ThreadNotify);
            nt |= PsSetCreateProcessNotifyRoutine(ProcessNotify, FALSE);
            nt |= PsSetLoadImageNotifyRoutine(ImageNotify);
        }

        return nt;
    }



    VOID RemoveNotify()
    {
        PsRemoveCreateThreadNotifyRoutine(ThreadNotify);
        PsSetCreateProcessNotifyRoutine(ProcessNotify, TRUE);
        PsRemoveLoadImageNotifyRoutine(ImageNotify);
        if (eventInfo)
        {
            Uti::Sleep(100);
            ExDeleteResourceLite(&eventInfo->EventlistR);
            delete eventInfo;
            eventInfo = nullptr;
        }
    }



    NTSTATUS SetNotify(ULONG DebuggerProcessPid, ULONG WatchPid, HANDLE hEvent)
    {
        auto nt = STATUS_SUCCESS;
        if (eventInfo)
        {
            if (ExAcquireResourceExclusiveLite(&eventInfo->EventlistR, TRUE)) 
            {
                eventInfo->nDebuggerProcessPid = (HANDLE)DebuggerProcessPid;
                eventInfo->nWatchPid = (HANDLE)WatchPid;
                nt = ObReferenceObjectByHandle((HANDLE)hEvent, EVENT_ALL_ACCESS, *ExEventObjectType, KernelMode, (PVOID*)&eventInfo->DebugEvent, NULL);
            }
            ExReleaseResourceLite(&eventInfo->EventlistR);
        }
        return nt;
    }


    NTSTATUS CopyDebugEvent(PVOID pBuffer, ULONG nSize)
    {
        NTSTATUS nt = STATUS_UNSUCCESSFUL;
        if (eventInfo) 
        {
            if (ExAcquireResourceExclusiveLite(&eventInfo->EventlistR, TRUE)) 
            {
                if ((nSize < (eventInfo->debugEventData.size()* sizeof(DEBUG_EVENT_EX)))|| eventInfo->debugEventData.size() == 0)
                {

                    ExReleaseResourceLite(&eventInfo->EventlistR);
                    return nt;
                }
                __try
                {
                    RtlCopyMemory(pBuffer, eventInfo->debugEventData.data(), eventInfo->debugEventData.size() * sizeof(DEBUG_EVENT_EX));
                    eventInfo->debugEventData.clear();
                    nt = STATUS_SUCCESS;
                }
                __except (1)
                {
                    nt = GetExceptionCode();
                }
            }
            ExReleaseResourceLite(&eventInfo->EventlistR);

        }
        return nt;
    }

}


