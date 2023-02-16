#pragma once
#include <Windows.h>

#ifdef _WIN64
#define DLL_PATH "\\plugins\\vehdebug64.dll"
#else
#define DLL_PATH "\\plugins\\vehdebug86.dll"
#endif
union DR6
{
    ULONG64 all;
    struct {
        unsigned B0 : 1;
        unsigned B1 : 1;
        unsigned B2 : 1;
        unsigned B3 : 1;
        unsigned Reverted : 9;
        unsigned BD : 1;
        unsigned BS : 1;       //单步异常 BS位会被置1
        unsigned Reverted2 : 17;
    }fields;
};
union DR7
{
    ULONG64 all;
    struct {
        unsigned l0 : 1;         //!< [0] Local Breakpoint Enable 0
        unsigned g0 : 1;         //!< [1] Global Breakpoint Enable 0
        unsigned l1 : 1;         //!< [2] Local Breakpoint Enable 1
        unsigned g1 : 1;         //!< [3] Global Breakpoint Enable 1
        unsigned l2 : 1;         //!< [4] Local Breakpoint Enable 2
        unsigned g2 : 1;         //!< [5] Global Breakpoint Enable 2
        unsigned l3 : 1;         //!< [6] Local Breakpoint Enable 3
        unsigned g3 : 1;         //!< [7] Global Breakpoint Enable 3
        unsigned le : 1;         //!< [8] Local Exact Breakpoint Enable
        unsigned ge : 1;         //!< [9] Global Exact Breakpoint Enable
        unsigned reserved1 : 1;  //!< [10] Always 1
        unsigned rtm : 1;        //!< [11] Restricted Transactional Memory
        unsigned reserved2 : 1;  //!< [12] Always 0
        unsigned gd : 1;         //!< [13] General Detect Enable
        unsigned reserved3 : 2;  //!< [14:15] Always 0
        unsigned rw0 : 2;        //!< [16:17] Read / Write 0
        unsigned len0 : 2;       //!< [18:19] Length 0
        unsigned rw1 : 2;        //!< [20:21] Read / Write 1
        unsigned len1 : 2;       //!< [22:23] Length 1
        unsigned rw2 : 2;        //!< [24:25] Read / Write 2
        unsigned len2 : 2;       //!< [26:27] Length 2
        unsigned rw3 : 2;        //!< [28:29] Read / Write 3
        unsigned len3 : 2;       //!< [30:31] Length 3
    } fields;
};



namespace VehFunction
{
    BOOL IsTargetException(HANDLE hThread);
    NTSTATUS VehDebugActiveProcess(HANDLE ProcessHandle, HANDLE DebugObjectHandle);
    BOOL  VehContinueDebugEvent(
            _In_ DWORD dwProcessId,
            _In_ DWORD dwThreadId,
            _In_ DWORD dwContinueStatus
        );

    BOOL  VehWaitForDebugEvent(
        _Out_ LPDEBUG_EVENT lpDebugEvent,
        _In_ DWORD dwMilliseconds
    );


    //如果函数执行失败了 就执行原始 api
    BOOL VehSetThreadContext(_In_ HANDLE hThread,
        _In_ CONST CONTEXT* lpContext);

    //如果函数执行失败了 就执行原始 api
    BOOL VehGetThreadContext(_In_ HANDLE hThread,
        _In_ CONST CONTEXT* lpContext);

 


}

