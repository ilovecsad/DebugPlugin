#pragma once
#include <ntifs.h>

#define EXCEPTION_DEBUG_EVENT       1
#define CREATE_THREAD_DEBUG_EVENT   2
#define CREATE_PROCESS_DEBUG_EVENT  3
#define EXIT_THREAD_DEBUG_EVENT     4
#define EXIT_PROCESS_DEBUG_EVENT    5
#define LOAD_DLL_DEBUG_EVENT        6
#define UNLOAD_DLL_DEBUG_EVENT      7
#define OUTPUT_DEBUG_STRING_EVENT   8
#define RIP_EVENT                   9


typedef struct _CREATE_THREAD_EVENT_ {
    ULONG64 hThread;
    ULONG64 lpStartAddress;
} CREATE_THREAD_EVENT, * PCREATE_THREAD_EVENT;


typedef struct _EXIT_THREAD_EVENT_ {
    ULONG dwExitCode;
} EXIT_THREAD_EVENT, * PEXIT_THREAD_EVENT;


typedef struct _LOAD_DLL_EVENT_ {
    ULONG64 hFile;
    ULONG64 lpBaseOfDll;
    ULONG64 nImageSize;
} LOAD_DLL_EVENT, * PLOAD_DLL_EVENT;

typedef struct _UNLOAD_DLL_EVENT_ {
    ULONG64 lpBaseOfDll;
} UNLOAD_DLL_EVENT, * PUNLOAD_DLL_EVENT;

typedef struct _DEBUG_EVENT_EX {
    ULONG dwDebugEventCode;
    ULONG64 dwProcessId;
    ULONG64 dwThreadId;
    union {

        CREATE_THREAD_EVENT CreateThread;
        EXIT_THREAD_EVENT ExitThread;
        LOAD_DLL_EVENT LoadDll;
    } u;
} DEBUG_EVENT_EX, * PDEBUG_EVENT_EX;

//通过系统回调 获取 创建/销毁线程消息  获取模块信息

namespace notify
{
    /// <summary>
    /// 注册系统回调
    /// </summary>
    /// <returns></returns>
    NTSTATUS RegisterNotify();
    /// <summary>
    /// 移除系统回调
    /// </summary>
    VOID RemoveNotify();
    /// <summary>
    /// 
    /// </summary>
    /// <param name="DebuggerProcessPid"></param>调试器pid
    /// <param name="WatchPid"></param>被调试进程的pid
    /// <param name="hEvent"></param>事件句柄
    /// <returns></returns>
    NTSTATUS SetNotify(ULONG DebuggerProcessPid, ULONG WatchPid, HANDLE hEvent);
    /// <summary>
    /// 拷贝事件到三环
    /// </summary>
    /// <param name="pBuffer"></param>
    /// <param name="nSize"></param>
    /// <returns></returns>
    NTSTATUS CopyDebugEvent(PVOID pBuffer, ULONG nSize);

};

