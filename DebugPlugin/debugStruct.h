#pragma once
#include <Windows.h>
#include <vector>
#include <list>
#include <TlHelp32.h>
#include "gui.h"


#define PADDING(type, name, size) union { type name; char name##_padding[size]; }
#define STATUS_WX86_SINGLE_STEP 0x4000001E
#define EXCEPTION_NO_HADNLE (ULONG64)(-1)
#define EXCEPTION_HADNLE    (ULONG64)(0x88)
#define UE_TRAP_FLAG (0x100)
#define UE_RESUME_FLAG (0x10000)

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

typedef struct _SUSUPENTHREAD_DATA_ {
	HANDLE hThread;
	HANDLE nTid;
}SUSUPENTHREAD_DATA, * PSUSUPENTHREAD_DATA;
struct CriticalSectionLock
{
	CRITICAL_SECTION cs;

	void Init()
	{
		InitializeCriticalSection(&cs);
	}

	void Enter()
	{
		EnterCriticalSection(&cs);
	}
	BOOL TryEnter()
	{
		return TryEnterCriticalSection(&cs);
	}

	void Leave()
	{
		LeaveCriticalSection(&cs);
	}
	void UnLoad()
	{
		DeleteCriticalSection(&cs);
	}
};
enum  ModuleTypes :int
{
	eApi,
	ePeb,
	eVad
};
typedef struct _VEHDebugSharedMem_
{
	PADDING(CONTEXT, CurrentContext, 0x1000);
	PADDING(DEBUG_EVENT, DebugEvent, 0x100);
	PADDING(HANDLE, HasDebugEvent, 8); //被调试进程，有异常事件
	PADDING(HANDLE, HasHandledDebugEvent, 8); //调试器 是否处理了这个异常事件
	PADDING(HANDLE, hDevice, 8);
	ULONG veh_debug_active;
	ULONG dwContinueStatus;
	char ConfigName[2][256];
}VEHDebugSharedMem, * PVEHDebugSharedMem;
struct DebugStruct
{
	HANDLE nCurDebuggerPid;       //当前被调试进程的PID
	PVEHDebugSharedMem  pShareMem;      //指向共享内存 VEHDebugSharedMem*
	HANDLE hCurDebuggerHandle;    //当前被调试进程的句柄
	HANDLE hFileMapping;  //共享内存的句柄
	HANDLE HasDebugEvent; //被调试进程，有异常事件
	HANDLE HasHandledDebugEvent;//调试器 是否处理了这个异常事件
	HANDLE hGetDebugEventThread;//获取 创建/销毁线程 模块加载的线程句柄
	HANDLE hNotifyEvent;           //事件 :用于 通知 hGetDebugEventThread 线程读取 事件
	HANDLE hDevice;              //驱动句柄
	gui* pGui;
	std::list<DEBUG_EVENT> m_event; //保存所有的事件(线程创建/销毁,异常等事件)
	std::list<MODULEENTRY32W> m_moduleInfo;//只是单纯在 DebugActiveProcess 保持 被调试进程的所有模块信息 
	std::list<SUSUPENTHREAD_DATA> m_SuspendThread; //保存新建线程
	CriticalSectionLock handler_cs; //锁
	bool bStop;
	char ConfigName[3][256]; //
	DEBUG_EVENT_EX DebugEvent[100] = { 0 }; //一个全局变量，用来保存内核 线程/模块回调 的信息
	ULONG_PTR dr0 = 0;
	ULONG_PTR dr1 = 0;
	ULONG_PTR dr2 = 0;
	ULONG_PTR dr3 = 0;
	ULONG_PTR dr6 = 0;
	ULONG_PTR dr7 = 0;
};

enum  class ExceptionType :int
{
	eBreakPoint,
	eHardWare,
	eMemoryVilation,
	eMax
};
enum class ExceptionState :int
{
	eValid,
	eRemove,
	eMax
};

struct RecordException
{
	ExceptionType nExceptionType;
	ExceptionState nState;
	ULONG_PTR nExceptionAddress;
};

namespace debugStruct
{
	bool InitDebugStruct(PVOID pThis);
	DebugStruct* GetDebugStructPointer();
	bool InitDebuggerInfo(HANDLE nPid);
	PVOID GetDebuggerProcessModuleBase(WCHAR* szModule);
	void FreeDebugStruct();
	void RecordExceptionMarkValid(ExceptionType nType, ULONG_PTR nAddress);
	void SetExceptionMarkRemove(ExceptionType nType, ULONG_PTR nAddress);
	BOOL FindRemoveStateRecordException(ExceptionType nType, ULONG_PTR nAddress);
}

