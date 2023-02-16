#pragma once
#include <cstdint>
#include <windows.h>
#include <tlhelp32.h>

#define STATUS_WX86_SINGLE_STEP 0x4000001E
#define PADDING(type, name, size) union { type name; char name##_padding[size]; }

#define EXCEPTION_NO_HADNLE (ULONG64)(-1)
#define EXCEPTION_HADNLE    (ULONG64)(0x88)
#define UE_TRAP_FLAG (0x100)
#define UE_RESUME_FLAG (0x10000)

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



void WINAPI InitializeVEH();


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

	void Leave()
	{
		LeaveCriticalSection(&cs);
	}
};


LONG  WINAPI Handler(LPEXCEPTION_POINTERS ep);

LONG WINAPI InternalHandler(LPEXCEPTION_POINTERS ep, DWORD tid);