#pragma once
#include <Windows.h>
#include"gui.h"
#define HOOKFN(name) name##Hook
#define ORIGFN(name) name##Orig
#define HOOKARGS(name) HOOKFN(name), &ORIGFN(name)
#define ORIGINAL(name) reinterpret_cast<decltype(HOOKFN(name))*>(ORIGFN(name))



enum  TypeIndex :int
{
	eReWriteReadProcessMemory,
	eReWriteWriteProcessMemory,
	eReWriteVirtualProtectEx,
	eReWriteVirtualAllocEx,
	eReWriteOpenProcess,
	eReWriteOpenThread,
	eReWriteResumeThread,
	eReWriteSuspendThread,
	eReWriteZwDuplicateObject,
	eReWriteGetThreadContext,
	eReWriteSetThreadContext,
	eReWriteNtDebugActiveProcess,
	eReWriteWaitForDebugEvent,
	eReWriteContinueDebugEvent,
	eTypeIndexMax
};

enum  DebugModel :int
{
	eNormal = 0xa,
	eWindowDebugEx,
	eVeh,
};

namespace hook {
	void initHookFunction(std::vector<HookData>& hook);
}

extern HANDLE hDevice;
