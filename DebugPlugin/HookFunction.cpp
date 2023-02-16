#include "HookFunction.h"
#include  "minhook/MinHook.h"
#include "DriverIo.h"
#include "debugStruct.h"
#include "VehFunction.h"

void* ORIGFN(ZwDuplicateObject);
void* ORIGFN(ReadProcessMemory);
void* ORIGFN(WriteProcessMemory);
void* ORIGFN(VirtualProtectEx);
void* ORIGFN(VirtualAllocEx);
void* ORIGFN(GetThreadContext);
void* ORIGFN(SetThreadContext);
void* ORIGFN(OpenThread);
void* ORIGFN(OpenProcess);
void* ORIGFN(ResumeThread);
void* ORIGFN(SuspendThread);
void* ORIGFN(NtDebugActiveProcess);
void* ORIGFN(WaitForDebugEvent);
void* ORIGFN(ContinueDebugEvent);



NTSTATUS WINAPI HOOKFN(ZwDuplicateObject)(
	HANDLE      SourceProcessHandle,
	HANDLE      SourceHandle,
	HANDLE      TargetProcessHandle,
	PHANDLE     TargetHandle,
	ACCESS_MASK DesiredAccess,
	ULONG       HandleAttributes,
	ULONG       Options
	)
{
#define STATUS_ACCESS_DENIED             ((NTSTATUS)0xC0000022L)
	NTSTATUS res = ORIGINAL(ZwDuplicateObject)(SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle, DesiredAccess, HandleAttributes, Options);
	if ((res == STATUS_ACCESS_DENIED))
	{
		if (DriverIo::ObDuplicateObjectD(SourceProcessHandle, SourceHandle, TargetProcessHandle, TargetHandle,
			DesiredAccess, HandleAttributes, Options))
		{
			res = 0;
		}
	}

	return res;
}



BOOL WINAPI HOOKFN(ReadProcessMemory)(
	_In_ HANDLE hProcess,
	_In_ LPCVOID lpBaseAddress,
	_Out_writes_bytes_to_(nSize, *lpNumberOfBytesRead) LPVOID lpBuffer,
	_In_ SIZE_T nSize,
	_Out_opt_ SIZE_T* lpNumberOfBytesRead
	)
{
	BOOL bRet = FALSE;

	bRet = DriverIo::KernelReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
	if (!bRet)
	{
		bRet = ORIGINAL(ReadProcessMemory)(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
	}
	return bRet;
}


BOOL
WINAPI HOOKFN(WriteProcessMemory)(
	_In_ HANDLE hProcess,
	_In_ LPVOID lpBaseAddress,
	_In_reads_bytes_(nSize) LPCVOID lpBuffer,
	_In_ SIZE_T nSize,
	_Out_opt_ SIZE_T* lpNumberOfBytesWritten
	)
{
	BOOL bRet = DriverIo::KernelWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
	if (!bRet)
	{
		bRet = ORIGINAL(WriteProcessMemory)(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
	}
	if(bRet && nSize == 1)
	{
		char* p = (char*)lpBuffer;
		char int3 = 0xcc;
		if (p[0] == int3)
		{
			debugStruct::RecordExceptionMarkValid(ExceptionType::eBreakPoint, (ULONG_PTR)lpBaseAddress);
		}
		else {
			debugStruct::SetExceptionMarkRemove(ExceptionType::eBreakPoint, (ULONG_PTR)lpBaseAddress);
		}
	}

	return bRet;
}

BOOL
WINAPI HOOKFN(VirtualProtectEx)(
	_In_ HANDLE hProcess,
	_In_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD flNewProtect,
	_Out_ PDWORD lpflOldProtect
	)
{
	BOOL bRet = FALSE;
	bRet = DriverIo::KernelVirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect);
	if (!bRet)
	{
		bRet = ORIGINAL(VirtualProtectEx)(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect);
	}
	return bRet;
}

LPVOID
WINAPI
HOOKFN(VirtualAllocEx)(
	_In_ HANDLE hProcess,
	_In_opt_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD flAllocationType,
	_In_ DWORD flProtect
	)
{
	PVOID p = nullptr;
	p = DriverIo::KernelVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);

	return p;
	
}


HANDLE
WINAPI
HOOKFN(OpenProcess)(
	_In_ DWORD dwDesiredAccess,
	_In_ BOOL bInheritHandle,
	_In_ DWORD dwProcessId
	)
{
	HANDLE h = 0;
	h = DriverIo::ReWritreOpenProcess(dwDesiredAccess, dwProcessId);
	if (!h)
	{
		h =  ORIGINAL(OpenProcess)(dwDesiredAccess, bInheritHandle, dwProcessId);
	}
	return h;
}

HANDLE
WINAPI
HOOKFN(OpenThread)(
	_In_ DWORD dwDesiredAccess,
	_In_ BOOL bInheritHandle,
	_In_ DWORD dwThreadId
	)
{
	HANDLE h = DriverIo::ReWritreOpenThread(dwDesiredAccess, dwThreadId);
	if (!h)
	{
		h=  ORIGINAL(OpenThread)(dwDesiredAccess, bInheritHandle, dwThreadId);
	}
	return h;
}

DWORD
WINAPI
HOOKFN(SuspendThread)(
	_In_ HANDLE hThread
	)
{
	return DriverIo::SuspendOrResumeThread(hThread, TRUE);
}


DWORD
WINAPI
HOOKFN(ResumeThread)(
	_In_ HANDLE hThread
	)
{

	return DriverIo::SuspendOrResumeThread(hThread, FALSE);
}




BOOL
WINAPI
HOOKFN(GetThreadContext)(
	_In_ HANDLE hThread,
	_Inout_ LPCONTEXT lpContext
	)
{
	auto p = debugStruct::GetDebugStructPointer();

	if (p) 
	{
		switch (p->pGui->GetDebugModels())
		{
		case eNormal:
		{
			break;
		}
		case eWindowDebugEx:
		{
			break;
		}
		case eVeh:
		{
			if (VehFunction::VehGetThreadContext(hThread, lpContext))
			{
				return TRUE;
			}
			break;
		}
		default:
			break;
		}
	}

	BOOL bRet = FALSE;

	bRet = DriverIo::KernelGetOrSetThreadContext(hThread, lpContext, TRUE);
	if (!bRet)
	{
		bRet = ORIGINAL(GetThreadContext)(hThread, lpContext);
	}
	return bRet;

}

BOOL
WINAPI
HOOKFN(SetThreadContext)(
	_In_ HANDLE hThread,
	_Inout_ LPCONTEXT lpContext
	)
{

	auto p = debugStruct::GetDebugStructPointer();

	if (p)
	{
		switch (p->pGui->GetDebugModels())
		{
		case eNormal:
		{
			break;
		}
		case eWindowDebugEx:
		{
			break;
		}
		case eVeh:
		{
			if (VehFunction::VehSetThreadContext(hThread, lpContext))
			{
				return TRUE;
			}
			break;
		}
		default:
			break;
		}
	}

	BOOL bRet = FALSE;

	bRet = DriverIo::KernelGetOrSetThreadContext(hThread, lpContext, FALSE);
	if (!bRet) {
		bRet =  ORIGINAL(SetThreadContext)(hThread, lpContext);
	}
	return bRet;
}




NTSTATUS WINAPI HOOKFN(NtDebugActiveProcess)(HANDLE ProcessHandle, HANDLE DebugObjectHandle)
{

	NTSTATUS nt = STATUS_ACCESS_VIOLATION;


	auto p = debugStruct::GetDebugStructPointer();

	if (p)
	{
		switch (p->pGui->GetDebugModels())
		{
		case eNormal:
		{
			nt = ORIGINAL(NtDebugActiveProcess)(ProcessHandle, DebugObjectHandle);
			break;
		}
		case eWindowDebugEx:
		{
			nt = ORIGINAL(NtDebugActiveProcess)(ProcessHandle, DebugObjectHandle);
			break;
		}
		case eVeh:
		{
			nt = VehFunction::VehDebugActiveProcess(ProcessHandle, DebugObjectHandle);
			break;
		}
		default:
			break;
		}
	}

	return nt;
}

BOOL WINAPI HOOKFN(WaitForDebugEvent)(
	_Out_ LPDEBUG_EVENT lpDebugEvent,
	_In_ DWORD dwMilliseconds
	)
{
	BOOL bRet = FALSE;

	auto p = debugStruct::GetDebugStructPointer();

	if (p)
	{
		switch (p->pGui->GetDebugModels())
		{
		case eNormal:
		{
			bRet = ORIGINAL(WaitForDebugEvent)(lpDebugEvent, dwMilliseconds);
			break;
		}
		case eWindowDebugEx:
		{
			bRet = ORIGINAL(WaitForDebugEvent)(lpDebugEvent, dwMilliseconds);
			break;
		}
		case eVeh:
		{
			bRet = VehFunction::VehWaitForDebugEvent(lpDebugEvent, dwMilliseconds);
			break;
		}
		default:
			break;
		}
	}

	return bRet;
}


BOOL WINAPI HOOKFN(ContinueDebugEvent)(
	_In_ DWORD dwProcessId,
	_In_ DWORD dwThreadId,
	_In_ DWORD dwContinueStatus
	)
{
	BOOL bRet = FALSE;

	auto p = debugStruct::GetDebugStructPointer();

	if (p)
	{
		switch (p->pGui->GetDebugModels())
		{
		case eNormal:
		{
			bRet = ORIGINAL(ContinueDebugEvent)(dwProcessId, dwThreadId, dwContinueStatus);
			break;
		}
		case eWindowDebugEx:
		{
			bRet = ORIGINAL(ContinueDebugEvent)(dwProcessId, dwThreadId, dwContinueStatus);
			break;
		}
		case eVeh:
		{
			bRet = VehFunction::VehContinueDebugEvent(dwProcessId, dwThreadId, dwContinueStatus);
			break;
		}
		default:
			break;
		}
	}

	return bRet;
}



namespace hook {
	void initHookFunction(std::vector<HookData>& hook)
	{
		HMODULE h = GetModuleHandle(L"ntdll.dll");
		PVOID pZwDuplicateObject = nullptr;
		PVOID NtDebugActiveProcess = nullptr;
		pZwDuplicateObject = GetProcAddress(h, "ZwDuplicateObject");
		NtDebugActiveProcess = (PVOID)GetProcAddress(h, "NtDebugActiveProcess");
		if (pZwDuplicateObject && NtDebugActiveProcess)
		{
			HookData n = { 0 };
			MH_Initialize();
			MH_CreateHook(ReadProcessMemory, HOOKARGS(ReadProcessMemory));
			n.bSelect = true;
			n.bHook = false;
			n.pOrgFunc = ReadProcessMemory;
			strcpy_s(n.sz, "ReadProcessMemory");
			hook.push_back(n);


			MH_CreateHook(WriteProcessMemory, HOOKARGS(WriteProcessMemory));
			n.bSelect = true;
			n.bHook = false;
			n.pOrgFunc = WriteProcessMemory;
			strcpy_s(n.sz, "WriteProcessMemory");
			hook.push_back(n);


			MH_CreateHook(VirtualProtectEx, HOOKARGS(VirtualProtectEx));
			n.bSelect = true;
			n.bHook = false;
			n.pOrgFunc = VirtualProtectEx;
			strcpy_s(n.sz, "VirtualProtectEx");
			hook.push_back(n);

			MH_CreateHook(VirtualAllocEx, HOOKARGS(VirtualAllocEx));
			n.bSelect = true;
			n.bHook = false;
			n.pOrgFunc = VirtualAllocEx;
			strcpy_s(n.sz, "VirtualAllocEx");
			hook.push_back(n);

			MH_CreateHook(OpenProcess, HOOKARGS(OpenProcess));
			n.bSelect = true;
			n.bHook = false;
			n.pOrgFunc = OpenProcess;
			strcpy_s(n.sz, "OpenProcess");
			hook.push_back(n);

			MH_CreateHook(OpenThread, HOOKARGS(OpenThread));
			n.bSelect = true;
			n.bHook = false;
			n.pOrgFunc = OpenThread;
			strcpy_s(n.sz, "OpenThread");
			hook.push_back(n);

			MH_CreateHook(ResumeThread, HOOKARGS(ResumeThread));
			n.bSelect = true;
			n.bHook = false;
			n.pOrgFunc = ResumeThread;
			strcpy_s(n.sz, "ResumeThread");
			hook.push_back(n);

			MH_CreateHook(SuspendThread, HOOKARGS(SuspendThread));
			n.bSelect = true;
			n.bHook = false;
			n.pOrgFunc = SuspendThread;
			strcpy_s(n.sz, "SuspendThread");
			hook.push_back(n);


			MH_CreateHook(pZwDuplicateObject, HOOKARGS(ZwDuplicateObject));
			n.bSelect = true;
			n.bHook = false;
			n.pOrgFunc = pZwDuplicateObject;
			strcpy_s(n.sz, "ZwDuplicateObject");
			hook.push_back(n);


			MH_CreateHook(GetThreadContext, HOOKARGS(GetThreadContext));
			n.bSelect = true;
			n.bHook = false;
			n.pOrgFunc = GetThreadContext;
			strcpy_s(n.sz, "GetThreadContext");
			hook.push_back(n);

			MH_CreateHook(SetThreadContext, HOOKARGS(SetThreadContext));
			n.bSelect = true;
			n.bHook = false;
			n.pOrgFunc = SetThreadContext;
			strcpy_s(n.sz, "SetThreadContext");
			hook.push_back(n);

			MH_CreateHook(NtDebugActiveProcess, HOOKARGS(NtDebugActiveProcess));
			n.bSelect = true;
			n.bHook = false;
			n.pOrgFunc = NtDebugActiveProcess;
			strcpy_s(n.sz, "NtDebugActiveProcess");
			hook.push_back(n);

			MH_CreateHook(WaitForDebugEvent, HOOKARGS(WaitForDebugEvent));
			n.bSelect = true;
			n.bHook = false;
			n.pOrgFunc = WaitForDebugEvent;
			strcpy_s(n.sz, "WaitForDebugEvent");
			hook.push_back(n);

			MH_CreateHook(ContinueDebugEvent, HOOKARGS(ContinueDebugEvent));
			n.bSelect = true;
			n.bHook = false;
			n.pOrgFunc = ContinueDebugEvent;
			strcpy_s(n.sz, "ContinueDebugEvent");
			hook.push_back(n);

		}
	}
}