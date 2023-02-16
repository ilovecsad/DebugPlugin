#include "main.h"



HANDLE fm;
char ConfigName[256];

CriticalSectionLock handler_cs;
VEHDebugSharedMem* vehmem;
PVOID exception_handler_handle = NULL;
HANDLE hDevice = NULL;

void WINAPI InitializeVEH()
{
	handler_cs.Init();
	if (!fm && !(fm = OpenFileMappingA(FILE_MAP_ALL_ACCESS, false, ConfigName)))
		return;

	vehmem = (VEHDebugSharedMem*)MapViewOfFile(fm, FILE_READ_ACCESS | FILE_WRITE_ACCESS, 0, 0, 0);
	if (!vehmem) {
		CloseHandle(fm);
		return;
	}
	if (!vehmem->HasDebugEvent) {
		vehmem->HasDebugEvent = OpenEventA(EVENT_MODIFY_STATE, FALSE, vehmem->ConfigName[0]);
	}
	if (!vehmem->HasHandledDebugEvent) {
		vehmem->HasHandledDebugEvent = OpenEventA(EVENT_MODIFY_STATE, FALSE, vehmem->ConfigName[1]);
	}
	if (vehmem && vehmem->HasDebugEvent && vehmem->HasHandledDebugEvent)
	{
		handler_cs.Enter();
		hDevice = vehmem->hDevice;
		exception_handler_handle = AddVectoredExceptionHandler(TRUE, (PVECTORED_EXCEPTION_HANDLER)Handler);
		if (!exception_handler_handle)
		{
			vehmem->veh_debug_active = FALSE;
		}

		handler_cs.Leave();

	}
	CloseHandle(fm);
	fm = 0;

}

LONG WINAPI Handler(LPEXCEPTION_POINTERS ep)
{
	LONG nRet = EXCEPTION_CONTINUE_SEARCH;

	if (ep->ExceptionRecord->ExceptionCode == STATUS_BREAKPOINT || ep->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP) {
		DWORD tid = GetCurrentThreadId();
		nRet = InternalHandler(ep, tid);
	}
	return nRet;
}

/*
若要将控制权返回到发生异常的点，请返回EXCEPTION_CONTINUE_EXECUTION （0xffffffff）。若要继续处理程序搜索，请返回EXCEPTION_CONTINUE_SEARCH （0x0）。

*/
LONG WINAPI InternalHandler(LPEXCEPTION_POINTERS ep, DWORD tid)
{
	LONG result = EXCEPTION_CONTINUE_SEARCH;
	if (!vehmem || !vehmem->veh_debug_active)
		return result;


	DWORD nPid = GetCurrentProcessId();

	//确保只有一个 线程进入
	handler_cs.Enter();
	vehmem->DebugEvent.dwDebugEventCode = EXCEPTION_DEBUG_EVENT;
	vehmem->DebugEvent.dwProcessId = nPid;
	vehmem->DebugEvent.dwThreadId = tid;
	vehmem->DebugEvent.u.Exception.ExceptionRecord.ExceptionCode = ep->ExceptionRecord->ExceptionCode;
	vehmem->DebugEvent.u.Exception.ExceptionRecord.ExceptionFlags = ep->ExceptionRecord->ExceptionFlags;
	vehmem->DebugEvent.u.Exception.ExceptionRecord.ExceptionRecord = ep->ExceptionRecord->ExceptionRecord;
	vehmem->DebugEvent.u.Exception.ExceptionRecord.NumberParameters = ep->ExceptionRecord->NumberParameters;
	vehmem->DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress = ep->ExceptionRecord->ExceptionAddress;
	vehmem->DebugEvent.u.Exception.dwFirstChance = 1;
	for (size_t i = 0; i < ep->ExceptionRecord->NumberParameters; i++) {
		vehmem->DebugEvent.u.Exception.ExceptionRecord.ExceptionInformation[i] = ep->ExceptionRecord->ExceptionInformation[i];
	}

	if (ep->ContextRecord)
	{

		RtlCopyMemory(&vehmem->CurrentContext, ep->ContextRecord, sizeof(CONTEXT));
	}

	if (SetEvent(vehmem->HasDebugEvent))
	{
		DWORD wr;
		do
		{
			wr = WaitForSingleObject(vehmem->HasHandledDebugEvent, 5000);
			if (WAIT_TIMEOUT == wr && vehmem->veh_debug_active == FALSE) {
				break;
			}
		} while (wr == WAIT_TIMEOUT);
		if (wr == WAIT_OBJECT_0)
		{
			if (ep->ContextRecord)
			{
				RtlCopyMemory(ep->ContextRecord, &vehmem->CurrentContext, sizeof(CONTEXT));
				//if (vehmem->dwContinueStatus == DBG_CONTINUE)
				//{
				//	vehmem->CurrentContext.ContextFlags = CONTEXT_DEBUG_REGISTERS;
				//	//设置 被调试线程中的上下文环境
				//	SetThreadContext(GetCurrentThread(), &vehmem->CurrentContext);
				//}
			}
		}
		else
		{
			result = EXCEPTION_CONTINUE_EXECUTION;
		}
		if (DBG_CONTINUE == vehmem->dwContinueStatus)
		{
			result = EXCEPTION_CONTINUE_EXECUTION;
		}
	}
	handler_cs.Leave();


	return result;
}

