#pragma once
#include <ntifs.h>



enum class FunctionType :int
{
	ePsSuspendThread,
	ePsResumeThread,
	eZwProtectVirtualMemory,
	eMiLocateAddress,
	eZwCreateThreadEx,
	eMax,
};

namespace symbol
{

	NTSTATUS InitAllSymbolFunction(PVOID* arryFun, ULONG nDescArrySize);

	PVOID MmGetSymbolRoutineAddress(FunctionType index);
	void FreeSymbolData();
};

