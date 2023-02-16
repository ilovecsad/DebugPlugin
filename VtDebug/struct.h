#pragma once
#include <ntifs.h>


 typedef NTSTATUS (NTAPI *t_ZwProtectVirtualMemory)(
	IN HANDLE     ProcessHandle,
	IN PVOID* BaseAddress,
	IN SIZE_T* NumberOfBytesToProtect,
	IN ULONG     NewAccessProtection,
	OUT PULONG     OldAccessProtection
);

 typedef NTSTATUS(__fastcall* t_PsSuspendThread)(PETHREAD  Thread, PULONG a2);
 typedef NTSTATUS(__fastcall* t_PsResumeThread)(PETHREAD  Thread, PULONG a2);
