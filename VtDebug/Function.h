#pragma once
#include <ntifs.h>
#define SYSTEM_ADDRESS_START 0x00007ffffffeffff
#define SYSTEM_ADDRESS_START32 0x7fffffff-1
#define PAGE_NOACESS_OR_PAGE_GUARD 0x200000000-1
#define PAGE_ERROR_UNKNOWN         0xffff00000  //ffff00000
typedef struct _MMPTE_HARDWARE            // 18 elements, 0x8 bytes (sizeof)
{
	/*0x000*/     UINT64       Valid : 1;               // 0 BitPosition
	/*0x000*/     UINT64       Dirty1 : 1;              // 1 BitPosition
	/*0x000*/     UINT64       Owner : 1;               // 2 BitPosition
	/*0x000*/     UINT64       WriteThrough : 1;        // 3 BitPosition
	/*0x000*/     UINT64       CacheDisable : 1;        // 4 BitPosition
	/*0x000*/     UINT64       Accessed : 1;            // 5 BitPosition  A 位，access 位，该位被置 1，说明对应的物理页被访问过。
	/*0x000*/     UINT64       Dirty : 1;               // 6 BitPosition  D 位，dirty 位，该位置 1， 说明对应的物理页被写过。如果你以前学过操作系统的话，另外还学过页面置换算法的话，相信这个位你应该知道怎么用。
	/*0x000*/     UINT64       LargePage : 1;           // 7 BitPosition
	/*0x000*/     UINT64       Global : 1;              // 8 BitPosition
	/*0x000*/     UINT64       CopyOnWrite : 1;         // 9 BitPosition
	/*0x000*/     UINT64       Unused : 1;              // 10 BitPosition
	/*0x000*/     UINT64       Write : 1;               // 11 BitPosition
	/*0x000*/     UINT64       PageFrameNumber : 36;    // 12 BitPosition
	/*0x000*/     UINT64       ReservedForHardware : 4; // 48 BitPosition
	/*0x000*/     UINT64       ReservedForSoftware : 4; // 52 BitPosition
	/*0x000*/     UINT64       WsleAge : 4;             // 56 BitPosition
	/*0x000*/     UINT64       WsleProtection : 3;      // 60 BitPosition
	/*0x000*/     UINT64       NoExecute : 1;           // 63 BitPosition
}MMPTE_HARDWARE, * PMMPTE_HARDWARE;

typedef struct _MMPTE         // 1 elements, 0x8 bytes (sizeof)
{
	/*0x000*/     union {
		MMPTE_HARDWARE  Hard;
		ULONG64         Long;
	} u; // 9 elements, 0x8 bytes (sizeof)
}MMPTE, * PMMPTE;

typedef MMPTE PXE, PPE, PDE, PTE;
typedef struct _physical_memory_data_
{
	PXE pxe;
	PPE ppe;
	PDE pde;
	PTE pte;
}physical_memory_data, * pphysical_memory_data;

typedef struct _read_physical_data
{
	PTE pte[0x200];//保存一个pde下的 所有得pte
	physical_memory_data pma;
}read_physical_data, * pread_physical_data;
namespace Function
{
	NTSTATUS mdlWrite(ULONG_PTR SrcAddr, ULONG_PTR DstAddr, ULONG Size);
	NTSTATUS MmCopyMemoryEx(ULONG64 hProcess, ULONG64 lpBaseAddress, ULONG64 lpBuffer, ULONG64 nSize);
	NTSTATUS BBCopyMemory(ULONG64 hProcess, ULONG64 lpBaseAddress, ULONG64 lpBuffer, ULONG64 nSize, ULONG64 write);
	NTSTATUS MdlForR3(ULONG ProcessHandle, ULONG nSize, ULONG64 dwVitruallAddress, ULONG64 pBuffer);
	NTSTATUS ReWriteZwProtectVirtualMemory(HANDLE ProcessHandle, PVOID lpAddress, SIZE_T dwSize, ULONG flNewProtect, PULONG flOldProtect);
	NTSTATUS AllcoateMemory(HANDLE hProcess, PVOID lpAddress, ULONG dwSize, ULONG flAllocationType, ULONG flProtect, PVOID* pRetAllocateAddress);
	NTSTATUS ReWriteOpenProcess(ULONG dwDesiredAccess, ULONG dwProcessId, PHANDLE outHandle);
	NTSTATUS ReWriteOpenThread(ULONG dwDesiredAccess, ULONG dwThreadId, PHANDLE outHandle);
	NTSTATUS SuspendOrResumeThread(HANDLE hThread, ULONG bSuspend, PULONG nCnt);
	NTSTATUS GetOrSetThreadContext(HANDLE hThread, PCONTEXT lpContext, BOOLEAN bGet);
	NTSTATUS ObDuplicateObjectD(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE pTargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options);
	NTSTATUS SuspendProcessOrPsResumProcessByPid(ULONG nPid, ULONG bSuspend);
	NTSTATUS SuspendOrResumeThreadByPid(HANDLE nTid, ULONG bSuspend, PULONG nCnt);
	NTSTATUS RtlSuperCopyMemoryEx(IN VOID UNALIGNED* Destination, IN CONST VOID UNALIGNED* Source, IN ULONG Length);
	//ps：maybe BSOD!!!!
	NTSTATUS DeleteFile(HANDLE FileHandle);
}

