#pragma once
#include <ntifs.h>

typedef struct _EXHANDLE
{
	union
	{
		struct
		{
			ULONG32 TagBits : 2;
			ULONG32 Index : 30;
		}u;
		HANDLE GenericHandleOverlay;
		ULONG_PTR Value;
	};
} EXHANDLE, * PEXHANDLE;

typedef struct _MY_OBJECT_TYPE                   // 12 elements, 0xD8 bytes (sizeof) 
{
	/*0x000*/     struct _LIST_ENTRY TypeList;              // 2 elements, 0x10 bytes (sizeof)  
	/*0x010*/     struct _UNICODE_STRING Name;              // 3 elements, 0x10 bytes (sizeof)  
	/*0x020*/     VOID* DefaultObject;
	/*0x028*/     UINT8        Index;
	/*0x029*/     UINT8        _PADDING0_[0x3];
	/*0x02C*/     ULONG32      TotalNumberOfObjects;
	/*0x030*/     ULONG32      TotalNumberOfHandles;
	/*0x034*/     ULONG32      HighWaterNumberOfObjects;
	/*0x038*/     ULONG32      HighWaterNumberOfHandles;
}MY_OBJECT_TYPE, * PMY_OBJECT_TYPE;


#define HANDLE_VALUE_INC 4

#define TABLE_PAGE_SIZE	PAGE_SIZE
#define LOWLEVEL_COUNT (TABLE_PAGE_SIZE / sizeof(HANDLE_TABLE_ENTRY))
#define MIDLEVEL_COUNT (PAGE_SIZE / sizeof(PHANDLE_TABLE_ENTRY))

#define LEVEL_CODE_MASK 3


////////////////////////////////////////////////////////////////////////////////////////////////////

typedef struct _HANDLE_TABLE_ENTRY
{
	union
	{
		LONG_PTR VolatileLowValue;
		LONG_PTR LowValue;
		PVOID InfoTable;
		LONG_PTR RefCountField;
		struct
		{
			ULONG_PTR Unlocked : 1;
			ULONG_PTR RefCnt : 16;
			ULONG_PTR Attributes : 3;
			ULONG_PTR ObjectPointerBits : 44;
		}u;
	};
	union
	{
		LONG_PTR HighValue;
		struct _HANDLE_TABLE_ENTRY* NextFreeHandleEntry;
		EXHANDLE LeafHandleValue;
		struct
		{
			ULONG32 GrantedAccessBits : 25;
			ULONG32 NoRightsUpgrade : 1;
			ULONG32 Spare1 : 6;
		}uu;
		ULONG32 Spare2;
	};
} HANDLE_TABLE_ENTRY, * PHANDLE_TABLE_ENTRY;


typedef struct _HANDLE_TABLE_FREE_LIST
{
	ULONG_PTR FreeListLock;
	PHANDLE_TABLE_ENTRY FirstFreeHandleEntry;
	PHANDLE_TABLE_ENTRY lastFreeHandleEntry;
	LONG32 HandleCount;
	ULONG32 HighWaterMark;
	ULONG32 Reserved[8];
} HANDLE_TABLE_FREE_LIST, * PHANDLE_TABLE_FREE_LIST;


typedef struct _HANDLE_TABLE
{
	ULONG32 NextHandleNeedingPool;
	LONG32 ExtraInfoPages;
	ULONG_PTR TableCode;
	PEPROCESS QuotaProcess;
	LIST_ENTRY HandleTableList;
	ULONG32 UniqueProcessId;
	union
	{
		ULONG32 Flags;
		struct
		{
			BOOLEAN StrictFIFO : 1;
			BOOLEAN EnableHandleExceptions : 1;
			BOOLEAN Rundown : 1;
			BOOLEAN Duplicated : 1;
			BOOLEAN RaiseUMExceptionOnInvalidHandleClose : 1;
		}u;
	};
	ULONG_PTR HandleContentionEvent;
	ULONG_PTR HandleTableLock;
	union
	{
		HANDLE_TABLE_FREE_LIST FreeLists[1];
		BOOLEAN ActualEntry[32];
	};
	PVOID DebugInfo;
} HANDLE_TABLE, * PHANDLE_TABLE;

typedef struct _HANDLE_GRANT_ACCESS_EX
{

	ULONG      dwTargetPid;         // Process ID
	ULONG      access;      // Access flags to grant
	ULONG      dwCurrentPid;
	ULONG      dwTableOffset_EPROCESS;  //¾ä±ú±íÆ«ÒÆ
	ULONG64    hTargetHandle;      // Handle to modify
} HANDLE_GRANT_ACCESS_EX, * PHANDLE_GRANT_ACCESS_EX;

NTSTATUS RestoreObjectAccessEx(PHANDLE_GRANT_ACCESS_EX pInfo);