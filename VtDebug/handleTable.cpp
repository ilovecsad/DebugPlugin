#include "handleTable.h"
#include "exapi.h"

PHANDLE_TABLE_ENTRY ExpLookupHandleTableEntry(IN PHANDLE_TABLE HandleTable, IN EXHANDLE tHandle)
{
	ULONG_PTR i = 0, j = 0, k = 0;
	ULONG_PTR CapturedTable = 0;
	ULONG TableLevel = 0;
	PHANDLE_TABLE_ENTRY Entry = NULL;
	EXHANDLE Handle;

	PUCHAR TableLevel1 = NULL;
	PUCHAR TableLevel2 = NULL;
	PUCHAR TableLevel3 = NULL;

	ULONG_PTR MaxHandle;



	if (__readcr8() <= APC_LEVEL)
	{

		Handle = tHandle;
		Handle.u.TagBits = 0;

		MaxHandle = *(volatile ULONG*)&HandleTable->NextHandleNeedingPool;
		if (Handle.Value >= MaxHandle)
		{
			return NULL;
		}

		CapturedTable = *(volatile ULONG_PTR*)&HandleTable->TableCode;
		TableLevel = (ULONG)(CapturedTable & LEVEL_CODE_MASK);
		CapturedTable = CapturedTable - TableLevel;

		switch (TableLevel)
		{
		case 0:
		{
			TableLevel1 = (PUCHAR)CapturedTable;

			Entry = (PHANDLE_TABLE_ENTRY)&TableLevel1[Handle.Value *
				(sizeof(HANDLE_TABLE_ENTRY) / HANDLE_VALUE_INC)];

			break;
		}

		case 1:
		{
			TableLevel2 = (PUCHAR)CapturedTable;

			i = Handle.Value % (LOWLEVEL_COUNT * HANDLE_VALUE_INC);
			Handle.Value -= i;
			j = Handle.Value / ((LOWLEVEL_COUNT * HANDLE_VALUE_INC) / sizeof(PHANDLE_TABLE_ENTRY));

			TableLevel1 = (PUCHAR) * (PHANDLE_TABLE_ENTRY*)&TableLevel2[j];
			Entry = (PHANDLE_TABLE_ENTRY)&TableLevel1[i * (sizeof(HANDLE_TABLE_ENTRY) / HANDLE_VALUE_INC)];

			break;
		}

		case 2:
		{
			TableLevel3 = (PUCHAR)CapturedTable;

			i = Handle.Value % (LOWLEVEL_COUNT * HANDLE_VALUE_INC);
			Handle.Value -= i;
			k = Handle.Value / ((LOWLEVEL_COUNT * HANDLE_VALUE_INC) / sizeof(PHANDLE_TABLE_ENTRY));
			j = k % (MIDLEVEL_COUNT * sizeof(PHANDLE_TABLE_ENTRY));
			k -= j;
			k /= MIDLEVEL_COUNT;

			TableLevel2 = (PUCHAR) * (PHANDLE_TABLE_ENTRY*)&TableLevel3[k];
			TableLevel1 = (PUCHAR) * (PHANDLE_TABLE_ENTRY*)&TableLevel2[j];
			Entry = (PHANDLE_TABLE_ENTRY)&TableLevel1[i * (sizeof(HANDLE_TABLE_ENTRY) / HANDLE_VALUE_INC)];

			break;
		}

		default:
			break;
		}

	}
	return Entry;
}

NTSTATUS RestoreObjectAccessEx(PHANDLE_GRANT_ACCESS_EX pInfo)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	PEPROCESS EProcess = NULL;
	ULONG_PTR Handle = 0;
	PHANDLE_TABLE_ENTRY Entry = NULL;
	PVOID Object = NULL;
	PMY_OBJECT_TYPE ObjectType = NULL;

	PHANDLE_TABLE handleTable = NULL;

	WCHAR szProcess[] = { 0x50 ,0x72 ,0x6F ,0x63 ,0x65 ,0x73,0x73,0x00,0x00 };

	WCHAR szThread[] = { 0x54 ,0x68 ,0x72 ,0x65 ,0x61 ,0x64,0x00,0x00 };


	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)pInfo->dwCurrentPid, &EProcess)))
	{
		return Status;
	}



	for (Handle = 0;; Handle += HANDLE_VALUE_INC)
	{

		if (pInfo->hTargetHandle != 0) {
			Handle = pInfo->hTargetHandle;
		}
		handleTable = *(PHANDLE_TABLE*)((PUCHAR)EProcess + pInfo->dwTableOffset_EPROCESS);

		if (!handleTable) {

			Status = STATUS_UNSUCCESSFUL;
			break;
		}


		Entry = ExpLookupHandleTableEntry(handleTable, *(PEXHANDLE)&Handle);
		if (Entry == NULL)
		{
			break;
		}

		*(ULONG_PTR*)&Object = Entry->u.ObjectPointerBits;
		*(ULONG_PTR*)&Object <<= 4;  //为什么左移四位呢？  因为 Entry->ObjectPointerBits 只占44位  要补充到 64
		if (Object == NULL)
		{
			continue;
		}

		*(ULONG_PTR*)&Object |= 0xFFFF000000000000;
		*(ULONG_PTR*)&Object += 0x30;
		ObjectType = (PMY_OBJECT_TYPE)ObGetObjectType(Object);
		if (ObjectType == NULL)
		{
			continue;
		}


		if (wcscmp(ObjectType->Name.Buffer, szProcess) == 0)
		{

			if (PsGetProcessId((PEPROCESS)Object) == (HANDLE)pInfo->dwTargetPid)
			{
				Entry->uu.GrantedAccessBits = pInfo->access;

				Status = STATUS_SUCCESS;

				if (pInfo->hTargetHandle != 0) {
					break;
				}

			}
		}

		if (wcscmp(ObjectType->Name.Buffer, szThread) == 0)
		{

			if (PsGetProcessId((PEPROCESS)Object) == (HANDLE)pInfo->dwTargetPid)
			{

				Entry->uu.GrantedAccessBits = pInfo->access;

				Status = STATUS_SUCCESS;

				//只是对 目标句柄执行提升，然后就退出。否则将对 所有目的进程的句柄，进行提升（包括线程句柄）
				if (pInfo->hTargetHandle != 0) {
					break;
				}
			}
		}


	}
	if (EProcess) {
		ObfDereferenceObject(EProcess);
	}

	return Status;
}