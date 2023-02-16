#include "ioDevice.h"
#include "event_notify.h"
#include "symbol.h"
#include "Function.h"
#include "handleTable.h"
#define  设备名  L"\\Device\\HZW_Debug_Plugin"
#define  符号名  L"\\??\\HZW_Debug_Plugin"
BOOLEAN g_IoState = FALSE;


NTSTATUS DrvClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;



	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DrvCreate(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

namespace ioDevice
{
	NTSTATUS Dispatcher(PDEVICE_OBJECT DeviceObject, PIRP Irp)
	{
		UNREFERENCED_PARAMETER(DeviceObject);
		NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;

		PIO_STACK_LOCATION     irpStack = NULL;

		irpStack = IoGetCurrentIrpStackLocation(Irp);
		ULONG OutputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
		ULONG InputBufferLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;

		switch (irpStack->Parameters.DeviceIoControl.IoControlCode)
		{
		     case  IOCTROL_PLUGIN_Initialize:
		     {
				 __try 
				 {
				
					 PVOID* p = (PVOID*)Irp->AssociatedIrp.SystemBuffer;
					 ntStatus = symbol::InitAllSymbolFunction(p, InputBufferLength / sizeof(PVOID));
				 }
				 __except (1)
				 {
					 ntStatus = GetExceptionCode();
				 }
				 break;
		     }

			 case  IOCTL_Read_PhysicalAddress:
			 {
				 struct input
				 {
					 ULONG64 lpBuffer;         // Buffer address
					 ULONG64 lpBaseAddress;        // Target address
					 ULONG64 nSize;             // Buffer size
					 ULONG64 hProcess;              // Target process id
					 ULONG64 ntStaus;
				 }*pinp;
				 pinp = NULL;
				 pinp = (input*)Irp->AssociatedIrp.SystemBuffer;

				 __try
				 {
					 ntStatus = Function::MmCopyMemoryEx(pinp->hProcess, pinp->lpBaseAddress, pinp->lpBuffer, pinp->nSize);
					 *(PULONG)pinp->ntStaus = ntStatus;
				 }
				 __except (1)
				 {
					 ntStatus = GetExceptionCode();

				 }

				 break;
			 }
			 case  IOCTROL_READ_OR_WRITE:
			 {
				 struct input
				 {
					 ULONG64 lpBuffer;         // Buffer address
					 ULONG64 lpBaseAddress;        // Target address
					 ULONG64 nSize;             // Buffer size
					 ULONG64 hProcess;              // Target process id
					 ULONG64 ntStaus;
					 ULONG64 write;
				 }*pinp;
				 pinp = NULL;
				 pinp = (input*)Irp->AssociatedIrp.SystemBuffer;

				 __try 
				 {
				
					 ntStatus = Function::BBCopyMemory(pinp->hProcess, pinp->lpBaseAddress, pinp->lpBuffer, pinp->nSize, pinp->write);
					 *(PULONG)pinp->ntStaus = ntStatus;
				 }
				 __except (1)
				 {
					 ntStatus = GetExceptionCode();
				 }

				 break;
			 }
			 case IOCTROL_MDL_WRITE_R3:
			 {
				 struct input
				 {
					 ULONG ProcessHandle;
					 ULONG nSize;
					 ULONG64 dwVitruallAddress;
					 ULONG64 pBuffer;
				 }*pinp;
				 pinp = NULL;
				 pinp = (input*)Irp->AssociatedIrp.SystemBuffer;
			
				 __try
				 {
					 ntStatus = Function::MdlForR3(pinp->ProcessHandle, pinp->nSize, pinp->dwVitruallAddress, pinp->pBuffer);
				 }
				 __except (1)
				 {
					 ntStatus = GetExceptionCode();
				 }


				 break;
			 }
			 case IOCTROL_ZwProtectVirtualMemory:
			 {
				 struct input
				 {
					 ULONG64 ProcessHandle;
					 ULONG64 lpAddress;
					 ULONG64 dwSize;
					 ULONG64 flNewProtect;
					 ULONG64 ntStatus;
				 }*pinp;
				 pinp = NULL;
				 pinp = (input*)Irp->AssociatedIrp.SystemBuffer;
	
				 ULONG OldProtect = 0;
				 __try
				 {
					 ntStatus = Function::ReWriteZwProtectVirtualMemory((HANDLE)pinp->ProcessHandle,(PVOID)pinp->lpAddress, pinp->dwSize,(ULONG)pinp->flNewProtect, &OldProtect);
					 if (NT_SUCCESS(ntStatus))
					 {
						 *(PULONG)Irp->AssociatedIrp.SystemBuffer = OldProtect;
					 }
					 *(PULONG)pinp->ntStatus = ntStatus;
				 }
				 __except (1)
				 {
					 ntStatus = GetExceptionCode();
				 }
				 break;
			 }
			 case IOCTROL_ALLOCATE_MEMORY2:
			 {
				 __try
				 {
					 struct input
					 {
						 ULONG64 hProcess;
						 ULONG64 lpAddress;
						 ULONG64 dwSize;
						 ULONG64 flAllocationType;
						 ULONG64 flProtect;
					 }*pinp;
					 pinp = NULL;
					 pinp = (input*)Irp->AssociatedIrp.SystemBuffer;
					 ntStatus = Function::AllcoateMemory((HANDLE)pinp->hProcess, (PVOID)pinp->lpAddress, (ULONG)pinp->dwSize, (ULONG)pinp->flAllocationType,
						 (ULONG)pinp->flProtect,(PVOID*)Irp->AssociatedIrp.SystemBuffer);
				 }
				 __except (1)
				 {
					 ntStatus = GetExceptionCode();
				 }
				 break;
			 }
			 case IOCTROL_OPEN_PROCESS:
			 {
				 __try
				 {
					 struct input
					 {
						 ULONG dwDesiredAccess;
						 ULONG dwProcessId;
					 }*pinp;
					 pinp = NULL;
					 pinp = (input*)Irp->AssociatedIrp.SystemBuffer;

					 ntStatus = Function::ReWriteOpenProcess(pinp->dwDesiredAccess, pinp->dwProcessId, (PHANDLE)Irp->AssociatedIrp.SystemBuffer);

				 }
				 __except (1)
				 {
					 ntStatus = GetExceptionCode();
				 }
				 break;
			 }
			 case IOCTROL_OPEN_THREAD:
			 {
				 __try
				 {
					 struct input
					 {
						 ULONG dwDesiredAccess;
						 ULONG dwThreadId;
					 }*pinp;
					 pinp = NULL;
					 pinp = (input*)Irp->AssociatedIrp.SystemBuffer;

					 ntStatus = Function::ReWriteOpenThread(pinp->dwDesiredAccess, pinp->dwThreadId, (PHANDLE)Irp->AssociatedIrp.SystemBuffer);

				 }
				 __except (1)
				 {
					 ntStatus = GetExceptionCode();
				 }
				 break;
			 }
			 case IOCTL_SUSPENTHREAD_OR_RESUMETHREAD:
			 {
				 __try
				 {
					 struct input
					 {
						 ULONG hThreadHanle;
						 ULONG bSuspend;
					 }*pinp;
					 pinp = NULL;
					 pinp = (input*)Irp->AssociatedIrp.SystemBuffer;

					 ntStatus = Function::SuspendOrResumeThread((HANDLE)pinp->hThreadHanle, (ULONG)pinp->bSuspend, (PULONG)Irp->AssociatedIrp.SystemBuffer);

				 }
				 __except (1)
				 {
					 ntStatus = GetExceptionCode();
				 }
				 break;
			 }
			 case IOCTL_SET_OR_GET_THREAD_CONTEXT:
			 {

				 __try
				 {
					 struct input
					 {
						 ULONG hThreadHanle;
						 ULONG bGet;
						 ULONG64 ThreadContext;
					 }*pinp;
					 pinp = NULL;
					 pinp = (input*)Irp->AssociatedIrp.SystemBuffer;

					 ntStatus = Function::GetOrSetThreadContext((HANDLE)pinp->hThreadHanle, (PCONTEXT)pinp->ThreadContext, (BOOLEAN)pinp->bGet);

				 }
				 __except (1)
				 {
					 ntStatus = GetExceptionCode();
				 }
				 break;
			 }
			 case IOCTROL_ZwDuplicateObject:
			 {
				 struct input
				 {
					 ULONG64 DesiredAccess;
					 ULONG64 HandleAttributes;
					 ULONG64 Options;
					 ULONG64 SourceProcessHandle;
					 ULONG64 SourceHandle;
					 ULONG64 TargetProcessHandle;
				 }*pinp;
				 pinp = NULL;
				 pinp = (input*)Irp->AssociatedIrp.SystemBuffer;

				 __try
				 {
					 ntStatus = Function::ObDuplicateObjectD((HANDLE)pinp->SourceProcessHandle, (HANDLE)pinp->SourceHandle, (HANDLE)pinp->TargetProcessHandle, (PHANDLE)Irp->AssociatedIrp.SystemBuffer,
						 (ACCESS_MASK)pinp->DesiredAccess, (ULONG)pinp->HandleAttributes, (ULONG)pinp->Options);
				 }
				 __except (1)
				 {
					 ntStatus = GetExceptionCode();
				 }


				 break;
			 }
			 case IOCTROL_DBKSUSPENDPROCESS:
			 {
				 struct input
				 {
					 ULONG nPid;
					 ULONG nRecoverTid;
				 }*pinp;
				 pinp = NULL;
				 pinp = (input*)Irp->AssociatedIrp.SystemBuffer;
				 ntStatus = Function::SuspendProcessOrPsResumProcessByPid(pinp->nPid, TRUE);
				 if (NT_SUCCESS(ntStatus))
				 {

					 if (pinp->nRecoverTid) {
						 ULONG nCnt = 0;
						 ntStatus = Function::SuspendOrResumeThreadByPid((HANDLE)pinp->nRecoverTid, FALSE, &nCnt);
					 }
				 }
				 break;
			 }
			 case IOCTROL_DBKRESUMEPROCESS:
			 {
				 struct input
				 {
					 ULONG nPid;
				 }*pinp;
				 pinp = NULL;
				 pinp = (input*)Irp->AssociatedIrp.SystemBuffer;
				 ntStatus = Function::SuspendProcessOrPsResumProcessByPid(pinp->nPid, FALSE);
				 break;
			 }
			 case IOCTROL_HANDLE_TABLE:
			 {
				
				 PHANDLE_GRANT_ACCESS_EX  pinp = (PHANDLE_GRANT_ACCESS_EX)Irp->AssociatedIrp.SystemBuffer;
				 __try
				 {
					 if (pinp->dwTableOffset_EPROCESS > 0x100 && pinp->dwTableOffset_EPROCESS < PAGE_SIZE ) {

						 ntStatus = RestoreObjectAccessEx(pinp);
					 }
				 }
				 __except (1)
				 {
					 ntStatus = GetExceptionCode();
				 }
				 break;
			 }


			 case IOCTROL_SET_SYSTEM_NOTIY:
			 {
				 struct input
				 {
					 ULONG nDebuggerProcessPid;
					 ULONG nWatchPid;
					 ULONG64 hEvent;
				 }*pinp;
				 pinp = NULL;
				 pinp = (input*)Irp->AssociatedIrp.SystemBuffer;

				 static bool b = false;
				 if (!b) 
				 {
					 ntStatus = notify::RegisterNotify();
					 if (NT_SUCCESS(ntStatus))
					 {
						 b = true;
					 }
				 }

				 if (b) {
					 ntStatus = notify::SetNotify(pinp->nDebuggerProcessPid, pinp->nWatchPid, (HANDLE)pinp->hEvent);
				 }

				 break;
			 }

			 case IOCTROL_GET_DEBUGEVENT:
			 {
				 ntStatus = notify::CopyDebugEvent(Irp->AssociatedIrp.SystemBuffer, OutputBufferLength);
				 break;
			 }
			 case IOCTL_ENABLE_DELETE_FILE:
			 {
				 struct input
				 {
					 ULONG64 hFile;
				 }*pinp;
				 pinp = NULL;
				 pinp = (input*)Irp->AssociatedIrp.SystemBuffer;


				 __try {
					 ntStatus = Function::DeleteFile((HANDLE)pinp->hFile);
				 }
				 __except (1) {
					 ntStatus = GetExceptionCode();
				 }

				 break;
			 }
			 case IOCTROL_MDL_WRITE_R0:
			 {
				 struct input
				 {
					 ULONG64  lpBaseAddress;
					 ULONG64 lpBuffer;
					 ULONG64 nSize;
				 }*pinp;
				 pinp = NULL;
				 pinp = (input*)Irp->AssociatedIrp.SystemBuffer;
				 __try
				 {
					 if (MmIsAddressValid((PVOID)pinp->lpBaseAddress) && pinp->nSize)
					 {
						 ProbeForRead((PVOID)pinp->lpBuffer, pinp->nSize, 1);
						 ntStatus = Function::RtlSuperCopyMemoryEx((void*)pinp->lpBaseAddress, (void*)pinp->lpBuffer, (ULONG)pinp->nSize);

						 *(PULONG)Irp->AssociatedIrp.SystemBuffer = ntStatus;
					 }
				 }
				 __except (1)
				 {
					 ntStatus = GetExceptionCode();
				 }

				 break;
			 }


			 default:
				 break;
		}


		Irp->IoStatus.Status = ntStatus; //三环通过 getlasterror() 得到的就是这个值
		if (irpStack)
		{
			if (ntStatus == STATUS_SUCCESS)
				Irp->IoStatus.Information = irpStack->Parameters.DeviceIoControl.OutputBufferLength; //返回给3环多少数据
			else
				Irp->IoStatus.Information = 0;

			IofCompleteRequest(Irp, IO_NO_INCREMENT);
		}
		return ntStatus;

	}
	


	NTSTATUS CreateDevice(IN PDRIVER_OBJECT pDriverObject)
	{
		NTSTATUS status;
		PDEVICE_OBJECT pDevObj;/*用来返回创建设备*/

							   //创建设备名称
		UNICODE_STRING devName;
		UNICODE_STRING symLinkName; // 
		RtlInitUnicodeString(&devName, 设备名);


		//创建设备
		status = IoCreateDevice(pDriverObject, \
			0, \
			& devName, \
			FILE_DEVICE_UNKNOWN, \
			0, TRUE, \
			& pDevObj);
		if (!NT_SUCCESS(status))
		{
			if (status == STATUS_INSUFFICIENT_RESOURCES)
			{
				DbgPrintEx(0, 0, "hzw:资源不足 STATUS_INSUFFICIENT_RESOURCES");
			}
			if (status == STATUS_OBJECT_NAME_EXISTS)
			{
				DbgPrintEx(0, 0, "hzw:指定对象名存在\n");
			}
			if (status == STATUS_OBJECT_NAME_COLLISION)
			{
				DbgPrintEx(0, 0, "hzw:对象名有冲突\n");
			}
			DbgPrintEx(0, 0, "hzw:设备创建失败\n");
			return status;
		}

		pDevObj->Flags |= DO_BUFFERED_IO;

		//创建符号链接

		RtlInitUnicodeString(&symLinkName, 符号名);
		status = IoCreateSymbolicLink(&symLinkName, &devName);
		if (!NT_SUCCESS(status))
		{
			IoDeleteDevice(pDevObj);
			return status;
		}

		g_IoState = TRUE;

		pDriverObject->MajorFunction[IRP_MJ_CLOSE] = DrvClose;
		pDriverObject->MajorFunction[IRP_MJ_CREATE] = DrvCreate;
		pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Dispatcher;

		return STATUS_SUCCESS;
	}

	VOID DeleteDevice(IN PDRIVER_OBJECT pDriverObject)
	{
		if (g_IoState)
		{
			UNICODE_STRING symLinkName = { 0 };
			RtlInitUnicodeString(&symLinkName, 符号名);
			IoDeleteSymbolicLink(&symLinkName);
			IoDeleteDevice(pDriverObject->DeviceObject);
		}
	}
}