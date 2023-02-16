#include <ntifs.h>
#include "utl.h"
#include "vm.h"
#include "vtdump.h"
#include "event_notify.h"
#include "ioDevice.h"
#include "symbol.h"
EXTERN_C
{
 NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object,PUNICODE_STRING registry_path);
static DRIVER_UNLOAD DriverpDriverUnload;


}


_Use_decl_annotations_ static void DriverpDriverUnload(PDRIVER_OBJECT driver_object)
{
	UNREFERENCED_PARAMETER(driver_object);
	HYPERPLATFORM_COMMON_DBG_BREAK();

	ioDevice::DeleteDevice(driver_object);
	VM::VmTermination();
	Uti::UtilTermination();
	dump::freeDump();
	notify::RemoveNotify();
	symbol::FreeSymbolData();
}


_Use_decl_annotations_ NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path)
{
	UNREFERENCED_PARAMETER(registry_path);
	auto nt = STATUS_UNSUCCESSFUL;
	ULONG64 a = 0;
	dump::initDump();
	driver_object->DriverUnload = DriverpDriverUnload;

	HYPERPLATFORM_COMMON_DBG_BREAK();

	__try
	{
		__vmx_off();
	}
	__except (1)
	{
		a = GetExceptionCode();
	}
	Log("所有核的vt的情况:%d,a = %x\n", VM::IsStartVt(), a);
	nt = Uti::UtilInitialization(driver_object);
	if (!NT_SUCCESS(nt))return nt;

	//nt = VM::VmInitialization();
	
	a = 0;
	__try
	{
		__vmx_off();
	
	}
	__except (1)
	{
		a = GetExceptionCode();
	}
	nt = ioDevice::CreateDevice(driver_object);

	Log("所有核的vt的情况:%d,a = %x\n", VM::IsStartVt(), a);

	return nt;
}