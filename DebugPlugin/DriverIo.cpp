#include "DriverIo.h"
#include "debugStruct.h"
#include "log.h"
#include <winternl.h>
#include "driver.h"

constexpr bool IsX64() {
#if defined(_AMD64_)
	return true;
#else
	return false;
#endif
}
namespace DriverIo
{
	static driver* m_pLoad_my_driver = NULL;
	HANDLE hDevice = 0;
	ULONG m_ObjectTableOffset = 0;
	BOOL InstallDriver()
	{
		BOOL bRet = FALSE;

		//hDevice = CreateFileW(ÎÒµÄÇý¶¯Á´½Ó, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		//if (!hDevice || hDevice == INVALID_HANDLE_VALUE) {
		//	return bRet;
		//}
		m_pLoad_my_driver = new driver;
		hDevice = m_pLoad_my_driver->Load();

		HANDLE hFile = CreateFileW(
			m_pLoad_my_driver->GetDriverPath().c_str(),
			GENERIC_READ,
			FILE_SHARE_READ,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL);

		ULONG64 hTempFile = (ULONG64)hFile;

		//maybe-> bsod !!!!!!!
		if (DeviceIoControl(hDevice,
			IOCTL_ENABLE_DELETE_FILE, &hTempFile, sizeof(ULONG64), NULL, 0, 0, 0)) {
		}
		CloseHandle(hFile);
		m_pLoad_my_driver->fabricateFile();

		//Record io handle
		auto p = debugStruct::GetDebugStructPointer();
		p->hDevice = hDevice;

		bRet = DeviceIoControl(hDevice, IOCTROL_PLUGIN_Initialize, nFunRva, sizeof(nFunRva), NULL, 0, 0, 0);



		return bRet;
	}

	void UnLoadDriver()
	{
		if (m_pLoad_my_driver) {
			m_pLoad_my_driver->Unload(hDevice);
			delete m_pLoad_my_driver;
			m_pLoad_my_driver = NULL;
		}
	}

	BOOL __stdcall KernelReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead)
	{
		if (!hDevice || hDevice == INVALID_HANDLE_VALUE) return FALSE;

		BOOL bRet = FALSE;

		if (!hProcess || INVALID_HANDLE_VALUE == hProcess || !lpBuffer || !nSize || ((ULONG64)lpBaseAddress < PAGE_SIZE)) return bRet;

		struct Input
		{
			ULONG64 lpBuffer;         // Buffer address
			ULONG64 lpBaseAddress;        // Target address
			ULONG64 nSize;             // Buffer size
			ULONG64 hProcess;              // Target process id
			ULONG64 ntStaus;
		};
		Input in = { 0 };
		in.hProcess = (ULONG64)hProcess;
		in.lpBaseAddress = (ULONG64)lpBaseAddress;
		in.lpBuffer = (ULONG64)lpBuffer;
		in.nSize = (ULONG64)nSize;
		in.ntStaus = (ULONG64)&in.ntStaus;

		bRet = DeviceIoControl(hDevice, IOCTL_Read_PhysicalAddress,
			&in, sizeof(Input),
			nullptr, 0,
			nullptr, nullptr);

		if (bRet)
		{
			if (lpNumberOfBytesRead) {
				*lpNumberOfBytesRead = nSize;
			}
		}

		return bRet;
	}

	BOOL __stdcall KernelWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten)
	{
		if (!hDevice || hDevice == INVALID_HANDLE_VALUE) return FALSE;
		BOOL bRet = FALSE;
		if (!hProcess || !lpBuffer || !nSize || ((ULONG64)lpBaseAddress < 0x1000)) return bRet;
		struct Input
		{
			ULONG64 lpBuffer;         // Buffer address
			ULONG64 lpBaseAddress;        // Target address
			ULONG64 nSize;             // Buffer size
			ULONG64 hProcess;              // Target process id
			ULONG64 ntStaus;
			ULONG64 write;
		};
		Input dwInfo = { 0 };

		dwInfo.lpBuffer = (ULONG64)lpBuffer;
		dwInfo.lpBaseAddress = (ULONG64)lpBaseAddress;
		dwInfo.hProcess = (ULONG64)hProcess;
		dwInfo.lpBuffer = (ULONG64)lpBuffer;
		dwInfo.write = TRUE;
		dwInfo.nSize = nSize;
		dwInfo.ntStaus = (ULONG64)&dwInfo.ntStaus;
#define SYSTEM_ADDRESS_START 0x00007ffffffeffff
		if ((ULONG64)lpBaseAddress < SYSTEM_ADDRESS_START)
		{
			bRet = DeviceIoControl(hDevice, IOCTROL_READ_OR_WRITE,
				&dwInfo, sizeof(Input),
				0, 0,
				nullptr, nullptr);
		}


		if (!bRet && (LONG)dwInfo.ntStaus == STATUS_PARTIAL_COPY) {

			typedef struct _INPUT
			{
				ULONG hProcess;
				ULONG nSize;
				ULONG64 dwVitruallAddress;
				ULONG64 pBuffer;
			}Input;
			Input in = { 0 };
			in.hProcess = (ULONG)hProcess;
			in.nSize = nSize;
			in.pBuffer = (ULONG64)lpBuffer;
			in.dwVitruallAddress = (ULONG64)lpBaseAddress;
			MEMORY_BASIC_INFORMATION mbi;
			if (VirtualQueryEx(hProcess, lpBaseAddress, &mbi, sizeof(MEMORY_BASIC_INFORMATION)) == sizeof(MEMORY_BASIC_INFORMATION))
			{
				if (mbi.AllocationProtect == PAGE_EXECUTE_READ)
				{
					bRet = DeviceIoControl(hDevice, IOCTROL_MDL_WRITE_R3,
						&in, sizeof(Input),
						0, 0,
						nullptr, nullptr);
				}
			}
		}

		if (bRet)
		{
			if (lpNumberOfBytesWritten) {
				*lpNumberOfBytesWritten = nSize;
			}
		}

		return bRet;
	}

	BOOL __stdcall KernelVirtualProtectEx(HANDLE hProcess, PVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
	{
		BOOL bRet = FALSE;
		if (!hProcess || hProcess == INVALID_HANDLE_VALUE || (ULONG64)lpAddress <= 0x1000 || !dwSize
			|| !lpflOldProtect) {
			return bRet;
		}


		struct Input
		{
			ULONG64 ProcessHandle;
			ULONG64 lpAddress;
			ULONG64 dwSize;
			ULONG64 flNewProtect;
			ULONG64 ntStatus;
		};

		Input in = { 0 };
		in.ProcessHandle = (ULONG64)hProcess;
		in.lpAddress = (ULONG64)lpAddress;
		in.dwSize = (ULONG64)dwSize;
		in.flNewProtect = (ULONG64)flNewProtect;
		in.ntStatus = (ULONG64)&in.ntStatus;



		DWORD OldProtect;

		bRet = DeviceIoControl(hDevice, IOCTROL_ZwProtectVirtualMemory,
			&in, sizeof(Input),
			&OldProtect, sizeof(DWORD),
			nullptr, nullptr);

		if (bRet && NT_SUCCESS(in.ntStatus))
		{
			if (lpflOldProtect) {
				*lpflOldProtect = flNewProtect;
			}
		}

		if ((ULONG32)in.ntStatus == STATUS_INVALID_PAGE_PROTECTION)
		{
			bRet = TRUE;
		}

		return bRet;
	}

	PVOID __stdcall KernelVirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
	{
		ULONG64 pAllocateAddress = NULL;
		if (!hProcess || hProcess == INVALID_HANDLE_VALUE || !dwSize)return NULL;
		typedef struct _INPUT
		{
			ULONG64 hProcess;
			ULONG64 lpAddress;
			ULONG64 dwSize;
			ULONG64 flAllocationType;
			ULONG64 flProtect;

		}Input;
		Input inputs = { 0 };
		inputs.hProcess = (ULONG64)hProcess;
		inputs.lpAddress = (ULONG64)lpAddress;
		inputs.dwSize = dwSize;
		inputs.flAllocationType = (ULONG64)flAllocationType;
		inputs.flProtect = (ULONG64)flProtect;

		DeviceIoControl(hDevice, IOCTROL_ALLOCATE_MEMORY2,
			&inputs, sizeof(Input),
			&pAllocateAddress, sizeof(ULONG64),
			nullptr, nullptr);


		return (PVOID)pAllocateAddress;
	}

	HANDLE __stdcall ReWritreOpenProcess(DWORD dwDesiredAccess, DWORD dwProcessId)
	{
		typedef struct _INPUT
		{
			ULONG dwDesiredAccess;
			ULONG dwProcessId;

		}Input;
		Input inputs = { dwDesiredAccess, dwProcessId };
		ULONG64 hHanle = 0;
		DeviceIoControl(hDevice, IOCTROL_OPEN_PROCESS,
			&inputs, sizeof(Input),
			&hHanle, sizeof(ULONG64),
			nullptr, nullptr);

		return (HANDLE)hHanle;
	}

	HANDLE __stdcall ReWritreOpenThread(DWORD dwDesiredAccess, DWORD dwThreadId)
	{
		typedef struct _INPUT
		{
			ULONG dwDesiredAccess;
			ULONG dwThreadId;

		}Input;
		Input inputs = { dwDesiredAccess, dwThreadId };
		ULONG64 hHanle = 0;
		DeviceIoControl(hDevice, IOCTROL_OPEN_THREAD,
			&inputs, sizeof(Input),
			&hHanle, sizeof(ULONG64),
			nullptr, nullptr);

		return (HANDLE)hHanle;
	}

	DWORD __stdcall SuspendOrResumeThread(HANDLE hThread, BOOL Suspend)
	{
		typedef struct _INPUT
		{
			ULONG hThreadHanle;
			ULONG bSuspend;

		}Input;
		Input inputs = { (ULONG)hThread, Suspend };
		ULONG nCnt = 0;
		BOOL bRet = DeviceIoControl(hDevice, IOCTL_SUSPENTHREAD_OR_RESUMETHREAD,
			&inputs, sizeof(Input),
			&nCnt, sizeof(ULONG),
			nullptr, nullptr);

		if (!bRet) {
			return (DWORD)-1;
		}

		return nCnt;
	}

	BOOL __stdcall KernelGetOrSetThreadContext(HANDLE hThread, LPCONTEXT lpContext, BOOL bGet)
	{
		BOOL bRet = FALSE;
		if (!IsX64())return FALSE;
		if (!hThread || hThread == INVALID_HANDLE_VALUE || !lpContext) return bRet;

		typedef struct _INPUT
		{
			ULONG hThreadHanle;
			ULONG bGet;
			ULONG64 ThreadContext;
		}Input;

		Input inputs = { 0 };
		inputs.hThreadHanle = (ULONG)hThread;
		inputs.bGet = bGet;
		inputs.ThreadContext = (ULONG64)lpContext;
		bRet = DeviceIoControl(hDevice, IOCTL_SET_OR_GET_THREAD_CONTEXT,
			&inputs, sizeof(Input),
			nullptr, 0,
			nullptr, nullptr);


		return bRet;
	}

	BOOL __stdcall ObDuplicateObjectD(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options)
	{
		BOOL bRet = FALSE;
		typedef struct _INPUT
		{
			ULONG64 DesiredAccess;
			ULONG64 HandleAttributes;
			ULONG64 Options;
			ULONG64 SourceProcessHandle;
			ULONG64 SourceHandle;
			ULONG64 TargetProcessHandle;
		}Input;

		Input inputs = { 0 };
		inputs.SourceProcessHandle = (ULONG64)SourceProcessHandle;
		inputs.SourceHandle = (ULONG64)SourceHandle;
		inputs.TargetProcessHandle = (ULONG64)TargetProcessHandle;
		inputs.DesiredAccess = (ULONG64)DesiredAccess;
		inputs.HandleAttributes = (ULONG64)HandleAttributes;
		inputs.Options = (ULONG64)Options;


		ULONG64 pTempTargetHandle;
		bRet = DeviceIoControl(hDevice, IOCTROL_ZwDuplicateObject,
			&inputs, sizeof(Input),
			&pTempTargetHandle, sizeof(ULONG64),
			nullptr, nullptr);

		if (bRet)
		{
			if (TargetHandle)
			{
				*TargetHandle = (HANDLE)pTempTargetHandle;
			}
		}


		return bRet;
	}

	BOOL __stdcall raise_ce_handle(DWORD dwPid)
	{

		typedef struct _HANDLE_GRANT_ACCESS_EX
		{

			ULONG      dwTargetPid;         // Process ID
			ULONG      access;      // Access flags to grant
			ULONG      dwCurrentPid;
			ULONG      dwTableOffset_EPROCESS;  //¾ä±ú±íÆ«ÒÆ
			ULONG64    hTargetHandle;      // Handle to modify
		} HANDLE_GRANT_ACCESS_EX, * PHANDLE_GRANT_ACCESS_EX;

		if (!hDevice || !dwPid || hDevice == INVALID_HANDLE_VALUE || !m_ObjectTableOffset) return FALSE;
		BOOL bRet = FALSE;
		if (dwPid == GetCurrentProcessId())return FALSE;
		HANDLE_GRANT_ACCESS_EX dwInfo = { 0 };

		dwInfo.access = 0x1fffff;
		dwInfo.dwCurrentPid = GetCurrentProcessId();
		dwInfo.dwTableOffset_EPROCESS = m_ObjectTableOffset;
		dwInfo.hTargetHandle = 0;
		dwInfo.dwTargetPid = dwPid;


		bRet = DeviceIoControl(hDevice, IOCTROL_HANDLE_TABLE,
			&dwInfo, sizeof(HANDLE_GRANT_ACCESS_EX),
			nullptr, 0,
			nullptr, nullptr);


		return bRet;
	}

	BOOL __stdcall WriteKernelemory(PVOID lpBaseAddress, PVOID lpBuffer, SIZE_T nSize)
	{
		BOOL bRet = FALSE;

		if ((ULONG64)lpBaseAddress < SYSTEM_ADDRESS_START || !lpBuffer || !nSize)return bRet;

		typedef struct _INPUT
		{
			ULONG64  lpBaseAddress;
			ULONG64 lpBuffer;
			ULONG64 nSize;
		}Input;

		Input inputs = { (ULONG64)lpBaseAddress, (ULONG64)lpBuffer ,(ULONG64)nSize };
		bRet = DeviceIoControl(hDevice, IOCTROL_MDL_WRITE_R0,
			&inputs, sizeof(Input),
			nullptr, 0,
			nullptr, nullptr);

		return bRet;
	}

	BOOL SetSystemNotify(ULONG nDebuggerProcessPid, ULONG nWatchPid, HANDLE hEvent)
	{
		BOOL bRet = FALSE;

		typedef struct _INPUT
		{
			ULONG nDebuggerProcessPid;
			ULONG nWatchPid;
			ULONG64 hEvent;
		}Input;

		Input inputs = { nDebuggerProcessPid, nWatchPid ,(ULONG64)hEvent };
		bRet = DeviceIoControl(hDevice, IOCTROL_SET_SYSTEM_NOTIY,
			&inputs, sizeof(Input),
			nullptr, 0,
			nullptr, nullptr);

		return bRet;
	}

	BOOL DbkSuspendProcess(ULONG nPid, ULONG nRecoverTid)
	{
		BOOL bRet = FALSE;

		typedef struct _INPUT
		{
			ULONG nPid;
			ULONG nRecoverTid;
		}Input;

		Input inputs = { nPid, nRecoverTid };
		bRet = DeviceIoControl(hDevice, IOCTROL_DBKSUSPENDPROCESS,
			&inputs, sizeof(Input),
			nullptr, 0,
			nullptr, nullptr);

		return bRet;
	}

	BOOL DbkResumeProcess(ULONG nPid)
	{
		BOOL bRet = FALSE;

		typedef struct _INPUT
		{
			ULONG nPid;
		}Input;

		Input inputs = { nPid };
		bRet = DeviceIoControl(hDevice, IOCTROL_DBKRESUMEPROCESS,
			&inputs, sizeof(Input),
			nullptr, 0,
			nullptr, nullptr);

		return bRet;
	}



	BOOL InitVersonPtr()
	{
		BOOL bRet = FALSE;
		OSVERSIONINFOW ow = { 0 };
		ow.dwOSVersionInfoSize = sizeof(OSVERSIONINFOW);
		if (!GetVersionExW(&ow)) ExitProcess(0);

		logs.addLog("BuildNumber:<%d>", ow.dwBuildNumber);
		m_ObjectTableOffset = 0;
		switch (ow.dwBuildNumber)
		{
		case WINDOWS_10_VERSION_19H1:
		case WINDOWS_10_VERSION_19H2://1909
		{
			m_ObjectTableOffset = 0x418; /*¾ä±ú±íÆ«ÒÆ Î»ÖÃ*/
			bRet = TRUE;
			break;
		}
		case WINDOWS_10_VERSION_21H2://21h2
		case WINDOWS_10_VERSION_22H2://21h2
		{
			m_ObjectTableOffset = 0x570; /*¾ä±ú±íÆ«ÒÆ Î»ÖÃ*/
			bRet = TRUE;
			break;
		}

		default:
			break;
		}
		return bRet;
	}




}



