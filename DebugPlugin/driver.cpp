#include "driver.h"
#include "intel_driver_resource.hpp"
#include "nt.hpp"
#include "DriverIo.h"

driver::driver()
{


}

driver::~driver()
{
	
}

HANDLE driver::Load()
{
    srand((unsigned)time(NULL) * GetCurrentThreadId());
	if (IsRunning())
	{
		OutputDebugStringA("hzw:driver:IsRunning!\n");
		return m_driverHanle;
	}

	memset(driver_name, 0, sizeof(driver_name));
	static const char alphanum[] =
		"abcdefghijklmnopqrstuvwxyz"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	int len = rand() % 20 + 10;
	for (int i = 0; i < len; ++i)
		driver_name[i] = alphanum[rand() % (sizeof(alphanum) - 1)];

	std::wstring driver_path = GetDriverPath();
	if (driver_path.empty())
	{
		return INVALID_HANDLE_VALUE;
	}
	_wremove(driver_path.c_str());

	if (!CreateFileFromMemory(driver_path, reinterpret_cast<const char*>(intel_driver_resource::driver), sizeof(intel_driver_resource::driver)))
	{
		return INVALID_HANDLE_VALUE;
	}
	if (!RegisterAndStart(driver_path))
	{
	
		_wremove(driver_path.c_str());
		return INVALID_HANDLE_VALUE;
	}
	
	//检测 是否已经成功加载了 并且 通信了
	// 只给GENERIC_READ 那么 你得驱动只能读 不能写
	HANDLE result = CreateFileW(我的驱动链接, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (!result || result == INVALID_HANDLE_VALUE)
	{

		Unload(result);
		return INVALID_HANDLE_VALUE;
	}

	

    return result;
}

BOOL driver::IsRunning()
{
	const HANDLE file_handle = CreateFileW(我的驱动链接, FILE_ANY_ACCESS, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (file_handle != nullptr && file_handle != INVALID_HANDLE_VALUE)
	{
		m_driverHanle = file_handle;
		return true;
	}
	return false;
}

std::wstring driver::GetDriverPath()
{
	std::wstring temp = GetFullTempPath();
	if (temp.empty())
	{
		return L"";
	}
	return temp + L"\\" + GetDriverNameW();
}

bool driver::fabricateFile()
{
	return CreateFileFromMemory(GetDriverPath().c_str(), reinterpret_cast<const char*>(intel_driver_resource2::driver), sizeof(intel_driver_resource2::driver));
}

std::wstring driver::GetFullTempPath()
{
	wchar_t temp_directory[MAX_PATH + 1] = { 0 };
	const uint32_t get_temp_path_ret = GetTempPathW(sizeof(temp_directory) / 2, temp_directory);
	if (!get_temp_path_ret || get_temp_path_ret > MAX_PATH + 1)
	{
		return L"";
	}
	if (temp_directory[wcslen(temp_directory) - 1] == L'\\')
		temp_directory[wcslen(temp_directory) - 1] = 0x0;

	return std::wstring(temp_directory);
}

std::wstring driver::GetDriverNameW()
{
	std::string t(driver_name);
	std::wstring name(t.begin(), t.end());
	return name;
}

bool driver::CreateFileFromMemory(const std::wstring& desired_file_path, const char* address, size_t size)
{
	std::ofstream file_ofstream(desired_file_path.c_str(), std::ios_base::out | std::ios_base::binary);

	if (!file_ofstream.write(address, size))
	{
		file_ofstream.close();
		return false;
	}

	file_ofstream.close();
	return true;
}

bool driver::RegisterAndStart(const std::wstring& driver_path)
{
	const static DWORD ServiceTypeKernel = 1;
	const std::wstring driver_name = GetDriverNameW();
	const std::wstring servicesPath = L"SYSTEM\\CurrentControlSet\\Services\\" + driver_name;
	const std::wstring nPath = L"\\??\\" + driver_path;

	HKEY dservice;
	LSTATUS status = RegCreateKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str(), &dservice); //Returns Ok if already exists
	if (status != ERROR_SUCCESS)
	{
		return false;
	}

	status = RegSetKeyValueW(dservice, NULL, L"ImagePath", REG_EXPAND_SZ, nPath.c_str(), (DWORD)(nPath.size() * sizeof(wchar_t)));
	if (status != ERROR_SUCCESS)
	{
		RegCloseKey(dservice);
		return false;
	}

	status = RegSetKeyValueW(dservice, NULL, L"Type", REG_DWORD, &ServiceTypeKernel, sizeof(DWORD));
	if (status != ERROR_SUCCESS)
	{
		RegCloseKey(dservice);
		return false;
	}

	RegCloseKey(dservice);

	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL)
	{
		return false;
	}

	auto RtlAdjustPrivilege = (nt::RtlAdjustPrivilege)GetProcAddress(ntdll, "RtlAdjustPrivilege");
	auto NtLoadDriver = (nt::NtLoadDriver)GetProcAddress(ntdll, "NtLoadDriver");

	ULONG SE_LOAD_DRIVER_PRIVILEGE = 10UL;
	BOOLEAN SeLoadDriverWasEnabled;
	NTSTATUS Status = RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE, &SeLoadDriverWasEnabled);
	if (!NT_SUCCESS(Status))
	{
		
		return false;
	}

	std::wstring wdriver_reg_path = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + driver_name;
	UNICODE_STRING serviceStr;
	RtlInitUnicodeString(&serviceStr, wdriver_reg_path.c_str());

	Status = NtLoadDriver(&serviceStr);

	//Never should occur since kdmapper checks for "IsRunning" driver before
	if (Status == 0xC000010E)
	{// STATUS_IMAGE_ALREADY_LOADED
		return true;
	}

	return NT_SUCCESS(Status);
}

bool driver::Unload(HANDLE device_handle)
{
	if (device_handle && device_handle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(device_handle);
	}

	if (!StopAndRemove(GetDriverNameW()))
		return false;

	std::wstring driver_path = GetDriverPath();

	//Destroy disk information before unlink from disk to prevent any recover of the file
	std::ofstream file_ofstream(driver_path.c_str(), std::ios_base::out | std::ios_base::binary);
	int newFileLen = sizeof(intel_driver_resource::driver) + ((long long)rand() % 2348767 + 56725);
	BYTE* randomData = new BYTE[newFileLen];
	for (size_t i = 0; i < newFileLen; i++)
	{
		randomData[i] = (BYTE)(rand() % 255);
	}
	if (!file_ofstream.write((char*)randomData, newFileLen))
	{
		OutputDebugStringA("hzw:[!] Error dumping shit inside the disk");
	}
	else
	{
		OutputDebugStringA("hzw:[+] Vul driver data destroyed before unlink");
	}
	file_ofstream.close();
	delete[] randomData;

	//unlink the file
	if (_wremove(driver_path.c_str()) != 0)
		return false;

	return true;
}

bool driver::StopAndRemove(const std::wstring& driver_name)
{
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL)
		return false;

	std::wstring wdriver_reg_path = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + driver_name;
	UNICODE_STRING serviceStr;
	RtlInitUnicodeString(&serviceStr, wdriver_reg_path.c_str());

	HKEY driver_service;
	std::wstring servicesPath = L"SYSTEM\\CurrentControlSet\\Services\\" + driver_name;
	LSTATUS status = RegOpenKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str(), &driver_service);
	if (status != ERROR_SUCCESS)
	{
		if (status == ERROR_FILE_NOT_FOUND)
		{
			return true;
		}
		return false;
	}
	RegCloseKey(driver_service);

	auto NtUnloadDriver = (nt::NtUnloadDriver)GetProcAddress(ntdll, "NtUnloadDriver");
	NTSTATUS st = NtUnloadDriver(&serviceStr);
	
	if (st != 0x0)
	{
		
		status = RegDeleteKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
		return false; //lets consider unload fail as error because can cause problems with anti cheats later
	}


	status = RegDeleteKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
	if (status != ERROR_SUCCESS)
	{
		return false;
	}
	return true;
}




	

/*
BOOL DeleteFileEx(WCHAR* szPath)
{

	if (!wcslen(szPath) || !szPath)return FALSE;

std:wstring szTempPath = szPath;
	wchar_t temp_directory[MAX_PATH * 2] = { 0 };
	const uint32_t get_temp_path_ret = GetTempPathW(sizeof(temp_directory) / 2, temp_directory);
	if (!get_temp_path_ret || get_temp_path_ret > MAX_PATH + 1)
	{
		return FALSE;
	}
	if (temp_directory[wcslen(temp_directory) - 1] == L'\\')
	{
		temp_directory[wcslen(temp_directory) - 1] = 0x0;
	}

	wstring szTempDirectory = temp_directory;

	szTempDirectory += L"\\CC\\";
	SECURITY_ATTRIBUTES sa = { 0 };
	if (CreateDirectoryW(szTempDirectory.c_str(), &sa))
	{
		wstring szTempA = szTempDirectory + L"\\....\\";
		if (CreateDirectoryW(szTempA.c_str(), &sa))
		{
			wstring szTempB = szTempDirectory + L"\\....\\TemporaryFile";
			if (MoveFileW(szTempPath.c_str(), szTempB.c_str()))
			{
				wstring szTempC = szTempDirectory + L"TemporaryFile";
				if (MoveFileW(szTempA.c_str(), szTempC.c_str()))
				{
					if (RemoveDirectoryW(szTempDirectory.c_str()))
					{
						int a = 0;
					}
				}
			}
		}
	}
}
*/