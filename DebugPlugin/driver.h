#pragma once
#include <Windows.h>
#include <winioctl.h>
#include <time.h>
#include <string>
#include <TlHelp32.h>
#include <stdint.h>
#include <vector>
#include <string>
#include <iostream>
#include <fstream>


				
//可以 加载任意驱动
class driver
{
public:
	driver();
	~driver();
	HANDLE Load();
	bool Unload(HANDLE device_handle);
	std::wstring GetDriverPath();
	bool fabricateFile();
private:
	char driver_name[100];
	
private:
	HANDLE m_driverHanle = NULL;
	BOOL IsRunning();
	std::wstring GetFullTempPath();
	std::wstring GetDriverNameW();
	bool CreateFileFromMemory(const std::wstring& desired_file_path, const char* address, size_t size);
	bool RegisterAndStart(const std::wstring& driver_path);
	bool StopAndRemove(const std::wstring& driver_name);
};



