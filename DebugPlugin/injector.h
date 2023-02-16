#pragma once
#include <Windows.h>

namespace injector
{
	BOOL Inject(HANDLE ProcessHandle, const char* szDllPath);
}

