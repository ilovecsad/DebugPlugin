#pragma once
#include <Windows.h>
#include <iostream>
#include <vector>
#include <map>
#include "win-url-download.hpp"
using namespace std;

typedef struct _symbol_info_
{
	SIZE_T rva;
	char szFuncName[100];
}symbol_info, * psymbol_info;

struct DebugInfo {
	DWORD Signature;
	GUID  Guid;
	DWORD Age;
	char  PdbFileName[1];
};


class Symbol
{
public:
	
	Symbol(const char* szFullPath);
	~Symbol();
	BOOL LoadSymbol(vector<symbol_info>& vectorsymbolInfo, ULONG_PTR nModuleBase = NULL, CBindStatusCallback* StatusCallback = NULL);
	BOOL DownSymBoolAndSave(string szSavePath,BOOL bIs64);
	BOOL DownKernelSymBoolAndSave(string szSavePath);
private:
	string m_szFullPath;
	string m_szDllBasePath;
	DWORD m_ImageSizeOfDll = 0;
	PVOID m_fileBuffer = NULL;


	std::string m_guid_filtered; //文件pdb唯一标志

private:

	DebugInfo* GetModuleDebugInfoEx(HMODULE module);
	DebugInfo* GetModuleDebugInfo(const char* moduleName);
	std::string pdburl(DebugInfo* pdb_info);

	BOOL ImageFile(PVOID FileBuffer, PVOID* ImageModuleBase, DWORD& ImageSize);
	PVOID file_to_image_buffer(LPCWSTR szFullPath, DWORD& pImageSize);
	UINT AlignSize(UINT nSize, UINT nAlign);
	void  open_binary_file(const std::string& file, std::vector<uint8_t>& data);
	void  buffer_to_file_bin(unsigned char* buffer, size_t buffer_size, const std::string& filename);
	wstring stringToWstring(const string& str);
	string wstringToString(const wstring& wstr);
	BOOL check_symbol_file(string symbol_name);
	bool init(void* pdbFile_baseAddress, vector<symbol_info>& vectorsymbolInfo, string moduleName, ULONG_PTR nModuleBase);
};

