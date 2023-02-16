#include "LoadSymbol.h"
#include "PDB.h"
#include "PDB_DBIStream.h"
#include "PDB_InfoStream.h"
#include "PDB_RawFile.h"
#include <Windows.h>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <Shlwapi.h>
#include "win-url-download.hpp"
#include "log.h"
#define PrintErro(text) MessageBoxA((HWND)0, text, "Erro", MB_OK | MB_TOPMOST)





Symbol::Symbol(const char* szFullPath)
{

	m_szFullPath = szFullPath;

}

Symbol::~Symbol()
{
	if (m_fileBuffer)
	{
		free(m_fileBuffer);
		m_fileBuffer = NULL;
	}
}





void Symbol::open_binary_file(const std::string & file, std::vector<uint8_t>&data) 
{
	std::ifstream fstr(file, std::ios::binary);
	fstr.unsetf(std::ios::skipws);
	fstr.seekg(0, std::ios::end);

	const auto file_size = fstr.tellg();

	fstr.seekg(NULL, std::ios::beg);
	data.reserve(static_cast<uint32_t>(file_size));
	data.insert(data.begin(), std::istream_iterator<uint8_t>(fstr), std::istream_iterator<uint8_t>());
}

void Symbol::buffer_to_file_bin(unsigned char* buffer, size_t buffer_size, const std::string& filename) 
{
	std::ofstream file(filename, std::ios_base::out | std::ios_base::binary);
	file.write((const char*)buffer, buffer_size);
	file.close();
}


PDB_NO_DISCARD static bool IsError(PDB::ErrorCode errorCode) 
{

	switch (errorCode) {
	case PDB::ErrorCode::Success:
		return false;

	case PDB::ErrorCode::InvalidSuperBlock:
		PrintErro("Invalid Superblock\n");
		return true;

	case PDB::ErrorCode::InvalidFreeBlockMap:
		PrintErro("Invalid free block map\n");
		return true;

	case PDB::ErrorCode::InvalidSignature:
		PrintErro("Invalid stream signature\n");
		return true;

	case PDB::ErrorCode::InvalidStreamIndex:
		PrintErro("Invalid stream index\n");
		return true;

	case PDB::ErrorCode::UnknownVersion:
		PrintErro("Unknown version\n");
		return true;
	}

	// only ErrorCode::Success means there wasn't an error, so all other paths
	// have to assume there was an error
	return true;
}

PDB_NO_DISCARD static bool HasValidDBIStreams(const PDB::RawFile& rawPdbFile, const PDB::DBIStream& dbiStream) {
	// check whether the DBI stream offers all sub-streams we need
	if (IsError(dbiStream.HasValidImageSectionStream(rawPdbFile))) {
		return false;
	}

	if (IsError(dbiStream.HasValidPublicSymbolStream(rawPdbFile))) {
		return false;
	}

	if (IsError(dbiStream.HasValidGlobalSymbolStream(rawPdbFile))) {
		return false;
	}

	if (IsError(dbiStream.HasValidSectionContributionStream(rawPdbFile))) {
		return false;
	}

	return true;
}

size_t find_sym_rva(const PDB::RawFile& rawPdbFile, const PDB::DBIStream& dbiStream, size_t symbol_hash) 
{

	const PDB::ImageSectionStream imageSectionStream = dbiStream.CreateImageSectionStream(rawPdbFile);
	const PDB::ModuleInfoStream   moduleInfoStream = dbiStream.CreateModuleInfoStream(rawPdbFile);
	const PDB::ArrayView<PDB::ModuleInfoStream::Module> modules = moduleInfoStream.GetModules();
	const PDB::PublicSymbolStream         publicSymbolStream = dbiStream.CreatePublicSymbolStream(rawPdbFile);
	const PDB::CoalescedMSFStream         symbolRecordStream = dbiStream.CreateSymbolRecordStream(rawPdbFile);
	const PDB::ArrayView<PDB::HashRecord> hashRecords = publicSymbolStream.GetRecords();

	std::hash<std::string> strhash;

	for (const PDB::HashRecord& hashRecord : hashRecords) 
	{
		const PDB::CodeView::DBI::Record* record = publicSymbolStream.GetRecord(symbolRecordStream, hashRecord);
		if ((PDB_AS_UNDERLYING(record->data.S_PUB32.flags) &
			PDB_AS_UNDERLYING(PDB::CodeView::DBI::PublicSymbolFlags::Function)) == 0u)
			continue;

		const uint32_t rva =
			imageSectionStream.ConvertSectionOffsetToRVA(record->data.S_PUB32.section, record->data.S_PUB32.offset);
		if (rva == 0u)
			continue;

		if (record->data.S_PUB32.name) {
			if (strhash(record->data.S_PUB32.name) == symbol_hash) {
				return static_cast<size_t>(rva);
			}
		}
	}

	size_t _ret = 0;
	for (const PDB::ModuleInfoStream::Module& module : modules) {
		if (!module.HasSymbolStream()) {
			continue;
		}
		const PDB::ModuleSymbolStream moduleSymbolStream = module.CreateSymbolStream(rawPdbFile);
		moduleSymbolStream.ForEachSymbol(
			[symbol_hash, &_ret, &strhash, &imageSectionStream](const PDB::CodeView::DBI::Record* record) {
				// only grab function symbols from the module streams
				const char* name = nullptr;
				uint32_t    rva = 0u;
				uint32_t    size = 0u;
				if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_THUNK32) {
					if (record->data.S_THUNK32.thunk == PDB::CodeView::DBI::ThunkOrdinal::TrampolineIncremental) {
						// we have never seen incremental linking thunks stored inside a
						// S_THUNK32 symbol, but better safe than sorry
						name = "ILT";
						rva = imageSectionStream.ConvertSectionOffsetToRVA(record->data.S_THUNK32.section,
							record->data.S_THUNK32.offset);
						size = 5u;
					}
				}
				else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_TRAMPOLINE) {
					// incremental linking thunks are stored in the linker module
					name = "ILT";
					rva = imageSectionStream.ConvertSectionOffsetToRVA(record->data.S_TRAMPOLINE.thunkSection,
						record->data.S_TRAMPOLINE.thunkOffset);
					size = 5u;
				}
				else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_LPROC32) {
					name = record->data.S_LPROC32.name;
					rva = imageSectionStream.ConvertSectionOffsetToRVA(record->data.S_LPROC32.section,
						record->data.S_LPROC32.offset);
					size = record->data.S_LPROC32.codeSize;
				}
				else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_GPROC32) {
					name = record->data.S_GPROC32.name;
					rva = imageSectionStream.ConvertSectionOffsetToRVA(record->data.S_GPROC32.section,
						record->data.S_GPROC32.offset);
					size = record->data.S_GPROC32.codeSize;
				}
				else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_LPROC32_ID) {
					name = record->data.S_LPROC32_ID.name;
					rva = imageSectionStream.ConvertSectionOffsetToRVA(record->data.S_LPROC32_ID.section,
						record->data.S_LPROC32_ID.offset);
					size = record->data.S_LPROC32_ID.codeSize;
				}
				else if (record->header.kind == PDB::CodeView::DBI::SymbolRecordKind::S_GPROC32_ID) {
					name = record->data.S_GPROC32_ID.name;
					rva = imageSectionStream.ConvertSectionOffsetToRVA(record->data.S_GPROC32_ID.section,
						record->data.S_GPROC32_ID.offset);
					size = record->data.S_GPROC32_ID.codeSize;
				}
				if (name) {
					// file << name << "\n";
					if (strhash(name) == symbol_hash) 
					{
						_ret = rva;
					}
				}

				if (rva == 0u)
					return;
			});
	}
	return _ret;
}


void find_sym_rva_ex(const PDB::RawFile& rawPdbFile, const PDB::DBIStream& dbiStream, vector<symbol_info>& vectorsymbolInfo,string moduleName,ULONG_PTR nModuleBase)
{

	const PDB::ImageSectionStream imageSectionStream = dbiStream.CreateImageSectionStream(rawPdbFile);
	const PDB::ModuleInfoStream   moduleInfoStream = dbiStream.CreateModuleInfoStream(rawPdbFile);
	const PDB::ArrayView<PDB::ModuleInfoStream::Module> modules = moduleInfoStream.GetModules();
	const PDB::PublicSymbolStream         publicSymbolStream = dbiStream.CreatePublicSymbolStream(rawPdbFile);
	const PDB::CoalescedMSFStream         symbolRecordStream = dbiStream.CreateSymbolRecordStream(rawPdbFile);
	const PDB::ArrayView<PDB::HashRecord> hashRecords = publicSymbolStream.GetRecords();


	symbol_info dwInfo = { 0 };

	for (const PDB::HashRecord& hashRecord : hashRecords)
	{
		const PDB::CodeView::DBI::Record* record = publicSymbolStream.GetRecord(symbolRecordStream, hashRecord);
		if ((PDB_AS_UNDERLYING(record->data.S_PUB32.flags) &
			PDB_AS_UNDERLYING(PDB::CodeView::DBI::PublicSymbolFlags::Function)) == 0u)
			continue;

		const uint32_t rva =
			imageSectionStream.ConvertSectionOffsetToRVA(record->data.S_PUB32.section, record->data.S_PUB32.offset);
		if (rva == 0u)
			continue;

		if (record->data.S_PUB32.name && strlen(record->data.S_PUB32.name)<100) 
		{
			dwInfo.rva = rva + nModuleBase;
			StrCpyA(dwInfo.szFuncName, record->data.S_PUB32.name);
			vectorsymbolInfo.push_back(dwInfo);
		}
	}


	return ;
}


bool Symbol::init(void* pdbFile_baseAddress,vector<symbol_info>& vectorsymbolInfo,string moduleName,ULONG_PTR nModuleBase) 
{
	// std::hash<std::string> strhash;

	if (IsError(PDB::ValidateFile(pdbFile_baseAddress))) {
		false;
	}

	const PDB::RawFile rawPdbFile = PDB::CreateRawFile(pdbFile_baseAddress);
	if (IsError(PDB::HasValidDBIStream(rawPdbFile))) {
		false;
	}

	const PDB::InfoStream infoStream(rawPdbFile);
	if (infoStream.UsesDebugFastLink()) {
		PrintErro("PDB was linked using unsupported option /DEBUG:FASTLINK\n");

		false;
	}

	const PDB::DBIStream dbiStream = PDB::CreateDBIStream(rawPdbFile);
	if (!HasValidDBIStreams(rawPdbFile, dbiStream)) {
		false;
	}


	find_sym_rva_ex(rawPdbFile, dbiStream, vectorsymbolInfo, moduleName,nModuleBase);


	return true;
}


BOOL Symbol::LoadSymbol(vector<symbol_info>& vectorsymbolInfo,ULONG_PTR nModuleBase, CBindStatusCallback* StatusCallback)
{
	std::vector<uint8_t> data;

	BOOL bRet = FALSE;
	string pdb_url = pdburl(GetModuleDebugInfo(m_szFullPath.c_str()));
	string saveSymbolFileName; //存放的符号名字
	saveSymbolFileName = m_guid_filtered + ".pdb";
	if (m_guid_filtered.empty() || pdb_url.empty()) {
		MessageBoxW(NULL, L"获取文件guid失败", L"提示", 0);
		return bRet;
	}
	if (!check_symbol_file(saveSymbolFileName)) 
	{
		auto hr = URLDownloadToFileA(0, pdb_url.c_str(), saveSymbolFileName.c_str(), 0, StatusCallback);
		if (hr != S_OK)
		{
			
			return bRet;
		}
	}
	logs.addLog("nt symbol:%s", saveSymbolFileName.c_str());
	open_binary_file(saveSymbolFileName, data);

	bRet = init(data.data(), vectorsymbolInfo, m_szDllBasePath, nModuleBase);
	

	return bRet;
}

BOOL Symbol::DownKernelSymBoolAndSave(string szSavePath)
{
	BOOL bRet = FALSE;
	string szTempSavePath;
	if (szSavePath.empty())return bRet;
	int b = szSavePath.rfind(".sys");
	if (b != -1)
	{
		szSavePath = szSavePath.replace(b, strlen(".sys"), ".pdb");

		szTempSavePath += szSavePath;
	    if (!check_symbol_file(szTempSavePath.c_str()))
	    {
	    	string pdb_url = pdburl(GetModuleDebugInfo(m_szFullPath.c_str()));
	    	if (!pdb_url.empty() && pdb_url.size()<MAX_PATH)
	    	{
				auto hr = URLDownloadToFileA(0, pdb_url.c_str(), szTempSavePath.c_str(), 0, NULL);
			    if (hr != S_OK)
			    {
			    	return bRet;
			    }
				bRet = TRUE;
	    	}
	    }
	}
	return bRet;
}

BOOL Symbol::DownSymBoolAndSave(string szSavePath,BOOL bIs64)
{
	BOOL bRet = FALSE;
	string szTempSavePath;

	if (szSavePath.empty())return bRet;
	if (bIs64)
	{
		szTempSavePath = "x64sym";
		szTempSavePath += "\\";
	}
	else 
	{
		szTempSavePath = "x32sym";
		szTempSavePath += "\\";
	}

	int b = szSavePath.rfind(".dll");
	if (b != -1)
	{
		szSavePath = szSavePath.replace(b, strlen(".dll"), ".pdb");

		szTempSavePath += szSavePath;
	    if (!check_symbol_file(szTempSavePath.c_str()))
	    {
	    	string pdb_url = pdburl(GetModuleDebugInfo(m_szFullPath.c_str()));
	    	if (!pdb_url.empty() && pdb_url.size()<MAX_PATH)
	    	{
				auto hr = URLDownloadToFileA(0, pdb_url.c_str(), szTempSavePath.c_str(), 0, NULL);
			    if (hr != S_OK)
			    {
			    	return bRet;
			    }
				bRet = TRUE;
	    	}
	    }
	}
	return bRet;
}

BOOL Symbol::check_symbol_file(string symbol_name)
{
	return PathFileExistsA(symbol_name.c_str());
}
DebugInfo* Symbol::GetModuleDebugInfo(const char* moduleName) 
{
	m_fileBuffer = file_to_image_buffer(stringToWstring(moduleName).c_str(),m_ImageSizeOfDll);

	return GetModuleDebugInfoEx((HMODULE)m_fileBuffer);
}

DebugInfo* Symbol::GetModuleDebugInfoEx(HMODULE module) 
{
	if (!module)return NULL;
	IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)module;
	IMAGE_NT_HEADERS32* pNt32 = (IMAGE_NT_HEADERS32*)((CHAR*)module + pDos->e_lfanew);
	IMAGE_NT_HEADERS64* pNt64 = (IMAGE_NT_HEADERS64*)((CHAR*)module + pDos->e_lfanew);
	IMAGE_DEBUG_DIRECTORY* pDebug = NULL;
	if (pNt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) 
	{
		pDebug =
			(IMAGE_DEBUG_DIRECTORY*)(pNt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress +
				(CHAR*)module);

	}
	else {
		pDebug =
			(IMAGE_DEBUG_DIRECTORY*)(pNt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress +
				(CHAR*)module);
	}

	if (!pDebug->AddressOfRawData) {
		return NULL;
	}
	auto pDebugInfo = (DebugInfo*)(pDebug->AddressOfRawData + (CHAR*)module);

	return pDebugInfo;
}


std::string Symbol::pdburl(DebugInfo* pdb_info) 
{
	if (!pdb_info || strlen(pdb_info->PdbFileName) > 20 ) return "";
	wchar_t w_GUID[100]{ 0 };
	if (!StringFromGUID2(pdb_info->Guid, w_GUID, 100)) {
		return {};
	}

	char   a_GUID[100]{ 0 };
	size_t l_GUID = 0;
	if (wcstombs_s(&l_GUID, a_GUID, w_GUID, sizeof(a_GUID)) || !l_GUID) {
		return {};
	}

	
	for (UINT i = 0; i != l_GUID; ++i) {
		if ((a_GUID[i] >= '0' && a_GUID[i] <= '9') || (a_GUID[i] >= 'A' && a_GUID[i] <= 'F') ||
			(a_GUID[i] >= 'a' && a_GUID[i] <= 'f')) {
			m_guid_filtered += a_GUID[i];
		}
	}

	char age[MAX_PATH]{ 0 };
	_itoa_s(pdb_info->Age, age, 10);

	std::string url = "https://msdl.microsoft.com/download/symbols/";

	url += pdb_info->PdbFileName;
	url += '/';
	url += m_guid_filtered;
	url += age;
	url += '/';
	url += pdb_info->PdbFileName;
	return url;
}


PVOID Symbol::file_to_image_buffer(LPCWSTR szFullPath, DWORD& pImageSize)
{
#ifdef  _WIN64

#else
	PVOID OldValue = NULL;
	BOOL bRelocate = ::Wow64DisableWow64FsRedirection(&OldValue);
#endif //  _WIN64
	HANDLE hFile = CreateFile(
		szFullPath,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

#ifdef  _WIN64

#else
	if (bRelocate == TRUE)
	{
		::Wow64RevertWow64FsRedirection(OldValue);
	}
#endif 

	if (hFile == INVALID_HANDLE_VALUE)
	{
		return NULL;
	}

	DWORD dwSize = GetFileSize(hFile, NULL);
	if (dwSize == 0)
	{
		CloseHandle(hFile);
		return NULL;
	}



	PVOID pBuffer = malloc(dwSize);
	if (!pBuffer)
	{
		CloseHandle(hFile);
		return NULL;
	}

	RtlZeroMemory(pBuffer, dwSize);
	DWORD dwRet = 0;
	if (!ReadFile(hFile, pBuffer, dwSize, &dwRet, NULL))
	{
		CloseHandle(hFile);
		free(pBuffer);
		return NULL;
	}

	CloseHandle(hFile);


	PVOID ImageBase = NULL;

	if (!ImageFile((PBYTE)pBuffer, &ImageBase, pImageSize) || ImageBase == NULL)
	{
		free(pBuffer);
		return NULL;
	}


	free(pBuffer);

	return ImageBase;
}

UINT Symbol::AlignSize(UINT nSize, UINT nAlign)
{
	return ((nSize + nAlign - 1) / nAlign * nAlign);
}

BOOL Symbol::ImageFile(PVOID FileBuffer, PVOID * ImageModuleBase, DWORD & ImageSize)
{
	PIMAGE_DOS_HEADER ImageDosHeader = NULL;
	PIMAGE_NT_HEADERS ImageNtHeaders = NULL;
	PIMAGE_SECTION_HEADER ImageSectionHeader = NULL;
	DWORD FileAlignment = 0, SectionAlignment = 0, NumberOfSections = 0, SizeOfImage = 0, SizeOfHeaders = 0;
	DWORD Index = 0;
	PVOID ImageBase = NULL;
	DWORD SizeOfNtHeaders = 0;

	if (!FileBuffer || !ImageModuleBase)
	{
		return FALSE;
	}

	__try
	{
		ImageDosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
		if (ImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			return FALSE;
		}

		HMODULE h = GetModuleHandle(L"ntdll.dll");
		typedef PIMAGE_NT_HEADERS(WINAPI* pfnRtlImageNtHeader)(PVOID Base);
		pfnRtlImageNtHeader RtlImageNtHeader_ = NULL;
		RtlImageNtHeader_ = (pfnRtlImageNtHeader)GetProcAddress(h, "RtlImageNtHeader");

		ImageNtHeaders = RtlImageNtHeader_(FileBuffer);


		if (ImageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
		{
			return FALSE;
		}

		FileAlignment = ImageNtHeaders->OptionalHeader.FileAlignment;
		SectionAlignment = ImageNtHeaders->OptionalHeader.SectionAlignment;
		NumberOfSections = ImageNtHeaders->FileHeader.NumberOfSections;
		SizeOfImage = ImageNtHeaders->OptionalHeader.SizeOfImage;
		SizeOfHeaders = ImageNtHeaders->OptionalHeader.SizeOfHeaders;
		SizeOfImage = AlignSize(SizeOfImage, SectionAlignment);

		ImageSize = SizeOfImage;

		ImageBase = malloc(SizeOfImage);
		if (ImageBase == NULL)
		{
			return FALSE;
		}
		RtlZeroMemory(ImageBase, SizeOfImage);

		SizeOfNtHeaders = sizeof(ImageNtHeaders->FileHeader) + sizeof(ImageNtHeaders->Signature) + ImageNtHeaders->FileHeader.SizeOfOptionalHeader;
		ImageSectionHeader = IMAGE_FIRST_SECTION(ImageNtHeaders);

		for (Index = 0; Index < NumberOfSections; Index++)
		{
			ImageSectionHeader[Index].SizeOfRawData = AlignSize(ImageSectionHeader[Index].SizeOfRawData, FileAlignment);
			ImageSectionHeader[Index].Misc.VirtualSize = AlignSize(ImageSectionHeader[Index].Misc.VirtualSize, SectionAlignment);
		}

		if (ImageSectionHeader[NumberOfSections - 1].VirtualAddress + ImageSectionHeader[NumberOfSections - 1].SizeOfRawData > SizeOfImage)
		{
			ImageSectionHeader[NumberOfSections - 1].SizeOfRawData = SizeOfImage - ImageSectionHeader[NumberOfSections - 1].VirtualAddress;
		}

		RtlCopyMemory(ImageBase, FileBuffer, SizeOfHeaders);

		for (Index = 0; Index < NumberOfSections; Index++)
		{
			DWORD FileOffset = ImageSectionHeader[Index].PointerToRawData;
			DWORD Length = ImageSectionHeader[Index].SizeOfRawData;
			ULONG64 ImageOffset = ImageSectionHeader[Index].VirtualAddress;
			RtlCopyMemory(&((PBYTE)ImageBase)[ImageOffset], &((PBYTE)FileBuffer)[FileOffset], Length);
		}

		*ImageModuleBase = ImageBase;


	}
	__except (1)
	{
		if (ImageBase)
		{
			free(ImageBase);
			ImageBase = NULL;
		}

		*ImageModuleBase = NULL;
		return FALSE;
	}

	return TRUE;
}


string Symbol::wstringToString(const wstring& wstr)
{
	LPCWSTR pwszSrc = wstr.c_str();
	int nLen = WideCharToMultiByte(CP_ACP, 0, pwszSrc, -1, NULL, 0, NULL, NULL);
	if (nLen == 0)
		return string("");
	char* pszDst = new char[nLen];
	if (!pszDst)
		return string("");
	WideCharToMultiByte(CP_ACP, 0, pwszSrc, -1, pszDst, nLen, NULL, NULL);
	string str(pszDst);
	delete[] pszDst;
	pszDst = NULL;
	return str;
}

wstring Symbol::stringToWstring(const string& str)
{
	LPCSTR pszSrc = str.c_str();
	int nLen = MultiByteToWideChar(CP_ACP, 0, pszSrc, -1, NULL, 0);
	if (nLen == 0)
		return wstring(L"");
	wchar_t* pwszDst = new wchar_t[nLen];
	if (!pwszDst)
		return wstring(L"");
	MultiByteToWideChar(CP_ACP, 0, pszSrc, -1, pwszDst, nLen);
	std::wstring wstr(pwszDst);
	delete[] pwszDst;
	pwszDst = NULL;
	return wstr;
}

