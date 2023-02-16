#include "common.h"
#include <stdio.h>

HANDLE remote_exec_final = 0;
char* dispatch_table_ptr = NULL;
char* dispatch_table = NULL;
HANDLE g_process = 0;

UCHAR mapInjectShellcode64[120] = {
    0x50 ,0x51 ,0x52 ,0x41 ,0x50 ,0x41 ,0x51 ,0x41,
    0x53 ,

    0x48,0x83,0xec,0x28,         //sub rsp,0x28
    0x48,0xb9,0,0,0,0,0,0,0,0,  // mov rcx,   offset +15
    0x48,0xba,0,0,0,0,0,0,0,0,  // mov rdx,    offset +25
    0x49,0xb8,0,0,0,0,0,0,0,0,  // mov r8,     offset +35
    0x48,0xb8,0,0,0,0,0,0,0,0,  // mov rax,    offset +45
    0xff,0xd0,                  //call rax
    0x48,0x83,0xc4,0x28,        //add rsp,0x28   +50


    0x48 ,0x83 ,0xEC ,0x38 //sub rsp,0x38
    ,0x48 ,0x31 ,0xC9,     //xor rcx,rcx


    0x48 ,0xBA ,0x01 ,0x00 ,0x00 ,0x00 ,0x00 ,0x00, 0x00 ,0x00 ,
    0x49 ,0xB8 ,//mov r8
    0x90 ,0x90 ,0x90,0x90, 0x90 ,0x90 ,0x90 ,0x90 , //dll的基地址

    0x48 ,0xB8 ,//mov rax,
    0x90,0x90, 0x90 ,0x90,0x90 ,0x90,0x90 ,0x90 ,  //dll的入口地址

    0xFF ,0xD0, //call rax
    0x48 ,0x83 ,0xC4 ,0x38 ,0x41 ,0x5B ,0x41 ,0x59,
    0x41 ,0x58 ,0x5A ,0x59 ,0x58 ,0xC3
};

DWORD HandleToPid(HANDLE hProcess)
{
    PROCESS_BASIC_INFORMATION pi = { 0 };
    if (NT_SUCCESS(NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pi, sizeof(PROCESS_BASIC_INFORMATION), 0)))
    {
        return (DWORD)pi.UniqueProcessId;
    }
    return 0;
}

PVOID GetThreadStartAddress(HANDLE hThread)
{
    PVOID b = NULL;
    if (NT_SUCCESS(NtQueryInformationThread(hThread, (THREADINFOCLASS)9, &b, sizeof(PVOID), 0))) {
        return b;
    }

    return NULL;
}

CLIENT_ID ThreadHandleToPid(HANDLE hThread)
{
    THREAD_BASIC_INFORMATION tbi = { 0 };
    if (NT_SUCCESS(NtQueryInformationThread(hThread, (THREADINFOCLASS)0/*ThreadBasicInformation*/, &tbi, sizeof(THREAD_BASIC_INFORMATION), 0)))
    {
        return tbi.ClientId;
    }
    return { 0,0 };
}


DWORD GetProcessPid(const WCHAR* szProcessName )
{
    HANDLE hProcessSnap;
    PROCESSENTRY32W pe32;
    DWORD nPid = 0;
    // Take a snapshot of all processes in the system.
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
 
        return nPid;
    }

    // Set the size of the structure before using it.
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    // Retrieve information about the first process,
    // and exit if unsuccessful
    if (!Process32FirstW(hProcessSnap, &pe32))
    {
     
        CloseHandle(hProcessSnap);          // clean the snapshot object
        return nPid;
    }

    // Now walk the snapshot of processes, and
    // display information about each process in turn
    do
    {
        if (!lstrcmp(szProcessName, pe32.szExeFile)) {
            nPid = pe32.th32ProcessID;
            break;
        }


    } while (Process32NextW(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    return nPid;
}



std::wstring stringToWstring(const std::string& str)
{
    LPCSTR pszSrc = str.c_str();
    int nLen = MultiByteToWideChar(CP_ACP, 0, pszSrc, -1, NULL, 0);
    if (nLen == 0)
        return std::wstring(L"");
    wchar_t* pwszDst = new wchar_t[nLen];
    if (!pwszDst)
        return std::wstring(L"");
    MultiByteToWideChar(CP_ACP, 0, pszSrc, -1, pwszDst, nLen);
    std::wstring wstr(pwszDst);
    delete[] pwszDst;
    pwszDst = NULL;
    return wstr;
}
std::string wstringToString(const std::wstring& wstr)
{
    LPCWSTR pwszSrc = wstr.c_str();
    int nLen = WideCharToMultiByte(CP_ACP, 0, pwszSrc, -1, NULL, 0, NULL, NULL);
    if (nLen == 0)
        return std::string("");
    char* pszDst = new char[nLen];
    if (!pszDst)
        return std::string("");
    WideCharToMultiByte(CP_ACP, 0, pwszSrc, -1, pszDst, nLen, NULL, NULL);
    std::string str(pszDst);
    delete[] pszDst;
    pszDst = NULL;
    return str;
}



PVOID file_to_image_buffer(LPCWSTR szFullPath, DWORD& pImageSize)
{
    HANDLE hFile = CreateFile(
        szFullPath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE || !hFile)
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

BOOL ImageFile(PVOID FileBuffer, PVOID* ImageModuleBase, DWORD& ImageSize)
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

UINT AlignSize(UINT nSize, UINT nAlign)
{
    return ((nSize + nAlign - 1) / nAlign * nAlign);
}


BOOL fixed_image_buffer(PVOID pImageBufer, ULONG_PTR pTargetAddress)
{

    if (pImageBufer && pTargetAddress)
    {
        return FixImportTable(pImageBufer, (ULONG_PTR)pTargetAddress);
    }
    return FALSE;
}


BOOL FixImportTable(PVOID pPEBuffer, ULONG_PTR dwLoadMemoryAddress)
{
    PIMAGE_NT_HEADERS64 pNtHeaders = NULL;
    PIMAGE_NT_HEADERS32 pNtHeaders32 = NULL;
    PIMAGE_DOS_HEADER       pDosHdr = (PIMAGE_DOS_HEADER)pPEBuffer;
    pNtHeaders = (PIMAGE_NT_HEADERS64)((ULONG_PTR)pPEBuffer + pDosHdr->e_lfanew);
    pNtHeaders32 = (PIMAGE_NT_HEADERS32)((ULONG_PTR)pPEBuffer + pDosHdr->e_lfanew);
    ULONG_PTR pImport = 0;
    BOOL bIs64 = FALSE;

    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }

    if (pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        pImport = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        bIs64 = TRUE;
    }
    else
    {
        pImport = pNtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    }

    PIMAGE_IMPORT_DESCRIPTOR pID = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)pPEBuffer + pImport);
    PIMAGE_IMPORT_BY_NAME    pByName = NULL;

    while ((pID->Characteristics != 0) && pImport)
    {

        PIMAGE_THUNK_DATA pRealIAT = (PIMAGE_THUNK_DATA)((ULONG_PTR)pPEBuffer + pID->FirstThunk);
        PIMAGE_THUNK_DATA pOriginalIAT = (PIMAGE_THUNK_DATA)((ULONG_PTR)pPEBuffer + pID->OriginalFirstThunk);
        //获取dll的名字
        char* pName = (char*)((ULONG_PTR)pPEBuffer + pID->Name);
        HANDLE hDll = 0;

        hDll = GetModuleHandleA(pName);

        if (!hDll)
        {
            hDll = LoadLibraryA(pName);
        }

        if (hDll == NULL) {

            return FALSE;
        }

        for (ULONG i = 0;; i++)
        {
            if (pOriginalIAT[i].u1.Function == 0)
                break;
            FARPROC lpFunction = NULL;
            if (IMAGE_SNAP_BY_ORDINAL(pOriginalIAT[i].u1.Ordinal)) //这里的值给出的是导出序号
            {
                if (IMAGE_ORDINAL(pOriginalIAT[i].u1.Ordinal)) {

                    //LdrGetProcedureAddress_(hDll, NULL, IMAGE_ORDINAL(pOriginalIAT[i].u1.Ordinal), &lpFunction);
                    lpFunction = (FARPROC)GetProcAddress((HMODULE)hDll, (char*)IMAGE_ORDINAL(pOriginalIAT[i].u1.Ordinal));
                }
            }
            else //按照名字导入
            {
                //获取此IAT项所描述的函数名称
                pByName = (PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)pPEBuffer + (ULONG_PTR)(pOriginalIAT[i].u1.AddressOfData));
                if ((char*)pByName->Name)
                {
                    /**
                    RtlInitAnsiString_(&ansiStr, (char *)pByName->Name);
                    LdrGetProcedureAddress_(hDll, &ansiStr, 0, &lpFunction);
                    */
                    lpFunction = (FARPROC)GetProcAddress((HMODULE)hDll, pByName->Name);
                }
            }

            //标记***********

            if (lpFunction != NULL) //找到了！
                pRealIAT[i].u1.Function = (ULONG_PTR)lpFunction;
            else {
                return FALSE;
            }
        }

        // move to next
        pID = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)pID + sizeof(IMAGE_IMPORT_DESCRIPTOR));
    }

    return FixBaseRelocTable(pPEBuffer, dwLoadMemoryAddress);

}




BOOL FixBaseRelocTable32(PVOID pPEBuffer, ULONG_PTR dwLoadMemoryAddress)
{
    PIMAGE_DOS_HEADER       pDosHdr = (PIMAGE_DOS_HEADER)pPEBuffer;
    PIMAGE_NT_HEADERS32 pNTHeader32 = NULL;

    pNTHeader32 = (PIMAGE_NT_HEADERS32)((ULONG_PTR)pPEBuffer + pDosHdr->e_lfanew);

    if (pNTHeader32->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }

    PIMAGE_BASE_RELOCATION pLoc = NULL;
    DWORD LocSize = 0;
    pLoc = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)pPEBuffer +
        pNTHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
        .VirtualAddress);

    LocSize = (DWORD)(pNTHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);

    if (pLoc && LocSize)
    {

        DWORD  Delta = (ULONG_PTR)dwLoadMemoryAddress - pNTHeader32->OptionalHeader.ImageBase;
        DWORD* pAddress = NULL;
        //注意重定位表的位置可能和硬盘文件中的偏移地址不同，应该使用加载后的地址

        while ((pLoc->VirtualAddress + pLoc->SizeOfBlock) != 0) //开始扫描重定位表
        {
            WORD* pLocData = (WORD*)((ULONG_PTR)pLoc + sizeof(IMAGE_BASE_RELOCATION));
            //计算本节需要修正的重定位项（地址）的数目
            int NumberOfReloc = (pLoc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            for (int i = 0; i < NumberOfReloc; i++) {
                if ((DWORD)(pLocData[i] & 0xF000) == 0x00003000 ||
                    (DWORD)(pLocData[i] & 0xF000) == 0x0000A000) //这是一个需要修正的地址
                {
                    // 举例：
                    // pLoc->VirtualAddress = 0×1000;
                    // pLocData[i] = 0×313E; 表示本节偏移地址0×13E处需要修正
                    // 因此 pAddress = 基地址 + 0×113E
                    // 里面的内容是 A1 ( 0c d4 02 10) 汇编代码是： mov eax , [1002d40c]
                    // 需要修正1002d40c这个地址
                    pAddress = (DWORD*)((ULONG_PTR)pPEBuffer + pLoc->VirtualAddress + (pLocData[i] & 0x0FFF));
                    *pAddress += Delta;
                }
            }
            //转移到下一个节进行处理
            pLoc = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)pLoc + pLoc->SizeOfBlock);
        }
        /***********************************************************************/
    }

    pNTHeader32->OptionalHeader.ImageBase = (DWORD)dwLoadMemoryAddress;


    return TRUE;
}

BOOL FixBaseRelocTable(PVOID pPEBuffer, ULONG_PTR dwLoadMemoryAddress)
{

    PIMAGE_DOS_HEADER       pDosHdr = (PIMAGE_DOS_HEADER)pPEBuffer;
    PIMAGE_NT_HEADERS64 pNTHeader = NULL;
    PIMAGE_NT_HEADERS32 pNTHeader32 = NULL;
    BOOL bIs64 = FALSE;

    pNTHeader = (PIMAGE_NT_HEADERS64)((ULONG_PTR)pPEBuffer + pDosHdr->e_lfanew);
    pNTHeader32 = (PIMAGE_NT_HEADERS32)((ULONG_PTR)pPEBuffer + pDosHdr->e_lfanew);

    if (pNTHeader->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }

    PIMAGE_BASE_RELOCATION pLoc = NULL;
    DWORD LocSize = 0;
    if (pNTHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        pLoc = (PIMAGE_BASE_RELOCATION)((DWORDX)pPEBuffer +
            pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
            .VirtualAddress);
        LocSize = (DWORD)(pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
        bIs64 = TRUE;
    }
    else
    {
        pLoc = (PIMAGE_BASE_RELOCATION)((DWORDX)pPEBuffer +
            pNTHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
            .VirtualAddress);
        LocSize = (DWORD)(pNTHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);

        return FixBaseRelocTable32(pPEBuffer, dwLoadMemoryAddress);

    }

    if (pLoc && LocSize)
    {

        DWORDX  Delta = (DWORDX)dwLoadMemoryAddress - pNTHeader->OptionalHeader.ImageBase;
        DWORDX* pAddress = NULL;
        //注意重定位表的位置可能和硬盘文件中的偏移地址不同，应该使用加载后的地址

        while ((pLoc->VirtualAddress + pLoc->SizeOfBlock) != 0) //开始扫描重定位表
        {
            WORD* pLocData = (WORD*)((DWORDX)pLoc + sizeof(IMAGE_BASE_RELOCATION));
            //计算本节需要修正的重定位项（地址）的数目
            int NumberOfReloc = (pLoc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            for (int i = 0; i < NumberOfReloc; i++) {
                if ((DWORDX)(pLocData[i] & 0xF000) == 0x00003000 ||
                    (DWORDX)(pLocData[i] & 0xF000) == 0x0000A000) //这是一个需要修正的地址
                {
                    // 举例：
                    // pLoc->VirtualAddress = 0×1000;
                    // pLocData[i] = 0×313E; 表示本节偏移地址0×13E处需要修正
                    // 因此 pAddress = 基地址 + 0×113E
                    // 里面的内容是 A1 ( 0c d4 02 10) 汇编代码是： mov eax , [1002d40c]
                    // 需要修正1002d40c这个地址
                    pAddress = (DWORDX*)((DWORDX)pPEBuffer + pLoc->VirtualAddress + (pLocData[i] & 0x0FFF));
                    *pAddress += Delta;
                }
            }
            //转移到下一个节进行处理
            pLoc = (PIMAGE_BASE_RELOCATION)((DWORDX)pLoc + pLoc->SizeOfBlock);
        }
        /***********************************************************************/
    }
    if (bIs64) {
        pNTHeader->OptionalHeader.ImageBase = (DWORDX)dwLoadMemoryAddress;
    }
    else {
        pNTHeader32->OptionalHeader.ImageBase = (DWORDX)dwLoadMemoryAddress;
    }


    return TRUE;

}



//\\Device\\HarddiskVolume1\x86.sys    c:\x86.sys    
BOOL DeviceDosPathToNtPath(wchar_t* pszDosPath, wchar_t* pszNtPath)
{
    static TCHAR    szDriveStr[MAX_PATH] = { 0 };
    static TCHAR    szDevName[MAX_PATH] = { 0 };
    TCHAR            szDrive[3];
    INT             cchDevName;
    INT             i;

    //检查参数  
    if (IsBadReadPtr(pszDosPath, 1) != 0)return FALSE;
    if (IsBadWritePtr(pszNtPath, 1) != 0)return FALSE;


    //获取本地磁盘字符串  
    ZeroMemory(szDriveStr, ARRAYSIZE(szDriveStr));
    ZeroMemory(szDevName, ARRAYSIZE(szDevName));
    if (GetLogicalDriveStringsW(sizeof(szDriveStr), szDriveStr))
    {
        for (i = 0; szDriveStr[i]; i += 4)
        {
            if (!lstrcmpi(&(szDriveStr[i]), L"A:\\") || !lstrcmpi(&(szDriveStr[i]), L"B:\\"))
                continue;

            szDrive[0] = szDriveStr[i];
            szDrive[1] = szDriveStr[i + 1];
            szDrive[2] = '\0';
            if (!QueryDosDevice(szDrive, szDevName, MAX_PATH))//查询 Dos 设备名  
                return FALSE;

            cchDevName = lstrlen(szDevName);
            if (_wcsnicmp(pszDosPath, szDevName, cchDevName) == 0)//命中  
            {
                lstrcpy(pszNtPath, szDrive);//复制驱动器  
                lstrcat(pszNtPath, pszDosPath + cchDevName);//复制路径  

                return TRUE;
            }
        }
    }

    lstrcpy(pszNtPath, pszDosPath);

    return FALSE;
}

NTSTATUS DosPathToNtPath(wchar_t* pDosPath, PUNICODE_STRING pNtPath)
{
    //定义变量
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    typedef BOOLEAN(__stdcall* fnRtlDosPathNameToNtPathName_U)(PCWSTR DosFileName, PUNICODE_STRING NtFileName, PWSTR* FilePart, PVOID Reserved);
    static fnRtlDosPathNameToNtPathName_U RtlDosPathNameToNtPathName_U = (fnRtlDosPathNameToNtPathName_U)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlDosPathNameToNtPathName_U");

    //参数效验
    if (IsBadReadPtr(pDosPath, 1) != 0)return NULL;
    if (RtlDosPathNameToNtPathName_U == NULL)return NULL;

    if (RtlDosPathNameToNtPathName_U(pDosPath, pNtPath, NULL, NULL))
    {
        Status = STATUS_SUCCESS;
    }
    return Status;
}






NTSTATUS NtPathToDosPath(PUNICODE_STRING pNtPath, wchar_t* pszDosPath)
{
    //删除指针
#define SafeDeletePoint(pData) { if(pData){delete pData;pData=NULL;} }

//删除数组
#define SafeDeleteArraySize(pData) { if(pData){delete []pData;pData=NULL;} }

    typedef struct _RTL_BUFFER {
        PWCHAR    Buffer;
        PWCHAR    StaticBuffer;
        SIZE_T    Size;
        SIZE_T    StaticSize;
        SIZE_T    ReservedForAllocatedSize; // for future doubling
        PVOID     ReservedForIMalloc; // for future pluggable growth
    } RTL_BUFFER, * PRTL_BUFFER;
    typedef struct _RTL_UNICODE_STRING_BUFFER {
        UNICODE_STRING String;
        RTL_BUFFER     ByteBuffer;
        WCHAR          MinimumStaticBufferForTerminalNul[sizeof(WCHAR)];
    } RTL_UNICODE_STRING_BUFFER, * PRTL_UNICODE_STRING_BUFFER;

    //定义变量
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    RTL_UNICODE_STRING_BUFFER DosPath = { 0 };
    wchar_t* ByteDosPathBuffer = NULL;
    wchar_t* ByteNtPathBuffer = NULL;


    typedef NTSTATUS(__stdcall* fnRtlNtPathNameToDosPathName)(ULONG Flags, PRTL_UNICODE_STRING_BUFFER Path, PULONG Disposition, PWSTR* FilePart);
    static fnRtlNtPathNameToDosPathName RtlNtPathNameToDosPathName = (fnRtlNtPathNameToDosPathName)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlNtPathNameToDosPathName");

    //参数效验
    if (IsBadReadPtr(pNtPath, 1) != 0)return Status;
    if (IsBadWritePtr(pszDosPath, 1) != 0)return Status;
    if (RtlNtPathNameToDosPathName == NULL)return Status;

    ByteDosPathBuffer = (wchar_t*)new char[pNtPath->Length + sizeof(wchar_t)];
    ByteNtPathBuffer = (wchar_t*)new char[pNtPath->Length + sizeof(wchar_t)];
    if (ByteDosPathBuffer == NULL || ByteNtPathBuffer == NULL) return Status;

    RtlZeroMemory(ByteDosPathBuffer, pNtPath->Length + sizeof(wchar_t));
    RtlZeroMemory(ByteNtPathBuffer, pNtPath->Length + sizeof(wchar_t));
    RtlCopyMemory(ByteDosPathBuffer, pNtPath->Buffer, pNtPath->Length);
    RtlCopyMemory(ByteNtPathBuffer, pNtPath->Buffer, pNtPath->Length);

    DosPath.ByteBuffer.Buffer = ByteDosPathBuffer;
    DosPath.ByteBuffer.StaticBuffer = ByteNtPathBuffer;
    DosPath.String.Buffer = pNtPath->Buffer;
    DosPath.String.Length = pNtPath->Length;
    DosPath.String.MaximumLength = pNtPath->Length;
    DosPath.ByteBuffer.Size = pNtPath->Length;
    DosPath.ByteBuffer.StaticSize = pNtPath->Length;


    Status = RtlNtPathNameToDosPathName(0, &DosPath, NULL, NULL);
    if (NT_SUCCESS(Status))
    {
        if (_wcsnicmp(pNtPath->Buffer, ByteDosPathBuffer, pNtPath->Length) == 0)
        {
            Status = STATUS_UNSUCCESSFUL;
        }
        else
        {
            RtlCopyMemory(pszDosPath, ByteDosPathBuffer, wcslen(ByteDosPathBuffer) * sizeof(wchar_t));
        }
    }
    else
    {
        Status = STATUS_UNSUCCESSFUL;
    }


    SafeDeleteArraySize(ByteDosPathBuffer);
    SafeDeleteArraySize(ByteNtPathBuffer);
    return Status;
}



BOOL CALLBACK EnumChildWindowsProc(HWND hwnd, LPARAM lParam)
{


    return true;
}
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam)
{
    DWORD dwPid = 0;
    ULONG64* p = (ULONG64*)lParam;
    GetWindowThreadProcessId(hwnd, &dwPid);
    if (dwPid == (DWORD)p[0])
    {
        p[1] = (ULONG64)hwnd;
       // EnumChildWindows(hwnd, EnumChildWindowsProc, lParam);
    }
    return true;
}

HWND CheackProcessHaveWnd(ULONG nPid)
{
    ULONG64 data[2] = { nPid,0 };

    if (EnumWindows(EnumWindowsProc, (LPARAM)data))
    {
        return (HWND)data[1];;
    }

    return 0;
}




DWORD WINAPI RemoteExecFinal(LPVOID param)
{
    char* mem = static_cast<char*>(param);
    char* exc = mem + 1024;

    HANDLE process = g_process;

    DWORD tick = GetTickCount();
    DWORD once = 0;
    SIZE_T lpNumberOfBytesRead = 0;
    while (GetTickCount() - tick < 4000 && !once)
    {
        ReadProcessMemory(process, exc + 0x59, &once, 4, &lpNumberOfBytesRead);
        Sleep(100);
    }

    WriteProcessMemory(process, dispatch_table_ptr, &dispatch_table, 8, &lpNumberOfBytesRead);



    if (VirtualFreeEx(process, mem, 0, MEM_RELEASE))
    {

    }

    CloseHandle(remote_exec_final);
    remote_exec_final = 0;
    g_process = 0;
    return 0;
}
BOOL CALLBACK EnumWindowFunc(HWND hwnd, LPARAM param)
{
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    if (pid == *(DWORD*)param)
    {
        /*
        * SMTO_NORMAL在等待函数返回时，调用线程不会被阻止处理其他请求。
        */
        SendMessageTimeoutW(hwnd, WM_NULL, 0, 0, SMTO_NORMAL, 1, nullptr);
        return FALSE;
    }
    return TRUE;
}
bool RemoteExec(HANDLE process,ULONG nPid, LPVOID address)
{
    if (remote_exec_final)
    {
        WaitForSingleObject(remote_exec_final, 5000);
    }
    g_process = process;


    SIZE_T lpNumberOfBytesRead = 0;
    PROCESS_BASIC_INFORMATION pbi = { 0 };
    if (!NT_SUCCESS(NtQueryInformationProcess(process, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr)))
        return false;

    char* peb = reinterpret_cast<char*>(pbi.PebBaseAddress);
    dispatch_table_ptr = peb + 0x58;
    dispatch_table = nullptr;
    if (!ReadProcessMemory(process, dispatch_table_ptr, &dispatch_table, 8, nullptr) || !dispatch_table)
        return false;

    char* mem = NULL;


    mem = (char*)VirtualAllocEx(process, NULL, 1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);


    if (!mem)
        return false;


    char* fdt = mem;
    char* exc = mem + 1024;

    char* tab[128];
    if (!ReadProcessMemory(process, dispatch_table, tab, sizeof(tab), &lpNumberOfBytesRead))
    {

        VirtualFreeEx(process, mem, 0, MEM_RELEASE);
        return false;
    }
    //0x460
    unsigned char excode[] = { 131,61,82,0,0,0,0,117,66,72,131,236,72,76,137,76,36,56,76,137,68,36,48,72,137,84,36,40,72,137,76,36,32,72,184,254,254,254,254,254,254,254,254,255,208,72,139,76,36,32,72,139,84,36,40,76,139,68,36,48,76,139,76,36,56,72,131,196,72,255,5,14,0,0,0,255,37,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
    *reinterpret_cast<LPVOID*>(excode + 0x23) = address;
    *reinterpret_cast<LPVOID*>(excode + 0x51) = tab[2];
    tab[2] = exc;


    if (!WriteProcessMemory(process, fdt, tab, sizeof(tab), &lpNumberOfBytesRead) ||
        !WriteProcessMemory(process, exc, excode, sizeof(excode), &lpNumberOfBytesRead) ||
        !WriteProcessMemory(process, dispatch_table_ptr, &fdt, 8, &lpNumberOfBytesRead))
    {
        VirtualFreeEx(process, mem, 0, MEM_RELEASE);
        return false;
    }

    //需要注意:  这里才是核心，如果要注入的dll 是有界面得话(如注入后弹出MessageBoxw的行为)程序直接崩溃
    EnumWindows(EnumWindowFunc, (LPARAM)&nPid);

    remote_exec_final = CreateThread(nullptr, 0, RemoteExecFinal, mem, 0, nullptr);

    return true;
}


