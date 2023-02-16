#include "vtdump.h"
#include "stl.h"
#define DUMP_MAX 100


struct DumpMark
{
	char mark[0x10];
	PVOID p;
};
struct DumpData
{
	ULONG_PTR hp_bug_check_code;
	ULONG_PTR param1;
	ULONG_PTR param2;
	ULONG_PTR param3;
};

struct DumpInfo
{
	std::vector<DumpData> data;
};

DumpMark g_Mark;
DumpInfo* info = NULL;
namespace dump {


	void initDump()
	{
		if (!info) 
		{
			RtlSecureZeroMemory(&g_Mark, sizeof(DumpMark));
			info = new DumpInfo;
			info->data.reserve(DUMP_MAX);

			strcpy(g_Mark.mark, "aaaabbbb");
			g_Mark.p = info->data.data();


		}
	}

	void dumpError(ULONG_PTR hp_bug_check_code, ULONG_PTR param1, ULONG_PTR param2, ULONG_PTR param3)
	{
		if (!info)return;
		if (info->data.size() > DUMP_MAX) return;

		info->data.push_back({ hp_bug_check_code ,param1 ,param2 ,param3 });


	}

	void freeDump()
	{
		if (info) 
		{
			delete info;
			info = nullptr;
		}
	}

}

/*
NTSTATUS NTAPI HookedNtUserBuildHwndListSeven(HANDLE hDesktop, HANDLE hwndParent, BOOLEAN bChildren, ULONG dwThreadId, ULONG lParam, PHANDLE pWnd, PULONG pBufSize)
{
	auto status = OriginalNtUserBuildHwndListSeven(hDesktop, hwndParent, bChildren, dwThreadId, lParam, pWnd, pBufSize);

	if (Hider::IsHidden(IoGetCurrentProcess(), HIDE_NT_USER_BUILD_HWND_LIST) == TRUE &&
		NT_SUCCESS(status) == TRUE &&
		pWnd != NULL &&
		pBufSize != NULL)
	{
		std::span handles = { pWnd, *pBufSize };
		const auto newEnd = std::remove_if(handles.begin(), handles.end(), [](auto Handle) {return Handle && IsWindowBad(Handle); });

		if (newEnd != handles.end())
		{
			const auto numberOfHandles = std::distance(newEnd, handles.end());
			RtlSecureZeroMemory(&*newEnd, sizeof(decltype(handles)::element_type) * numberOfHandles);
			*pBufSize -= static_cast<ULONG>(numberOfHandles);
		}
	}

	return status;
}

*/
