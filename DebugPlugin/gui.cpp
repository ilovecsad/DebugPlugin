#include "gui.h"
#include  "minhook/MinHook.h"
#include "imgui/imgui_window.h"
#include "HookFunction.h"
#include "log.h"
#include "debugStruct.h"
#include "LoadSymbol.h"
#include "common.h"
#include "DriverIo.h"

 LONG_PTR orgWndProc = NULL;
ImVec4 green = { 0, 255, 0, 255 };
ImVec4 red = { 255, 0, 0, 255 }; //RGBA
ULONG64 nFunRva[eMax];
LRESULT WINAPI NewWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{

	switch (msg)
	{
	case WM_DESTROY:
	{
		break;
	}
	case WM_CLOSE:
	{
		if (IDOK == MessageBoxW(hWnd, L"Are you sure close wnd?(VK_HOME:Hide Wnd)", L"tip", MB_OKCANCEL))
		{
			break;
		}
		else {
			return TRUE;
		}
	}
	default:
		break;
	}

	return ((WNDPROC)orgWndProc)(hWnd, msg, wParam, lParam);
}

DWORD gui::guiThread(gui* pThis)
{
	if (!imgui_window::init(windows_Width, windows_Height)) {
		return false;
	}

	pThis->m_hwnd = imgui_window::GetMainHwnd();

	ImVec4 color = { 1.0f,0.1389f,0,1 };

	while (!pThis->m_done) {
		MSG msg;
		while (::PeekMessage(&msg, NULL, 0U, 0U, PM_REMOVE)) {
			::TranslateMessage(&msg);
			::DispatchMessage(&msg);
			if (msg.message == WM_QUIT)
				pThis->m_done = true;
		}
		if (pThis->m_done)
			break;
		if ((GetAsyncKeyState(VK_HOME) & 0x01))
		{
			ShowWindow(pThis->m_hwnd, pThis->m_show ? SW_SHOWDEFAULT : SW_HIDE);
			pThis->m_show = !pThis->m_show;
		}

		if (imgui_window::begin())
		{


			if (pThis->m_bInit)
			{

				ImGui::SetNextWindowPos({ 0, 0 }, ImGuiCond_Always);
				ImGui::SetNextWindowSize(imgui_window::GetGuiWindowSize(), ImGuiCond_Always);

				//无标题栏，无法拉伸
				ImGui::Begin("BackGround", NULL,
					ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoTitleBar |
					ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | /*ImGuiWindowFlags_NoBackground |*/
					ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollbar |
					ImGuiWindowFlags_NoSavedSettings);



				ImGui::BeginChild("item view", ImVec2(0, 0)); // Leave room for 1 line below us
				ImGui::Separator();
				if (ImGui::BeginTabBar("##Tabs", ImGuiTabBarFlags_None))
				{

					if (ImGui::BeginTabItem(u8"configs"))
					{
						if (ImGui::CollapsingHeader("Hook Apis"))
						{
							if (ImGui::BeginTable("split", 3))
							{
								for (int i = 0; i <= eReWriteSetThreadContext; i++)
								{
									ImGui::TableNextColumn();
									ImGui::Checkbox(pThis->m_hook.at(i).sz, &pThis->m_hook.at(i).bSelect);
								}
								ImGui::EndTable();
							}
						}

						if (pThis->m_bEnableDebug) {
							if (ImGui::CollapsingHeader(u8"Debugger Moden"))
							{
								ImGui::RadioButton(u8"Kernel Veh Debugger", &pThis->nDebugModel, eVeh); ImGui::SameLine();
								ImGui::RadioButton(u8"Window Debugger", &pThis->nDebugModel, eNormal); ImGui::SameLine();

								ImGui::Separator();
								ImGui::Text("Enum Module Types:");
								ImGui::RadioButton(u8"Api", &pThis->nEnumModuleTypes, eApi); ImGui::SameLine();
								ImGui::RadioButton(u8"Peb", &pThis->nEnumModuleTypes, ePeb); ImGui::SameLine();
								ImGui::RadioButton(u8"unSafe", &pThis->nEnumModuleTypes, eVad); ImGui::SameLine();

								ImGui::Separator();
								ImGui::Text("Others:");
								ImGui::Checkbox("PrivateHanleTable", &pThis->nPrivateHandleTable);
								ImGui::Checkbox("Enhancing Inject", &pThis->nInjectEx);
							}
						}

						ImGui::EndTabItem();
					}
					pThis->setHook();
				}
				if (ImGui::BeginTabItem("DebugLogs"))
				{


					if (pThis->m_RecordLogList.size() > 200) {
						pThis->bClear = true;
					}
					if (pThis->bClear) {
						pThis->m_RecordLogList.clear();
						pThis->bClear = false;
					}
					logs.copyLog(pThis->m_RecordLogList);
					if (!pThis->m_RecordLogList.empty())
					{
						std::string sz;
						std::list<std::string>::iterator it;
						for (it = pThis->m_RecordLogList.begin(); it != pThis->m_RecordLogList.end(); ++it)
						{
							sz = *it;
							ImGui::TextColored(red, sz.c_str());
						}
					}
					if (ImGui::Button("clear all logs"))
					{
						pThis->bClear = true;
					}

					ImGui::EndTabItem();
				}


				ImGui::EndTabBar();
				ImGui::EndChild();

				ImGui::End();

			}
			else
			{

				ImGui::SetNextWindowPos({ 0, 0 }, ImGuiCond_Always);
				ImGui::SetNextWindowSize(imgui_window::GetGuiWindowSize(), ImGuiCond_Always);
				ImGui::Begin("Init",
					0,
					ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize |
					ImGuiWindowFlags_AlwaysAutoResize);



				static bool b = false;
				if (!b) 
				{
					pThis->nDebugModel = eVeh;
					b = true;
					PVOID p = pThis;

					if (pThis->InitPtrForSymBool() && debugStruct::InitDebugStruct(p))
					{
						pThis->m_bInit = DriverIo::InstallDriver();
						if (pThis->m_bInit)
						{
							hook::initHookFunction(pThis->m_hook);
							orgWndProc = SetWindowLongPtrW(pThis->m_hwnd, GWLP_WNDPROC, (LONG_PTR)NewWndProc);
						}
					}

				}
				if (!pThis->m_bInit) {
					ImGui::Text("Init failed");
				}


				ImGui::End();

			}

			imgui_window::end();
		}

	}

	if (orgWndProc) {
		SetWindowLongPtrW(pThis->m_hwnd, GWLP_WNDPROC, (LONG_PTR)orgWndProc);
	}
	pThis->m_RecordLogList.clear();
	imgui_window::destroy();
	return 0;
}
void gui::setHook()
{
	for (int i = 0; i < m_hook.size(); i++)
	{
		if (m_hook.at(i).bSelect && !m_hook.at(i).bHook)
		{
			m_hook.at(i).bHook = true;
			MH_EnableHook(m_hook.at(i).pOrgFunc);

			logs.addLog("%s<%p> EnableHook", m_hook.at(i).sz, m_hook.at(i).pOrgFunc);
		}
		if ((m_hook.at(i).bSelect == false) && m_hook.at(i).bHook)
		{
			m_hook.at(i).bHook = false;
			MH_DisableHook(m_hook.at(i).pOrgFunc);
			logs.addLog("%s<%p> DisableHook", m_hook.at(i).sz, m_hook.at(i).pOrgFunc);
		}
	}
}
bool gui::CreateGui()
{
	if (!m_hImGuiThreadHanle)
	{
		m_hImGuiThreadHanle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)guiThread, this, 0, 0);
	}
	return  m_hImGuiThreadHanle ? TRUE : FALSE;
}

void gui::FreeGui()
{
	m_done = true;
	WaitForSingleObject(m_hImGuiThreadHanle, 500);
	DriverIo::UnLoadDriver();
	CloseHandle(m_hImGuiThreadHanle);
	m_hImGuiThreadHanle = 0;

}

int gui::GetDebugModels()
{
	return nDebugModel;
}

int gui::GetEnumModuleTypes()
{
	return nEnumModuleTypes;
}

bool gui::IsMapInject()
{
	return nInjectEx;
}

bool gui::IsEnablePrivateHandleTable()
{
	return nPrivateHandleTable;
}

BOOL gui::InitPtrForSymBool()
{
	BOOL bRet = FALSE;
	std::vector<std::string> szName;
	{
		szName.push_back("PsSuspendThread");
		szName.push_back("PsResumeThread");
		szName.push_back("ZwProtectVirtualMemory");
		szName.push_back("MiLocateAddress");
		szName.push_back("ZwCreateThreadEx");
		szName.push_back("ZwGetContextThread");
		szName.push_back("ZwSetContextThread");
	}

	vector<symbol_info> so;
	logs.addLog(u8"初始化未导出函数");
	std::string szTemp;
	szTemp.resize(MAX_PATH);
	DWORD nPid = GetProcessPid(L"explorer.exe");
	HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, nPid);
	if (h || h != INVALID_HANDLE_VALUE) {
		DWORD nSize = MAX_PATH;
		if (!QueryFullProcessImageNameA(h, 0, (LPSTR)szTemp.data(), &nSize)) {
			return FALSE;
		}

		if (!szTemp.empty())
		{
			int i = szTemp.rfind("\\");
			if (i != -1) {
				szTemp.replace(i, strlen("\\System32\\ntoskrnl.exe"), "\\System32\\ntoskrnl.exe");
			}
		}
		else {
			return FALSE;
		}

	}

	Symbol* sl = new Symbol(szTemp.c_str());


	if (bRet = sl->LoadSymbol(so))
	{

		for (int i = 0; i < szName.size(); i++)
		{
			for (int j = 0; j < so.size(); j++)
			{
				if (!stricmp(so.at(j).szFuncName, szName.at(i).c_str()))
				{
					nFunRva[i] = so.at(j).rva;
					if (nFunRva[i] == 0) {
						bRet = FALSE;
						goto END;
					}
					else {

						logs.addLog("%s<%x>", so.at(j).szFuncName, nFunRva[i]);
						bRet = TRUE;
					}
					break;
				}
			}

		}
	}
	szTemp.~string();
END:
	delete sl;
	return bRet;
}