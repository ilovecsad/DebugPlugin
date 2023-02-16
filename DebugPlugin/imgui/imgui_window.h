#pragma once
#include "imgui.h"
#include "imgui_impl_dx11.h"
#include "imgui_impl_win32.h"
#include <atomic>
#include <d3d11.h>
#include <tchar.h>
#include <vector>

namespace imgui_window {
bool                      init(ULONG nWidth,ULONG nHeigth);
void                      destroy();
bool                      begin();
void                      end();
ID3D11Device* GetD3D11Device();
HWND                      GetMainHwnd();
ImVec2                    GetGuiWindowSize();
ID3D11ShaderResourceView *CreateDwmScreenShotShaderResourceView(void *);

} 