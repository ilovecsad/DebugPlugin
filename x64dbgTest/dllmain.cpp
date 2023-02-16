// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include <Windows.h>
#include "pluginsdk/_plugins.h"

#ifndef DLL_EXPORT
#define DLL_EXPORT __declspec(dllexport)
#endif
int pluginHandle;
HWND hwndDlg;
int hMenu;

extern "C" DLL_EXPORT bool pluginit(PLUG_INITSTRUCT * initStruct)
{
    initStruct->pluginVersion = 1;
    initStruct->sdkVersion = PLUG_SDKVERSION;
    strncpy_s(initStruct->pluginName, sizeof(initStruct->pluginName), "VehDebug", _TRUNCATE);
    pluginHandle = initStruct->pluginHandle;


    //_plugin_registercallback(pluginHandle, CB_MENUENTRY, cbMenuEntry);
    //_plugin_registercallback(pluginHandle, CB_DEBUGEVENT, cbDebugloop);
    //_plugin_registercallback(pluginHandle, CB_STOPDEBUG, cbReset);
   

    return true;
}

extern "C" DLL_EXPORT void plugsetup(PLUG_SETUPSTRUCT * setupStruct)
{
    hwndDlg = setupStruct->hwndDlg;
    hMenu = setupStruct->hMenu;
    LoadLibrary(L"DebugPlugin.dll");


}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

