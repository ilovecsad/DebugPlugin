#include <Windows.h>
#include "debugStruct.h"



BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    gui* pGui = nullptr;
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        if (!pGui) {
            pGui = new gui;
            pGui->CreateGui();
        }
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        debugStruct::FreeDebugStruct();
        break;
    }
    return TRUE;
}

