#pragma once
#include <ntifs.h>


namespace dump 
{
    void initDump();
    void dumpError(ULONG_PTR hp_bug_check_code, ULONG_PTR param1, ULONG_PTR param2, ULONG_PTR param3);
    void freeDump();
}
    