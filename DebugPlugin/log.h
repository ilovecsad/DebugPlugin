#pragma once
#include <Windows.h>
#include <list>
#include <string>
#include <vector>
struct Lock
{
    CRITICAL_SECTION cs;

    void Init()
    {
        InitializeCriticalSection(&cs);
    }

    void Enter()
    {
        EnterCriticalSection(&cs);
    }
    BOOL TryEnter()
    {
        return TryEnterCriticalSection(&cs);
    }

    void Leave()
    {
        LeaveCriticalSection(&cs);
    }
    void UnLoad()
    {
        DeleteCriticalSection(&cs);
    }
};


class DebugLog
{
public:
    DebugLog();
	~DebugLog();
    void addLog(char* szText, ...);
    void copyLog(std::list<std::string>& plist);

private:
    void DoLogV(const char* fmt, va_list vargs);
    void addLogEx(std::string sz);
    Lock m_lock;
    std::list<std::string> m_RecordList;
};




extern DebugLog logs;

bool DoLogV(const char* fmt, va_list vargs);
