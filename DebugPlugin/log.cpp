#include "log.h"
#include <ctime>

DebugLog logs;


DebugLog::DebugLog()
{
	m_lock.Init();
}

DebugLog::~DebugLog()
{
	m_lock.UnLoad();
}

void DebugLog::addLogEx(std::string sz)
{
	m_lock.Enter();
	m_RecordList.push_back(sz);
	m_lock.Leave();
}

void DebugLog::DoLogV(const char* fmt, va_list vargs)
{
	char varbuf[MAX_PATH*2] = { 0 };
	char message[MAX_PATH*2] = { 0 };
	char timebuf[MAX_PATH] = { 0 };
	// Format message time
	auto t = std::time(nullptr);
	tm stm;
	localtime_s(&stm, &t);
	std::strftime(timebuf, _countof(timebuf), "%Y-%m-%d %H:%M:%S", &stm);
	// Format messages
	vsprintf_s(varbuf, _countof(varbuf), fmt, vargs);
	sprintf_s(message, _countof(message), "%s:%s", timebuf, varbuf);

	addLogEx(message);
}

void DebugLog::addLog(char* szText, ...)
{
	va_list alist;
	bool result = false;

	va_start(alist, szText);
	DoLogV(szText, alist);
	va_end(alist);
}

void DebugLog::copyLog(std::list<std::string>& plist)
{
	m_lock.Enter();
	if (!m_RecordList.empty()) {
		std::list<std::string> ::iterator it;
		for (it = m_RecordList.begin(); it != m_RecordList.end(); ++it) {
			plist.push_back(*it);
		}
		m_RecordList.clear();
	}
	m_lock.Leave();
}

