#pragma once
#include "stl.h"

namespace VM {
	EXTERN_C{

	NTSTATUS VmInitialization();
	void VmTermination();

	bool IsStartVt();

	}
}

