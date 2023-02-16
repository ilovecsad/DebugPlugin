#include "symbol.h"
#include "stl.h"
#include "utl.h"
BOOLEAN bInitSymbol = FALSE;
struct SymboolArry
{
	std::vector<PVOID> m_data;
};
SymboolArry* pFunc = nullptr;
namespace symbol
{
	NTSTATUS InitAllSymbolFunction(PVOID* arryFun, ULONG nDescArrySize)
	{
		if (bInitSymbol) {
			return STATUS_SUCCESS;
		}

		NTSTATUS nt = STATUS_UNSUCCESSFUL;
		if (!pFunc)
		{
			__try 
			{
				pFunc = new SymboolArry();
				pFunc->m_data.reserve(nDescArrySize);

				ULONG n = 0;
				ULONG64 p = (ULONG64)Uti::GetKernelBase(&n);

				for (ULONG i = 0; i < nDescArrySize; i++)
				{
					pFunc->m_data.push_back((PVOID)((ULONG64)arryFun[i] + p));
				}
				bInitSymbol = TRUE;
				nt = STATUS_SUCCESS;
			}
			__except (1)
			{
				bInitSymbol = FALSE;
			}
		}
		return nt;
	}

	PVOID MmGetSymbolRoutineAddress(FunctionType index)
	{
		int i = (int)index;
		int max = (int)FunctionType::eMax;

		if (!pFunc || !bInitSymbol || i >= max)return nullptr;

		return pFunc->m_data.at(i);
	}

	void FreeSymbolData()
	{
		bInitSymbol = FALSE;
		if (pFunc)
		{
			delete pFunc;
			pFunc = nullptr;
		}

	}

	

}