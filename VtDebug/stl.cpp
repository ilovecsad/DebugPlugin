#include "stl.h"



// Workarounds https://github.com/tandasat/DdiMon/issues/34
EXTERN_C
{

_ACRTIMP void __cdecl _invoke_watson(_In_opt_z_ wchar_t const*,
	_In_opt_z_ wchar_t const*,
	_In_opt_z_ wchar_t const*,
	_In_ unsigned int,
	_In_ uintptr_t) {}

// Workarounds https://github.com/tandasat/DdiMon/issues/34
namespace std {
	_Prhand _Raise_handler;
}
}