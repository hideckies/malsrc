#ifndef EDR_PRELOADING_HPP
#define EDR_PRELOADING_HPP

#include "Nt.hpp"

struct PTR_TABLE {
	_NtProtectVirtualMemory NtProtectVirtualMemory;
	_NtAllocateVirtualMemory NtAllocateVirtualMemory;
	_LdrLoadDll LdrLoadDll;
	_NtContinue NtContinue;
	_OutputDebugStringW OutputDebugStringW;
	LPVOID KiUserApcDispatcher;
};

#endif // EDR_PRELOADING_HPP