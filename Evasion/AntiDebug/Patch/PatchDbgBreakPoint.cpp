/*
Title: Patch DgbBreakPoint
Resources:
	- https://anti-debug.checkpoint.com/techniques/process-memory.html#hardware-breakpoints
*/
#include <Windows.h>

VOID PatchDbgBreakPoint() {
	HMODULE hNtdll = LoadLibraryA("ntdll.dll");
	if (!hNtdll) return;

	FARPROC pDbgBreakPoint = GetProcAddress(hNtdll, "DbgBreakPoint");
	if (!pDbgBreakPoint) {
		FreeLibrary(hNtdll);
		return;
	}

	DWORD dwOldProtect;
	if (!VirtualProtect(pDbgBreakPoint, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
		FreeLibrary(hNtdll);
		return;
	}

	*(PBYTE)pDbgBreakPoint = (BYTE)0xC3; // ret

    FreeLibrary(hNtdll);
}
