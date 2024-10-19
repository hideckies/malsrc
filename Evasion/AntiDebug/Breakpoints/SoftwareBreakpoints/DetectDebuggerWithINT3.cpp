/*
Title: Detect Debugger with Software Breakpoints (INT3)
Resources:
	- https://anti-debug.checkpoint.com/techniques/process-memory.html
WARNING: This technique can result in false-positive so be cafeful when using it.
*/
#include <Windows.h>
#include <stdio.h>

VOID Func1() {
	printf("This function should be protected from debuggers.\n");
	return;
}

VOID Func2() {
	printf("This function should be protected from debugggers.\n");
	return;
}

VOID Func3() {
	printf("This function should be protected from debugggers.\n");
	return;
}

BOOL CheckByte(BYTE cByte, PVOID pMemory, SIZE_T dwMemorySize = 0) {
	PBYTE pBytes = (PBYTE)pMemory;
	for (SIZE_T i = 0; ; i++) {
		// Break on RET (0xC3) if we don't know the function's size.
		if (((dwMemorySize > 0) && (i >= dwMemorySize)) ||
			((dwMemorySize == 0) && (pBytes[i] == 0xC3)))
			break;

		if (pBytes[i] == cByte)
			return TRUE;
	}
	return FALSE;
}

VOID DetectDebuggerWithINT3() {
	PVOID funcsToCheck[] = {
		&Func1,
		&Func2,
		&Func3
	};
	for (auto funcAddr : funcsToCheck) {
		if (CheckByte(0xCC, funcAddr)) {
			printf("Debugger found! Exit the process.\n");
			ExitProcess(-1);
		}
	}
}
