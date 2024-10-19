/*
Title: Detect Debugger with BeingDebugged
Resources:
	- https://evasions.checkpoint.com/src/Anti-Debug/techniques/debug-flags.html
*/
#include <Windows.h>
#include <intrin.h>
#include <stdio.h>
#include "Helper.hpp"

VOID DetectDebuggerWithBeingDebugged() {
#ifndef _WIN64
	PPEB pPeb = (PPEB)__readfsdword(0x30);
#else
	PPEB pPeb = (PPEB)__readgsqword(0x60);
#endif

	if (pPeb->BeingDebugged) {
		printf("Debugger found! Exit the process.\n");
		ExitProcess(-1);
	}
}
