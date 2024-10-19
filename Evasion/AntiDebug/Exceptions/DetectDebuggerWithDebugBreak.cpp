/*
Title: Detect Debugger with DebugBreak
Resources:
	- https://anti-debug.checkpoint.com/techniques/assembly.html
*/
#include <Windows.h>
#include <stdio.h>

VOID DetectDebuggerWithDebugBreak() {
	BOOL bDebugged = TRUE;

	__try {
		DebugBreak();
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		bDebugged = FALSE;
	}

	if (bDebugged) {
		printf("Debugger found! Exit the process.\n");
		ExitProcess(-1);
	}
}
