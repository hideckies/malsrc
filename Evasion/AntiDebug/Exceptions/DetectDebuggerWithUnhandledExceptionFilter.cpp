/*
Title: Detect Debugger with UnhandledExceptionFilter
Resources:
	- https://unprotect.it/technique/unhandled-exception-filter/
*/
#include <Windows.h>
#include <stdio.h>

BOOL bDebugged = TRUE;

LONG CustomUnhandledExceptionFilter(PEXCEPTION_POINTERS pExceptionInfo) {
	// If a debugger is present, then this function will not be reached.
	// That's because a debugger catches exceptions and handles them.
	bDebugged = FALSE;
	return EXCEPTION_CONTINUE_EXECUTION;
}

VOID DetectDebuggerWithUnhandledExceptionFilter() {
	LPTOP_LEVEL_EXCEPTION_FILTER lpOrigFilter = SetUnhandledExceptionFilter(CustomUnhandledExceptionFilter);
	RaiseException(EXCEPTION_FLT_DIVIDE_BY_ZERO, 0, 0, nullptr);
	SetUnhandledExceptionFilter(lpOrigFilter); // Restores the original filter.

	if (bDebugged) {
		printf("Debugger found! Exit the process.\n");
		ExitProcess(-1);
	}
}
