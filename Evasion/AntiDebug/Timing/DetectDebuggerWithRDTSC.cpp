/*
Title: Detect Debugger with RDTSC
Resources:
	- https://unprotect.it/technique/rdtsc/
WARNING: This technique is unstable because it depends on the architecture in which it is run.
*/
#include <Windows.h>
#include <stdio.h>

VOID DetectDebuggerWithRDTSC() {
	DWORD dwDiff = 20; // Adjust this value.

	ULONGLONG tsc1, tsc2, tsc3;
	
	for (DWORD i = 0; i < 10; i++) {
		tsc1 = __rdtsc();

		GetProcessHeap();

		tsc2 = __rdtsc();

		CloseHandle(0);

		tsc3 = __rdtsc();

		if ((tsc3 - tsc2) / (tsc2 - tsc1) >= dwDiff) {
			// Debugger is not present.
			return;
		}
	}

	printf("Debugger found! Exit the process.\n");
	ExitProcess(-1);
}
