/*
Title: Detect VM with Number of Processors
Resources:
	- https://evasions.checkpoint.com/src/Evasions/techniques/generic-os-queries.html
*/
#include <Windows.h>
#include <stdio.h>

VOID DetectVMWithNumberOfProcessors1() {
#ifndef _WIN64
	PULONG ulNumOfProcessors = (PULONG)(__readfsdword(0x30) + 0x64);
#else
	PULONG ulNumOfProcessors = (PULONG)(__readgsqword(0x60) + 0xB8);
#endif

	if (*ulNumOfProcessors <= 2) {
		printf("VM detected! Exit the process.\n");
		ExitProcess(-1);
	}
}

VOID DetectVMWithNumberOfProcessors2() {
	SYSTEM_INFO si;
	GetSystemInfo(&si);
	if (si.dwNumberOfProcessors <= 2) {
		printf("VM detected! Exit the process.\n");
		ExitProcess(-1);
	}
}
