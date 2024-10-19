/*
Title: Detect Debugger with Kernel Debugger Information
Resources:
	- https://evasions.checkpoint.com/src/Anti-Debug/techniques/debug-flags.html
*/
#include <Windows.h>
#include <stdio.h>
#include "Helper.hpp"

VOID DetectDebuggerWithKernelDebugInfo() {
	HMODULE hNtdll = LoadLibraryA("ntdll.dll");
	if (!hNtdll) return;

	_NtQuerySystemInformation ntQuerySystemInformation = reinterpret_cast<_NtQuerySystemInformation>(GetProcAddress(hNtdll, "NtQuerySystemInformation"));
	if (!ntQuerySystemInformation) {
		FreeLibrary(hNtdll);
		return;
	}

	SYSTEM_KERNEL_DEBUGGER_INFORMATION debugInfo;

	NTSTATUS status = ntQuerySystemInformation(
		SystemKernelDebuggerInformation,
		&debugInfo,
		sizeof(debugInfo),
		nullptr
	);
	if (NT_SUCCESS(status) && debugInfo.KernelDebuggerEnabled && !debugInfo.KernelDebuggerNotPresent) {
		printf("Debugger found! Exit the process.\n");
		FreeLibrary(hNtdll);
		ExitProcess(-1);
	}
}
