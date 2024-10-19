/*
Title: Detect Debugger with processDebugflags
Resources:
    - https://evasions.checkpoint.com/src/Anti-Debug/techniques/debug-flags.html
*/
#include <Windows.h>
#include <stdio.h>
#include "Helper.hpp"

VOID DetectDebuggerWithProcessDebugFlags() {
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (!hNtdll) return;

    _NtQueryInformationProcess ntQueryInformationProcess = reinterpret_cast<_NtQueryInformationProcess>(GetProcAddress(hNtdll, "NtQueryInformationProcess"));
    if (!ntQueryInformationProcess) {
        FreeLibrary(hNtdll);
        return;
    }

    DWORD dwProcessDebugFlags, dwReturnLength;
    NTSTATUS status = ntQueryInformationProcess(
        GetCurrentProcess(),
        ProcessDebugFlags,
        &dwProcessDebugFlags,
        sizeof(DWORD),
        &dwReturnLength
    );
    if (NT_SUCCESS(status) && dwProcessDebugFlags == 0) {
        printf("Debugger found! Exit the process.\n");
        FreeLibrary(hNtdll);
        ExitProcess(-1);
    }

    FreeLibrary(hNtdll);
}