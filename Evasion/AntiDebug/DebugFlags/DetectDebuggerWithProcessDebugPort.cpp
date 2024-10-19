/*
Title: Detect Debugger with ProcessDebugPort
Resources:
    - https://evasions.checkpoint.com/src/Anti-Debug/techniques/debug-flags.html
*/
#include <Windows.h>
#include <stdio.h>
#include "Helper.hpp"

VOID DetectDebuggerWithProcessDebugPort() {
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (!hNtdll) return;

    _NtQueryInformationProcess ntQueryInformationProcess = reinterpret_cast<_NtQueryInformationProcess>(GetProcAddress(hNtdll, "NtQueryInformationProcess"));
    if (!ntQueryInformationProcess) {
        FreeLibrary(hNtdll);
        return;
    }

    HANDLE hProcessDebugPort = nullptr;
    DWORD dwReturnLength = 0;
    NTSTATUS status = ntQueryInformationProcess(
        GetCurrentProcess(),
        ProcessDebugPort,
        &hProcessDebugPort,
        sizeof(HANDLE),
        &dwReturnLength
    );
    if (NT_SUCCESS(status) && hProcessDebugPort) {
        printf("Debugger found! Exit the process.\n");
        FreeLibrary(hNtdll);
        ExitProcess(-1);
    }

    FreeLibrary(hNtdll);
}