/*
Title: Detect Debugger with CheckRemoteDebuggerPresent
Resources:
    - https://evasions.checkpoint.com/src/Anti-Debug/techniques/debug-flags.html
*/
#include <Windows.h>
#include <stdio.h>

VOID DetectDebuggerWithCheckRemoteDebuggerPresent() {
    BOOL bDebuggerPresent;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebuggerPresent) && bDebuggerPresent) {
        printf("Debugger found! Exit the process.\n");
        ExitProcess(-1);
    }
}