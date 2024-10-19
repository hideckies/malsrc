/*
Title: Detect Debugger with IsDebuggerPresent
Resources:
    - https://evasions.checkpoint.com/src/Anti-Debug/techniques/debug-flags.html
*/
#include <Windows.h>
#include <stdio.h>

VOID DetectDebuggerWithIsDebuggerPresent() {
    if (IsDebuggerPresent()) {
        printf("Debugger found! Exit the process.\n");
        ExitProcess(-1);
    }
}