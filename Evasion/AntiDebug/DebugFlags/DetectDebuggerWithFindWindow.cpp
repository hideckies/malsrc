/*
Title: Detect Debugger with FindWindow
Resources:
	- https://medium.com/@X3non_C0der/anti-debugging-techniques-eda1868e0503
*/
#include <Windows.h>
#include <stdio.h>

VOID DetectDebuggerWithFindWindow() {
	LPCWSTR debuggerNames[] = {
		L"IDA",
		L"OllyDbg",
		L"WinDbg",
		L"x32dbg",
		L"x64dbg",
	};

	for (const auto& debuggerName : debuggerNames) {
		if (FindWindow(nullptr, debuggerName)) {
			printf("Debugger found! Exit the process.\n");
			ExitProcess(-1);
		}
	}
}
