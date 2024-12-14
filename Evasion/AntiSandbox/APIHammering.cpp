/*
* Title: API Hammering
* Resources:
*	- https://unprotect.it/snippet/api-hammering/224/
*/
#include <Windows.h>

VOID APIHammering() {
	for (int i = 0; i < 10000; i++) {
		GetCurrentProcessId();
		GetCurrentThreadId();
		GetFileAttributesW(L"C:\\Windows\\System32\\notepad.exe");
		GetLastError();
		GetTickCount64();
	}
}
