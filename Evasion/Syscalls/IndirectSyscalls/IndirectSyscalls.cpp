/*
Title: Indirect Syscalls
Resources:
	- https://github.com/cr-0w/maldev/tree/main/Indirect%20Syscalls
*/
#include <Windows.h>
#include "IndirectSyscalls.hpp"

// Get syscall number and address
BOOL GetSSNAndAddr(HMODULE hNtdll, LPCSTR lpNtFuncName, PDWORD ntFuncSSN, PUINT_PTR ntFuncSyscall) {
	UCHAR syscallOpcodes[2] = { 0x0f, 0x05 }; // = "syscall"

	UINT_PTR dwNtFuncAddr = (UINT_PTR)GetProcAddress(hNtdll, lpNtFuncName);
	if (!dwNtFuncAddr) return FALSE;

	*ntFuncSSN = ((PBYTE)(dwNtFuncAddr + 0x4))[0];
	*ntFuncSyscall = dwNtFuncAddr + 0x12;

	if (memcmp(syscallOpcodes, (PVOID)*ntFuncSyscall, sizeof(syscallOpcodes) != 0)) {
		return FALSE;
	}
	return TRUE;
}

BOOL IndirectSyscalls() {
	HMODULE hNtdll = LoadLibraryA("ntdll.dll");
	if (!hNtdll) return FALSE;

	if (!GetSSNAndAddr(hNtdll, "NtCreateFile", &NtCreateFileSSN, &NtCreateFileSyscall)) {
		CloseHandle(hNtdll);
		return FALSE;
	}

	// --------------------------------------------------------------------------------------- //
	// The following code is for testing purpose.

	UNICODE_STRING uniFileName;
	RtlInitUnicodeString(&uniFileName, (PCWSTR)L"\\??\\C:\\test.txt");
	IO_STATUS_BLOCK isb;
	ZeroMemory(&isb, sizeof(IO_STATUS_BLOCK));
	OBJECT_ATTRIBUTES oa;
	InitializeObjectAttributes(&oa, &uniFileName, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
	HANDLE hFile = nullptr;

	NTSTATUS status = NtCreateFile(
		&hFile,
		FILE_GENERIC_WRITE,
		&oa,
		&isb,
		0,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_WRITE,
		FILE_OVERWRITE_IF,
		FILE_SYNCHRONOUS_IO_NONALERT,
		nullptr,
		0
	);
	if (!NT_SUCCESS(status)) {
		CloseHandle(hNtdll);
		return FALSE;
	}
	// --------------------------------------------------------------------------------------- //

	CloseHandle(hNtdll);
	CloseHandle(hFile);

	return TRUE;
}
