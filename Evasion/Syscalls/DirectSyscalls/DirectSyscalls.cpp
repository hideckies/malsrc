/*
Title: Direct Syscalls
Resources:
	- https://www.ired.team/offensive-security/defense-evasion/using-syscalls-directly-from-visual-studio-to-bypass-avs-edrs
	- https://github.com/cr-0w/maldev/tree/main/Direct%20Syscalls
*/
#include <Windows.h>
#include "DirectSyscalls.hpp"

BOOL GetSyscallNumber(HMODULE hNtdll, LPCSTR lpNtFuncName, PDWORD pdwNtFuncSSN) {
	UINT_PTR dwNtFuncAddr = (UINT_PTR)GetProcAddress(hNtdll, lpNtFuncName);
	if (!dwNtFuncAddr) return FALSE;

	*pdwNtFuncSSN = ((PBYTE)(dwNtFuncAddr + 0x4))[0];
	return TRUE;
}

BOOL DirectSyscalls() {
	HMODULE hNtdll = LoadLibraryA("ntdll.dll");
	if (!hNtdll) return FALSE;

	if (!GetSyscallNumber(hNtdll, "NtCreateFile", &NtCreateFileSSN)) {
		CloseHandle(hNtdll);
		return FALSE;
	}

	UNICODE_STRING uniFileName;
	RtlInitUnicodeString(&uniFileName, (PCWSTR)L"\\??\\C:\\Users\\deehi\\AppData\\Local\\Temp\\test.txt");
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

	CloseHandle(hNtdll);
	CloseHandle(hFile);

	return TRUE;
}
