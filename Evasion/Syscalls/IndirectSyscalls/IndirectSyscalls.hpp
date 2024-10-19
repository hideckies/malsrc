#ifndef INDIRECT_SYSCALLS_HPP
#define INDIRECT_SYSCALLS_HPP

#include <Windows.h>
#include <winternl.h>

FORCEINLINE VOID RtlInitUnicodeString(
	_Out_ PUNICODE_STRING DestinationString,
	_In_opt_z_ PCWSTR SourceString
)
{
	if (SourceString)
		DestinationString->MaximumLength = (DestinationString->Length = (USHORT)(wcslen(SourceString) * sizeof(WCHAR))) + sizeof(UNICODE_NULL);
	else
		DestinationString->MaximumLength = DestinationString->Length = 0;

	DestinationString->Buffer = (PWCH)SourceString;
}

typedef unsigned __int64 QWORD;

extern "C" {
	DWORD NtCreateFileSSN;
	QWORD NtCreateFileSyscall;
}

extern "C" NTSTATUS NtCreateFile(
	PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	PLARGE_INTEGER AllocationSize,
	ULONG FileAttributes,
	ULONG ShareAccess,
	ULONG CreateDisposition,
	ULONG CreateOptions,
	PVOID EaBuffer,
	ULONG EaLength
);

BOOL GetSSNAndAddr(HMODULE hNtdll, LPCSTR lpNtFuncName, PDWORD ntFuncSSN, PUINT_PTR ntFuncSyscall);
BOOL IndirectSyscalls();

#endif // INDIRECT_SYSCALLS_HPP