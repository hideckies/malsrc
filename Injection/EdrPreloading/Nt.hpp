#ifndef NT_HPP
#define NT_HPP

#include <Windows.h>
#include <winternl.h>

typedef struct _LDR_DATA_TABLE_ENTRY2
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	WORD LoadCount;
	WORD TlsIndex;
} LDR_DATA_TABLE_ENTRY2, * PLDR_DATA_TABLE_ENTRY2;

typedef NTSTATUS(NTAPI* _LdrLoadDll)(PWSTR search_path, PULONG dll_characteristics, UNICODE_STRING* dll_name, PVOID* base_address);
typedef NTSTATUS(NTAPI* _NtAllocateVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
typedef NTSTATUS(NTAPI* _NtContinue)(PCONTEXT ThreadContext, BOOLEAN RaiseAlert);
typedef NTSTATUS(NTAPI* _NtProtectVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);

typedef LPVOID(WINAPI* _BaseThreadInitThunk)(DWORD unknown, LPVOID thread_start, LPVOID param);
typedef void(WINAPI* _OutputDebugStringW)(LPCWSTR lpOutputString);

#endif // NT_HPP