#ifndef BLINDSIDE_HPP
#define BLINDSIDE_HPP

#include <Windows.h>

#define HASH_NTDLL					0x3E8557
#define HASH_KERNEL32				0x6870A8F

#define HASH_LDRLOADDLL				0xAFEE49
#define HASH_NTREADVIRTUALMEMORY	0x353FB260DF
#define HASH_VIRTUALPROTECT			0x38EC8D55

typedef NTSTATUS(NTAPI* _LdrLoadDll)(PCWSTR DllPath, PULONG DllCharacteristics, PUNICODE_STRING DllName, PVOID* DllHandle);
typedef NTSTATUS(NTAPI* _NtReadVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead);

typedef BOOL(WINAPI* _VirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);

#endif // BLINDSIDE_HPP