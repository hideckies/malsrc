#ifndef MODULE_HASHING_HPP
#define MODULE_HASHING_HPP

#include <Windows.h>

#define NT_SUCCESS(Status)  (((NTSTATUS)(Status)) >= 0)

constexpr DWORD KEY = 0x48;
constexpr DWORD RANDOM_ADDR = 0x14da703d;

constexpr DWORD HASH_NTDLL		= 0x4644894;
constexpr DWORD HASH_KERNEL32	= 0x0058dc794;

// The following API is for testing purpose.
typedef NTSTATUS(NTAPI* _RtlGetVersion)(PRTL_OSVERSIONINFOW VersionInformation);

#endif // MODULE_HASHING_HPP