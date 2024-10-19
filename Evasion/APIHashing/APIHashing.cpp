/*
Title: API Hashing
Resources:
	- https://www.ired.team/offensive-security/defense-evasion/windows-api-hashing-in-malware
*/
#include <Windows.h>
#include <string>
#include "APIHashing.hpp"

DWORD StringToHash(CHAR* s) {
	size_t dwLen = strnlen_s(s, 50);
	DWORD dwHash = KEY;

	for (size_t i = 0; i < dwLen; i++) {
		dwHash += (dwHash * RANDOM_ADDR + s[i]) & 0xffffff;
	}

	return dwHash;
}

LPVOID GetProcAddressByHash(CHAR* sLibrary, DWORD dwHash) {
	HMODULE hLibBase = LoadLibraryA(sLibrary);
	if (!hLibBase) return nullptr;

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hLibBase;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)hLibBase + pDosHeader->e_lfanew);
	DWORD_PTR dwExportDirRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)hLibBase + dwExportDirRVA);

	PDWORD pdwAddrOfFuncsRVA = (PDWORD)((DWORD_PTR)hLibBase + pExportDir->AddressOfFunctions);
	PDWORD pdwAddrOfNamesRVA = (PDWORD)((DWORD_PTR)hLibBase + pExportDir->AddressOfNames);
	PWORD pwAddrOfNameOrdinalsRVA = (PWORD)((DWORD_PTR)hLibBase + pExportDir->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pExportDir->NumberOfFunctions; i++) {
		DWORD dwFuncNameRVA = pdwAddrOfNamesRVA[i];
		DWORD_PTR dwFuncNameVA = (DWORD_PTR)hLibBase + dwFuncNameRVA;
		CHAR* sFuncName = (CHAR*)dwFuncNameVA;

		DWORD dwFuncHash = StringToHash(sFuncName);
		if (dwFuncHash == dwHash) {
			DWORD_PTR dwFuncAddrRVA = pdwAddrOfFuncsRVA[pwAddrOfNameOrdinalsRVA[i]];
			return (LPVOID)((DWORD_PTR)hLibBase + dwFuncAddrRVA);
		}
	}

	return nullptr;
}

BOOL APIHashing() {
	_MessageBoxA messageBoxA = reinterpret_cast<_MessageBoxA>(GetProcAddressByHash((CHAR*)"user32.dll", HASH_MESSAGEBOXA));

	messageBoxA(nullptr, "Test", "Test", MB_OK);

	return TRUE;
}
