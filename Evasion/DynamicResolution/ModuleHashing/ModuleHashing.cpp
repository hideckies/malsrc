/*
Title: Module Hashing
*/
#include <Windows.h>
#include <stdio.h>
#include <string>
#include "nt.hpp"
#include "ModuleHashing.hpp"

VOID FreeAll(HMODULE hNtdll, HMODULE hKernel32) {
	if (hNtdll)
		FreeLibrary(hNtdll);
	if (hKernel32)
		FreeLibrary(hKernel32);
}

DWORD StringToHashW(WCHAR* s) {
	size_t dwLen = wcsnlen_s(s, 50);
	DWORD dwHash = KEY;

	for (size_t i = 0; i < dwLen; i++) {
		WCHAR upperS = s[i];
		// uppercase => lowercase
		if (upperS >= L'a' && upperS <= L'z') {
			upperS -= (L'a' - L'A');
		}

		dwHash += (dwHash * RANDOM_ADDR + upperS) & 0xffffff;
	}

	return dwHash;
}

HMODULE GetModuleHandleByHash(DWORD dwHash) {
	PPEB pPeb = (PPEB)NtCurrentPeb();
	PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;

	// Get the first entry.
	PLIST_ENTRY pEntry = &pLdr->InLoadOrderModuleList;
	PLIST_ENTRY pCurrEntry = pEntry->Flink;

	for (; pEntry != pCurrEntry; pCurrEntry = pCurrEntry->Flink) {
		PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)pCurrEntry;

		if (StringToHashW(pDte->BaseDllName.Buffer) == dwHash) {
			return (HMODULE)pDte->DllBase;
		}
	}

	return nullptr;
}

BOOL ModuleHashing() {
	HMODULE hNtdll = GetModuleHandleByHash(HASH_NTDLL);
	if (!hNtdll) return FALSE;
	HMODULE hKernel32 = GetModuleHandleByHash(HASH_KERNEL32);
	if (!hKernel32) {
		FreeAll(hNtdll, nullptr);
		return FALSE;
	}
	
	// ------------------------------------------------------------------------------------------------- //
	// OPTION: Test if this works well.
	_RtlGetVersion rtlGetVersion = reinterpret_cast<_RtlGetVersion>(GetProcAddress(hNtdll, "RtlGetVersion"));
	if (rtlGetVersion) {
		RTL_OSVERSIONINFOW osInfo = { 0 };
		osInfo.dwOSVersionInfoSize = sizeof(osInfo);
		NTSTATUS status = rtlGetVersion(&osInfo);
		if (!NT_SUCCESS(status)) {
			FreeAll(hNtdll, hKernel32);
			return FALSE;
		}
		printf("Windows version %d.%d (Build %d)\n", osInfo.dwMajorVersion, osInfo.dwMinorVersion, osInfo.dwBuildNumber);
	}
	// ------------------------------------------------------------------------------------------------- //

	FreeAll(hNtdll, hKernel32);

	return TRUE;
}
