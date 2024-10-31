/*
* Title: IAT Hooking
* Resources:
*	- https://www.ired.team/offensive-security/code-injection-process-injection/import-adress-table-iat-hooking
*/
#include <Windows.h>
#include <string>
#include <stdio.h>

typedef int (WINAPI* _MessageBoxA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);

_MessageBoxA origMessageBoxA = MessageBoxA;

int WINAPI HookedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
	printf("HookedmessageBoxA called\n");
	lpText = "Hooked";
	return origMessageBoxA(hWnd, lpText, lpCaption, uType);
}

BOOL Hook(const char* targetFunctionName) {
	LPVOID lpImageBase = GetModuleHandleA(nullptr);
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpImageBase;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpImageBase + pDosHeader->e_lfanew);

	IMAGE_DATA_DIRECTORY importDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importDir.VirtualAddress + (DWORD_PTR)lpImageBase);

	LPCSTR libName = nullptr;
	HMODULE hLib = nullptr;
	PIMAGE_IMPORT_BY_NAME funcName = nullptr;

	while (pImportDescriptor->Name != 0) {
		libName = (DWORD_PTR)lpImageBase + (LPCSTR)pImportDescriptor->Name;
		hLib = LoadLibraryA(libName);

		if (hLib) {
			PIMAGE_THUNK_DATA pOrigFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)lpImageBase + pImportDescriptor->OriginalFirstThunk);
			PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)lpImageBase + pImportDescriptor->FirstThunk);

			while (pOrigFirstThunk->u1.AddressOfData != 0) {
				funcName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)lpImageBase + pOrigFirstThunk->u1.AddressOfData);

				std::string sFuncName = std::string(funcName->Name);

				// Find the address of the target function
				if (std::string(funcName->Name).compare(targetFunctionName) == 0) {
					SIZE_T dwBytesWritten = 0;
					DWORD dwOldProtect = 0;
					if (!VirtualProtect((LPVOID)(&pFirstThunk->u1.Function), 8, PAGE_READWRITE, &dwOldProtect)) {
						return FALSE;
					}

					// Swap the function address with the address of the hooked function.
					pFirstThunk->u1.Function = (DWORD_PTR)HookedMessageBoxA;
				}
				++pOrigFirstThunk;
				++pFirstThunk;
			}
		}
		pImportDescriptor++;
	}

	return TRUE;
}

BOOL IATHooking() {
	const char* targetFuncName = "MessageBoxA";

	if (!Hook(targetFuncName)) return FALSE;

	MessageBoxA(nullptr, "This text should be replaced after hooking.", "IAT Hooking", MB_OK);

	return TRUE;
}
