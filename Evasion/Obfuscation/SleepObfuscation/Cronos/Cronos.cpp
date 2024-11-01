/*
Title: Cronos
Resources:
	- https://github.com/Idov31/Cronos
*/
#include <Windows.h>
#include <Psapi.h>
#include <stdio.h>
#include "Cronos.hpp"

VOID FreeAll(
	HMODULE hNtdll,
	HMODULE hAdvapi32,
	HANDLE hProtectionRWTimer,
	HANDLE hEncryptionTime,
	HANDLE hDecryptionTimer,
	HANDLE hProtectionRWXTimer,
	HANDLE hThreadTimer
) {
	if (hNtdll)
		FreeLibrary(hNtdll);
	if (hAdvapi32)
		FreeLibrary(hAdvapi32);
	if (hProtectionRWTimer)
		CloseHandle(hProtectionRWTimer);
	if (hEncryptionTime)
		CloseHandle(hEncryptionTime);
	if (hDecryptionTimer)
		CloseHandle(hDecryptionTimer);
	if (hProtectionRWXTimer)
		CloseHandle(hProtectionRWXTimer);
	if (hThreadTimer)
		CloseHandle(hThreadTimer);
}

BOOL Compare(const BYTE* pData, const BYTE* bMask, const char* szMask) {
	for (; *szMask; ++szMask, ++pData, ++bMask)
		if (*szMask == 'x' && *pData != *bMask)
			return FALSE;

	return TRUE;
}

DWORD_PTR FindPattern(DWORD_PTR dwAddress, DWORD dwLen, PBYTE bMask, PCHAR szMask) {
	for (DWORD i = 0; i < dwLen; i++)
		if (Compare((PBYTE)(dwAddress + i), bMask, szMask))
			return (DWORD_PTR)(dwAddress + i);

	return 0;
}

DWORD_PTR FindInModule(LPCSTR moduleName, PBYTE bMask, PCHAR szMask) {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)GetModuleHandleA(moduleName);
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)pDosHeader + pDosHeader->e_lfanew);
	DWORD_PTR dwSecOffset = (DWORD_PTR)pDosHeader + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS);
	PIMAGE_SECTION_HEADER pSecHeader = (PIMAGE_SECTION_HEADER)dwSecOffset;
	DWORD_PTR dwAddr = FindPattern((DWORD_PTR)pDosHeader + pSecHeader->VirtualAddress, pSecHeader->SizeOfRawData, bMask, szMask);
	return dwAddr;
}

PVOID FindGadget(PBYTE hdrParserFuncB, PCHAR hdrParserFunctMask) {
	HANDLE hProcess = GetCurrentProcess();
	if (!hProcess) return nullptr;

	HMODULE* moduleList = (HMODULE*)malloc(SIZE_MODULE_LIST * sizeof(HMODULE));
	DWORD dwBytesNeeded;
	if (!EnumProcessModules(hProcess, moduleList, SIZE_MODULE_LIST * sizeof(HMODULE), &dwBytesNeeded)) {
		CloseHandle(hProcess);
		free(moduleList);
		return nullptr;
	}
	if (dwBytesNeeded > SIZE_MODULE_LIST * sizeof(HMODULE)) {
		moduleList = (HMODULE*)realloc(moduleList, dwBytesNeeded);
		if (!EnumProcessModules(hProcess, moduleList, SIZE_MODULE_LIST * sizeof(HMODULE), &dwBytesNeeded)) {
			CloseHandle(hProcess);
			free(moduleList);
			return nullptr;
		}
	}

	LPSTR moduleName = nullptr;
	DWORD_PTR dwModule = 0;
	for (int i = 1; i < (dwBytesNeeded / sizeof(HMODULE)); i++) {
		moduleName = (LPSTR)malloc(MAX_MODULE_NAME * sizeof(CHAR));
		if (GetModuleFileNameExA(hProcess, moduleList[i], moduleName, MAX_MODULE_NAME * sizeof(CHAR)) == 0) {
			CloseHandle(hProcess);
			free(moduleList);
			free(moduleName);
			return nullptr;
		}
		dwModule = FindInModule(moduleName, hdrParserFuncB, hdrParserFunctMask);
		if (dwModule) break;
	}

	CloseHandle(hProcess);
	free(moduleList);
	free(moduleName);

	return (PVOID)dwModule;
}

VOID CronosSleep(int sleepTime) {
	HMODULE hImageBase = GetModuleHandleA(nullptr);
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hImageBase;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)hImageBase + pDosHeader->e_lfanew);
	DWORD dwImageSize = pNtHeaders->OptionalHeader.SizeOfImage;
	
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	HMODULE hAdvapi32 = LoadLibraryA("advapi32.dll");
	if (!hNtdll || !hAdvapi32) {
		return;
	}
	_NtContinue ntContinue = reinterpret_cast<_NtContinue>(GetProcAddress(hNtdll, "NtContinue"));
	if (!ntContinue) {
		FreeAll(hNtdll, hAdvapi32, nullptr, nullptr, nullptr, nullptr, nullptr);
		return;
	}
	_SystemFunction032 systemFunction032 = reinterpret_cast<_SystemFunction032>(GetProcAddress(hAdvapi32, "SystemFunction032"));
	if (!systemFunction032) {
		FreeAll(hNtdll, hAdvapi32, nullptr, nullptr, nullptr, nullptr, nullptr);
		return;
	}

	CHAR keyBuf[16] = { 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18 };
	DATA_KEY key = { 0 };
	key.Buffer = keyBuf;
	key.Length = key.MaximumLength = 16;
	CRYPT_BUFFER image = { 0 };
	image.Buffer = (PVOID)hImageBase;
	image.Length = image.MaximumLength = dwImageSize;

	HANDLE hProtectionRWTimer = CreateWaitableTimerW(nullptr, TRUE, L"ProtectionRWTimer");
	HANDLE hEncryptionTimer = CreateWaitableTimerW(nullptr, TRUE, L"EncryptionTimer");
	HANDLE hDecryptionTimer = CreateWaitableTimerW(nullptr, TRUE, L"DecryptionTimer");
	HANDLE hProtectionRWXTimer = CreateWaitableTimerW(nullptr, TRUE, L"ProtectionRWXTimer");
	HANDLE hThreadTimer = CreateWaitableTimerW(nullptr, TRUE, L"ThreadTimer");
	if (!hProtectionRWTimer || !hEncryptionTimer || !hDecryptionTimer || !hProtectionRWXTimer || !hThreadTimer) {
		FreeAll(hNtdll, hAdvapi32, hProtectionRWTimer, hEncryptionTimer, hDecryptionTimer, hProtectionRWXTimer, hThreadTimer);
		return;
	}

	LARGE_INTEGER lgProtectionRWDueTime;
	InitializeTimerMs(&lgProtectionRWDueTime, 0);
	LARGE_INTEGER lgEncryptionDueTime;
	InitializeTimerMs(&lgEncryptionDueTime, 1);
	LARGE_INTEGER lgDecryptionDueTime;
	InitializeTimerMs(&lgDecryptionDueTime, sleepTime - 1);
	LARGE_INTEGER lgProtectionRWXDueTime;
	InitializeTimerMs(&lgProtectionRWXDueTime, sleepTime);
	LARGE_INTEGER lgThreadDueTime;
	InitializeTimerMs(&lgThreadDueTime, 0);

	CONTEXT ctxProtectionRW = { 0 };
	CONTEXT ctxEncryption = { 0 };
	CONTEXT ctxDecryption = { 0 };
	CONTEXT ctxProtectionRWX = { 0 };
	CONTEXT ctxThread = { 0 };

	// Capture apc context.
	if (!SetWaitableTimer(hThreadTimer, &lgThreadDueTime, 0, (PTIMERAPCROUTINE)RtlCaptureContext, &ctxThread, FALSE)) {
		FreeAll(hNtdll, hAdvapi32, hProtectionRWTimer, hEncryptionTimer, hDecryptionTimer, hProtectionRWXTimer, hThreadTimer);
		return;
	}
	SleepEx(INFINITE, TRUE);

	// Create the contexts.
	memcpy(&ctxProtectionRW, &ctxThread, sizeof(CONTEXT));
	memcpy(&ctxEncryption, &ctxThread, sizeof(CONTEXT));
	memcpy(&ctxDecryption, &ctxThread, sizeof(CONTEXT));
	memcpy(&ctxProtectionRWX, &ctxThread, sizeof(CONTEXT));

	DWORD dwOldProtect = 0;

	// VirtualProtect(ImageBase, ImageSize, PAGE_READWRITE, &OldProtect)
	ctxProtectionRW.Rsp -= (8 + 0x150);
	ctxProtectionRW.Rip = reinterpret_cast<DWORD_PTR>(VirtualProtect);
	ctxProtectionRW.Rcx = reinterpret_cast<DWORD_PTR>(hImageBase);
	ctxProtectionRW.Rdx = dwImageSize;
	ctxProtectionRW.R8 = PAGE_READWRITE;
	ctxProtectionRW.R9 = reinterpret_cast<DWORD_PTR>(&dwOldProtect);

	// SystemFunction032 (&Key, &Img)
	ctxEncryption.Rsp -= (8 + 0xf0);
	ctxEncryption.Rip = reinterpret_cast<DWORD_PTR>(systemFunction032);
	ctxEncryption.Rcx = reinterpret_cast<DWORD_PTR>(&image);
	ctxEncryption.Rdx = reinterpret_cast<DWORD_PTR>(&key);

	// SystemFunction032 (&Key, &Img)
	ctxDecryption.Rsp -= (8 + 0x90);
	ctxDecryption.Rip = reinterpret_cast<DWORD_PTR>(systemFunction032);
	ctxDecryption.Rcx = reinterpret_cast<DWORD_PTR>(&image);
	ctxDecryption.Rdx = reinterpret_cast<DWORD_PTR>(&key);

	// VirtualProtect(ImageBase, ImageSize, PAGE_READWRITE, &OldProtect)
	ctxProtectionRWX.Rsp -= (8 + 0x30);
	ctxProtectionRWX.Rip = reinterpret_cast<DWORD_PTR>(VirtualProtect);
	ctxProtectionRWX.Rcx = reinterpret_cast<DWORD_PTR>(hImageBase);
	ctxProtectionRWX.Rdx = dwImageSize;
	ctxProtectionRWX.R8 = PAGE_EXECUTE_READWRITE;
	ctxProtectionRWX.R9 = reinterpret_cast<DWORD_PTR>(&dwOldProtect);

	// Get the gadgets for the SleepEx ROP.
	PVOID pRcxGadget = FindGadget((PBYTE)"\x59\xc3", (PCHAR)"xx");
	PVOID pRdxGadget = FindGadget((PBYTE)"\x5a\xc3", (PCHAR)"xx");
	PVOID pShadowFixGadget = FindGadget((PBYTE)"\x48\x83\xc4\x20\x5f\xc3", (PCHAR)"xxxxxx");
	if (!pRcxGadget || !pRdxGadget || !pShadowFixGadget) {
		FreeAll(hNtdll, hAdvapi32, hProtectionRWTimer, hEncryptionTimer, hDecryptionTimer, hProtectionRWXTimer, hThreadTimer);
		return;
	}

	// Set the timers.
	if (
		!SetWaitableTimer(hDecryptionTimer, &lgDecryptionDueTime, 0, (PTIMERAPCROUTINE)ntContinue, &ctxDecryption, FALSE) ||
		!SetWaitableTimer(hProtectionRWXTimer, &lgProtectionRWXDueTime, 0, (PTIMERAPCROUTINE)ntContinue, &ctxProtectionRWX, FALSE) ||
		!SetWaitableTimer(hProtectionRWTimer, &lgProtectionRWDueTime, 0, (PTIMERAPCROUTINE)ntContinue, &ctxProtectionRW, FALSE) ||
		!SetWaitableTimer(hEncryptionTimer, &lgEncryptionDueTime, 0, (PTIMERAPCROUTINE)ntContinue, &ctxEncryption, FALSE)
	) {
		FreeAll(hNtdll, hAdvapi32, hProtectionRWTimer, hEncryptionTimer, hDecryptionTimer, hProtectionRWXTimer, hThreadTimer);
		return;
	}

	// Execute the code.
	QuadSleep(pRcxGadget, pRdxGadget, pShadowFixGadget, (PVOID)SleepEx);

	FreeAll(hNtdll, hAdvapi32, hProtectionRWTimer, hEncryptionTimer, hDecryptionTimer, hProtectionRWXTimer, hThreadTimer);
	return;
}


BOOL Cronos() {
	do {
		printf("CronosSleep: Start\n");
		CronosSleep(4);
		printf("CronosSleep: Finish\n\n");
	} while (TRUE);

	return TRUE;
}

int main() {
	Cronos();
	return 0;
}