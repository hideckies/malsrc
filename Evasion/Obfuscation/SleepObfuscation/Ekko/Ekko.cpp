/*
Title: Ekko
Resources:
	- https://github.com/Cracked5pider/Ekko
*/
#include <Windows.h>
#include <stdio.h>
#include "Ekko.hpp"

VOID FreeAll(HMODULE hAdvapi32, HANDLE hEvent, HANDLE hTimerQueue) {
	if (hAdvapi32) {
		FreeLibrary(hAdvapi32);
		hAdvapi32 = nullptr;
	}
	if (hEvent) {
		CloseHandle(hEvent);
		hEvent = nullptr;
	}
	if (hTimerQueue) {
		CloseHandle(hTimerQueue);
		hTimerQueue = nullptr;
	}
}

VOID EkkoSleep(DWORD dwSleepTime) {
	HMODULE hImageBase = GetModuleHandleA(nullptr);
	if (!hImageBase) return;
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hImageBase;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)hImageBase + pDosHeader->e_lfanew);
	DWORD dwImageSize = pNtHeaders->OptionalHeader.SizeOfImage;

	// Resolve function addresses.
	HMODULE hNtdll = GetModuleHandleA("ntdll");
	HMODULE hAdvapi32 = LoadLibraryA("advapi32");
	if (!hNtdll || !hAdvapi32) {
		FreeAll(hAdvapi32, nullptr, nullptr);
		return;
	}
	_NtContinue ntContinue = reinterpret_cast<_NtContinue>(GetProcAddress(hNtdll, "NtContinue"));
	if (!ntContinue) {
		FreeAll(hAdvapi32, nullptr, nullptr);
		return;
	}
	_SystemFunction032 systemFunction032 = reinterpret_cast<_SystemFunction032>(GetProcAddress(hAdvapi32, "SystemFunction032"));
	if (!systemFunction032) {
		FreeAll(hAdvapi32, nullptr, nullptr);
		return;
	}

	// Replace it with your own key that can be randomly generated.
	CHAR keyBuf[16] = { 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 };
	USTRING key = { 0 };
	key.Buffer = keyBuf;
	key.Length = key.MaximumLength = 16;
	USTRING img = { 0 };
	img.Buffer = (PVOID)hImageBase;
	img.Length = img.MaximumLength = dwImageSize;

	HANDLE hEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
	if (!hEvent) {
		FreeAll(hAdvapi32, nullptr, nullptr);
		return;
	}
	HANDLE hTimerQueue = CreateTimerQueue();
	if (!hTimerQueue) {
		FreeAll(hAdvapi32, hEvent, nullptr);
		return;
	}

	HANDLE hNewTimer = nullptr;

	CONTEXT ctxThread = { 0 };
	CONTEXT ctxRopProtRW = { 0 };
	CONTEXT ctxRopMemEnc = { 0 };
	CONTEXT ctxRopDelay = { 0 };
	CONTEXT ctxRopMemDec = { 0 };
	CONTEXT ctxRopProtRWX = { 0 };
	CONTEXT ctxRopSetEvt = { 0 };

	DWORD dwOldProtect = 0;

	if (CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)RtlCaptureContext, &ctxThread, 0, 0, WT_EXECUTEINTIMERTHREAD)) {
		WaitForSingleObject(hEvent, 0x32);

		memcpy(&ctxRopProtRW,	&ctxThread, sizeof(CONTEXT));
		memcpy(&ctxRopMemEnc,	&ctxThread, sizeof(CONTEXT));
		memcpy(&ctxRopDelay,	&ctxThread, sizeof(CONTEXT));
		memcpy(&ctxRopMemDec,	&ctxThread, sizeof(CONTEXT));
		memcpy(&ctxRopProtRWX,	&ctxThread, sizeof(CONTEXT));
		memcpy(&ctxRopSetEvt,	&ctxThread, sizeof(CONTEXT));

		// VirtualProtect(ImageBase, ImageSize, PAGE_READWRITE, &OldProtect);
		ctxRopProtRW.Rsp -= 8;
		ctxRopProtRW.Rip = reinterpret_cast<DWORD_PTR>(VirtualProtect);
		ctxRopProtRW.Rcx = reinterpret_cast<DWORD_PTR>(hImageBase);
		ctxRopProtRW.Rdx = dwImageSize;
		ctxRopProtRW.R8 = PAGE_READWRITE;
		ctxRopProtRW.R9 = reinterpret_cast<DWORD_PTR>(&dwOldProtect);

		// SystemFunction032 (&Key, &Img)
		ctxRopMemEnc.Rsp -= 8;
		ctxRopMemEnc.Rip = reinterpret_cast<DWORD_PTR>(systemFunction032);
		ctxRopMemEnc.Rcx = reinterpret_cast<DWORD_PTR>(&img);
		ctxRopMemEnc.Rdx = reinterpret_cast<DWORD_PTR>(&key);

		// WaitForSingleObject( hTargetHdl, SleepTime );
		ctxRopDelay.Rsp -= 8;
		ctxRopDelay.Rip = reinterpret_cast<DWORD_PTR>(WaitForSingleObject);
		ctxRopDelay.Rcx = reinterpret_cast<DWORD_PTR>(NtCurrentProcess());
		ctxRopDelay.Rdx = dwSleepTime;

		// SystemFunction032( &Key, &Img );
		ctxRopMemDec.Rsp -= 8;
		ctxRopMemDec.Rip = reinterpret_cast<DWORD_PTR>(systemFunction032);
		ctxRopMemDec.Rcx = reinterpret_cast<DWORD_PTR>(&img);
		ctxRopMemDec.Rdx = reinterpret_cast<DWORD_PTR>(&key);

		// VirtualProtect(ImageBase, ImageSize, PAGE_EXECUTE_READWRITE, &OldProtect);
		ctxRopProtRWX.Rsp -= 8;
		ctxRopProtRWX.Rip = reinterpret_cast<DWORD_PTR>(VirtualProtect);
		ctxRopProtRWX.Rcx = reinterpret_cast<DWORD_PTR>(hImageBase);
		ctxRopProtRWX.Rdx = dwImageSize;
		ctxRopProtRWX.R8 = PAGE_EXECUTE_READWRITE;
		ctxRopProtRWX.R9 = reinterpret_cast<DWORD_PTR>(&dwOldProtect);

		// SetEvent(hEvent)
		ctxRopSetEvt.Rsp -= 8;
		ctxRopSetEvt.Rip = reinterpret_cast<DWORD_PTR>(SetEvent);
		ctxRopSetEvt.Rcx = reinterpret_cast<DWORD_PTR>(hEvent);

		CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)ntContinue, &ctxRopProtRW,	100, 0, WT_EXECUTEINTIMERTHREAD);
		CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)ntContinue, &ctxRopMemEnc,	200, 0, WT_EXECUTEINTIMERTHREAD);
		CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)ntContinue, &ctxRopDelay,	300, 0, WT_EXECUTEINTIMERTHREAD);
		CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)ntContinue, &ctxRopMemDec,	400, 0, WT_EXECUTEINTIMERTHREAD);
		CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)ntContinue, &ctxRopProtRWX,	500, 0, WT_EXECUTEINTIMERTHREAD);
		CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)ntContinue, &ctxRopSetEvt,	600, 0, WT_EXECUTEINTIMERTHREAD);

		WaitForSingleObject(hEvent, INFINITE);
	}

	DeleteTimerQueue(hTimerQueue);

	FreeAll(hAdvapi32, hEvent, hTimerQueue);
}

BOOL Ekko() {
	DWORD dwSleepTime = 4 * 1000;

	do {
		printf("EkkoSleep: Start\n");
		EkkoSleep(dwSleepTime);
		printf("EkkoSleep: Finish\n\n");
	} while (TRUE);

	return TRUE;
}
