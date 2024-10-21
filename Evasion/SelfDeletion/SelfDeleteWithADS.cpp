/*
Title: Self Delete with Alternate Data Streams (ADS)
*/
#include <Windows.h>
#include <stdio.h>
#include <string>

BOOL SelfDeleteWithADS() {
	WCHAR wSelfPath[MAX_PATH * 2] = { 0 };
	if (!GetModuleFileNameW(nullptr, wSelfPath, MAX_PATH * 2))
		return FALSE;

	// Rename this file.
	HANDLE hFile = CreateFile(
		wSelfPath,
		DELETE | SYNCHRONIZE,
		FILE_SHARE_READ,
		nullptr,
		OPEN_EXISTING,
		0,
		nullptr
	);
	if (!hFile) return FALSE;

	LPCWSTR wFileName = L":null";
	SIZE_T dwFileNameLength = wcslen(wFileName) * sizeof(WCHAR);
	PFILE_RENAME_INFO pRenameInfo = (PFILE_RENAME_INFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(FILE_RENAME_INFO) + dwFileNameLength);
	if (!pRenameInfo) return FALSE;
	RtlCopyMemory(pRenameInfo->FileName, wFileName, dwFileNameLength);
	pRenameInfo->FileNameLength = dwFileNameLength;

	if (!SetFileInformationByHandle(hFile, FileRenameInfo, pRenameInfo, sizeof(FILE_RENAME_INFO) + dwFileNameLength)) {
		HeapFree(GetProcessHeap(), 0, pRenameInfo);
		CloseHandle(hFile);
		return FALSE;
	}

	CloseHandle(hFile);

	// Delete this file.
	HANDLE hFile2 = CreateFile(
		wSelfPath,
		DELETE | SYNCHRONIZE,
		FILE_SHARE_READ,
		nullptr,
		OPEN_EXISTING,
		0,
		nullptr
	);
	if (!hFile2) {
		HeapFree(GetProcessHeap(), 0, pRenameInfo);
		return FALSE;
	}

	FILE_DISPOSITION_INFO fdi = { 0 };
	fdi.DeleteFile = TRUE;

	if (!SetFileInformationByHandle(hFile2, FileDispositionInfo, &fdi, sizeof(fdi))) {
		HeapFree(GetProcessHeap(), 0, pRenameInfo);
		return FALSE;
	}

	CloseHandle(hFile2);
	HeapFree(GetProcessHeap(), 0, pRenameInfo);

	return TRUE;
}
