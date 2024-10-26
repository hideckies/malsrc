/*
Title: Detect VM with Usernames
Resources:
	- https://evasions.checkpoint.com/src/Evasions/techniques/generic-os-queries.html
*/
#include <Windows.h>
#include <stdio.h>
#include <wchar.h>

#define BUFFER_SIZE 256

VOID DetectVMWithUsernames() {
	LPCWSTR usernames[] = {
		// General
		L"admin",
		L"malware",
		L"sandbox",
		L"snort",
		L"virus",
		L"virusclone",
		// VMWare
		L"vmware",
	};

	WCHAR wUsername[BUFFER_SIZE] = { '\0' };
	DWORD dwSize = BUFFER_SIZE;
	if (!::GetUserNameW(wUsername, &dwSize)) {
		printf("Error: %d\n", GetLastError());
		return;
	}

	for (auto& username : usernames) {
		if (wcscmp(wUsername, username) == 0) {
			printf("VM detected! Exit the process.\n");
			ExitProcess(-1);
		}
	}
}
