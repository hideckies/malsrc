/*
Title: Detect VM with Processes
Resources:
	- https://evasions.checkpoint.com/src/Evasions/techniques/processes.html
*/
#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>

BOOL ProcessExists(LPCWSTR wProcName) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) return FALSE;

	PROCESSENTRY32 pe = {};

	BOOL bExist = FALSE;

	if (Process32First(hSnapshot, &pe)) {
		do {
			if (_wcsicmp(pe.szExeFile, wProcName) == 0) {
				bExist = TRUE;
				break;
			}
		} while (Process32Next(hSnapshot, &pe));
	}

	CloseHandle(hSnapshot);

	return bExist;
}

VOID DetectVMWithProcesses() {
	LPCWSTR procNames[] = {
        // JoeBox
        L"joeboxcontrol.exe",
        L"joeboxserver.exe",
		// QEMU
		L"qemu-ga.exe",
		// VirtualBox
		L"vboxservice.exe",
		L"vboxtray.exe",
		// VMWare
		L"vmacthlp.exe",
		L"vmount2.exe",
		L"vmtoolsd.exe",
		L"vmware.exe",
		L"vmwaretray.exe",
		L"vmwareservice.exe"
	};

	for (auto& procName : procNames) {
		if (ProcessExists(procName)) {
			printf("The process exists! Exit.\n");
			ExitProcess(-1);
		}
	}
}
