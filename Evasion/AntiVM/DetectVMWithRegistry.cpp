/*
Title: Detect VM with Registry
Resources:
	- https://unprotect.it/technique/detecting-virtual-environment-artefacts/
	- https://evasions.checkpoint.com/src/Evasions/techniques/registry.html
*/
#include <Windows.h>
#include <stdio.h>
#include <string>

VOID DetectVMWithRegistry() {
	LPCWSTR regPaths[] = {
		// Hyper-V
		L"HKLM\\SOFTWARE\\Microsoft\\Hyper-V",
		// VirtualBox
		L"SOFTWARE\\Oracle\\VirtualBox Guest Additions",
		L"HARDWARE\\ACPI\\DSDT\\VBOX__",
		L"HARDWARE\\ACPI\\FADT\\VBOX__",
		L"HARDWARE\\ACPI\\RSDT\\VBOX__",
		L"SYSTEM\\ControlSet001\\Services\\VBoxGuest",
		L"SYSTEM\\ControlSet001\\Services\\VBoxMouse",
		L"SYSTEM\\ControlSet001\\Services\\VBoxService",
		L"SYSTEM\\ControlSet001\\Services\\VBoxSF",
		L"SYSTEM\\ControlSet001\\Services\\VBoxVideo",
		// VMWare
		L"SOFTWARE\\VMWare, Inc.\\VMWare Tools",
	};

	HKEY hKey = nullptr;

	for (auto& regPath : regPaths) {
		if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, regPath, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
			printf("VM detected! Exit the process.\n");
			RegCloseKey(hKey);
			ExitProcess(-1);
		}
	}
}
