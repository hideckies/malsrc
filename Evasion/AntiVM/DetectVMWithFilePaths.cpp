/*
Title: Detect VM with File Paths
Resources:
	- https://unprotect.it/technique/detecting-virtual-environment-files/
	- https://evasions.checkpoint.com/src/Evasions/techniques/filesystem.html
*/
#include <Windows.h>
#include <stdio.h>

BOOL FileExists(LPCWSTR wFilePath) {
	DWORD dwAttrib = GetFileAttributes(wFilePath);
	return (dwAttrib != INVALID_FILE_ATTRIBUTES) && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY);
}

VOID DetectVMWithFilePaths() {
	LPCWSTR filePaths[] = {
		// CAPE, CAPEv2
		L"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\agent.pyw",
		// Parallels
		L"C:\\Windows\\System32\\drivers\\prleth.sys",
		L"C:\\Windows\\System32\\drivers\\prlfs.sys",
		L"C:\\Windows\\System32\\drivers\\prlmouse.sys",
		L"C:\\Windows\\System32\\drivers\\prlvideo.sys",
		L"C:\\Windows\\System32\\drivers\\prltime.sys",
		L"C:\\Windows\\System32\\drivers\\prl_pv32.sys",
		L"C:\\Windows\\System32\\drivers\\prl_paravirt_32.sys",
		// VMWare
		L"C:\\Windows\\System32\\drivers\\vmhgfs.sys",
		L"C:\\Windows\\System32\\drivers\\vmmouse.sys",
		// VirtualBox
		L"C:\\Windows\\System32\\drivers\\VBoxMouse.sys",
		L"C:\\Windows\\System32\\drivers\\VBoxGuest.sys",
		L"C:\\Windows\\System32\\drivers\\VBoxSF.sys",
		L"C:\\Windows\\System32\\drivers\\VBoxVideo.sys",
		L"C:\\Windows\\System32\\vboxdisp.dll",
		L"C:\\Windows\\System32\\vboxhook.dll",
		L"C:\\Windows\\System32\\vboxmrxnp.dll",
		L"C:\\Windows\\System32\\vboxogl.dll",
		L"C:\\Windows\\System32\\vboxoglarrayspu.dll",
		L"C:\\Windows\\System32\\vboxoglcrutil.dll",
		L"C:\\Windows\\System32\\vboxoglerrorspu.dll",
		L"C:\\Windows\\System32\\vboxoglfeedbackupspu.dll",
		L"C:\\Windows\\System32\\vboxoglpackspu.dll",
		L"C:\\Windows\\System32\\vboxoglpassthroughspu.dll",
		L"C:\\Windows\\System32\\vboxservice.dll",
		L"C:\\Windows\\System32\\vboxtray.exe",
		L"C:\\Windows\\System32\\VBoxControl.exe"
	};

	for (auto& filePath : filePaths) {
		if (FileExists(filePath)) {
			printf("VM detected! Exit the process.\n");
			ExitProcess(-1);
		}
	}
}

int main() {
	DetectVMWithFilePaths();
	printf("VM not detected.\n");
	return 0;
}