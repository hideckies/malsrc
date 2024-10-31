/*
* Title: API Inline Hooking
*/
#include <Windows.h>
#include <stdio.h>

#define HOOK_BYTE_SIZE 12

typedef int (WINAPI* _MessageBoxA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);

unsigned char* targetFuncAddr = nullptr;

_MessageBoxA messageBoxA = nullptr;

// The original instructions are backuped here.
unsigned char origBytes[HOOK_BYTE_SIZE];

int WINAPI HookedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
BOOL Hook();
BOOL Unhook();
BOOL ApiInlineHooking();

int WINAPI HookedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
	printf("HookedMessageBoxA called\n");

	// Unhook the hooked function before executing it.
	Unhook();

	lpText = "Hooked";
	return messageBoxA(hWnd, lpText, lpCaption, uType);
}

BOOL Hook() {
	HMODULE hMod = GetModuleHandleA("user32.dll");
	if (!hMod) return FALSE;

	targetFuncAddr = (unsigned char*)GetProcAddress(hMod, "MessageBoxA");
	if (!targetFuncAddr) return FALSE;

	// Backup for unhooking later.
	memcpy(origBytes, targetFuncAddr, HOOK_BYTE_SIZE);

	DWORD dwOldProtect;
	if (!VirtualProtect(targetFuncAddr, HOOK_BYTE_SIZE, PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
		return FALSE;
	}

	// Write hook to the target function.
	targetFuncAddr[0] = 0x48; // REX.W prefix
	targetFuncAddr[1] = 0xB8;
	*(uintptr_t*)&targetFuncAddr[2] = (uintptr_t)HookedMessageBoxA; // mov rax, [address]
	targetFuncAddr[10] = 0xFF;
	targetFuncAddr[11] = 0xE0; // jmp rax

	if (!VirtualProtect(targetFuncAddr, HOOK_BYTE_SIZE, dwOldProtect, &dwOldProtect)) {
		return FALSE;
	}

	messageBoxA = (_MessageBoxA)targetFuncAddr;

	return TRUE;
}

BOOL Unhook() {
	DWORD dwOldProtect;
	if (!VirtualProtect(targetFuncAddr, HOOK_BYTE_SIZE, PAGE_EXECUTE_READWRITE, &dwOldProtect))
		return FALSE;

	// Restore the original instructions.
	memcpy(targetFuncAddr, origBytes, HOOK_BYTE_SIZE);

	if (!VirtualProtect(targetFuncAddr, HOOK_BYTE_SIZE, dwOldProtect, &dwOldProtect))
		return FALSE;

	return TRUE;
}

BOOL ApiInlineHooking() {
	if (!Hook()) return FALSE;

	MessageBoxA(nullptr, "This text should be replaced after hooking.", "InlineHooking", MB_OK);

	return TRUE;
}
