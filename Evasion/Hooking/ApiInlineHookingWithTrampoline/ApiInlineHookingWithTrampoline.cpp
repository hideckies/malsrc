/*
* Title: API Inline Hooking with Trampoline
* Resources:
*	- https://blog.securehat.co.uk/process-injection/manually-implementing-inline-function-hooking
*	- https://unprotect.it/technique/inline-hooking/
* Status: This code crashes (0xc0000005) when invoking the trampolineMessageBoxA in the HookedMessageBoxA. And I have no idea how to fix...
*/
#include <Windows.h>
#include <stdio.h>

#define HOOK_BYTE_SIZE 12

typedef int (WINAPI* _MessageBoxA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);

unsigned char* targetFuncAddr = nullptr;
unsigned char* trampolineAddr = nullptr;

_MessageBoxA trampolineMessageBoxA = nullptr;

// The original instructions are backuped here.
unsigned char origBytes[HOOK_BYTE_SIZE];

int WINAPI HookedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
	printf("HookedMessageBoxA called\n");
	lpText = "Hooked";
	return trampolineMessageBoxA(hWnd, lpText, lpCaption, uType);
}

BOOL Hook() {
	HMODULE hMod = GetModuleHandleA("user32.dll");
	if (!hMod) return FALSE;

	targetFuncAddr = (unsigned char*)GetProcAddress(hMod, "MessageBoxA");
	if (!targetFuncAddr) return FALSE;
	trampolineAddr = (unsigned char*)VirtualAlloc(nullptr, 64, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!trampolineAddr) return FALSE;

	// Backup for unhooking later.
	memcpy(origBytes, targetFuncAddr, HOOK_BYTE_SIZE);

	// -------------------------------------------------------------------------------------------------- //
	// Set the trampoline function
	// -------------------------------------------------------------------------------------------------- //

	// Copy the first N bytes from the target function to the trampoline function.
	memcpy(trampolineAddr, targetFuncAddr, HOOK_BYTE_SIZE);

	// Append instructions for jumping back to the original function after the hook.
	trampolineAddr[HOOK_BYTE_SIZE] = 0x48; // REX.W prefix
	trampolineAddr[HOOK_BYTE_SIZE + 1] = 0xB8;
	*(uintptr_t*)&trampolineAddr[HOOK_BYTE_SIZE + 2] = (uintptr_t)(targetFuncAddr + HOOK_BYTE_SIZE); // mov rax, [address]
	trampolineAddr[HOOK_BYTE_SIZE + 10] = 0xFF;
	trampolineAddr[HOOK_BYTE_SIZE + 11] = 0xE0; // jmp rax

	trampolineMessageBoxA = (_MessageBoxA)trampolineAddr;

	// -------------------------------------------------------------------------------------------------- //
	// Set the original function
	// -------------------------------------------------------------------------------------------------- //

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

	VirtualFree(trampolineAddr, 0, MEM_RELEASE);

	return TRUE;
}

BOOL ApiInlineHookingWithTrampoline() {
	if (!Hook()) return FALSE;
	MessageBoxA(nullptr, "This text should be replaced after hooking.", "Inline Hooking with Trampoline", MB_OK);

	if (!Unhook()) return FALSE;
	MessageBoxA(nullptr, "This text should appear after unhooking.", "Inline Hooking with Trampoline", MB_OK);

	return TRUE;
}
