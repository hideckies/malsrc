/*
* Title: Thread Local Storage
* Resources:
*	- https://github.com/xalicex/TLS-callback-injection/blob/main/TLS_Inject.cpp
*/
#include <Windows.h>
#include <stdio.h>

void NTAPI __stdcall TLSCallbacks(PVOID DllHandle, DWORD dwReason, PVOID Reserved);

//linker spec
#ifdef _M_IX86
#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:__tls_callback")
#else
#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:_tls_callback")
#endif

EXTERN_C
#ifdef _M_X64
#pragma const_seg (".CRT$XLB")
const
#else
#pragma data_seg (".CRT$XLB")
#endif
//end linker

//tls import
PIMAGE_TLS_CALLBACK _tls_callback = TLSCallbacks;
#pragma data_seg ()
#pragma const_seg ()
//end 

void NTAPI __stdcall TLSCallbacks(PVOID DllHandle, DWORD dwReason, PVOID Reserved) {
	MessageBox(nullptr, L"TLS Callback before the main function", L"Test", 0);
	ExitProcess(0);
}

int main() {
	printf("This message should not be printed.\n");
	return 0;
}