#ifndef EKKO_HPP
#define EKKO_HPP

#include <Windows.h>

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define NtCurrentThread() ((HANDLE) (LONG_PTR) - 2)
#define NtCurrentProcess() ((HANDLE) (LONG_PTR) - 1)

typedef struct
{
	DWORD Length;
	DWORD MaximumLength;
	PVOID Buffer;
} USTRING;

typedef NTSTATUS(NTAPI* _NtContinue)(PCONTEXT ContextRecord, BOOLEAN TestAlert);
typedef NTSTATUS(WINAPI* _SystemFunction032)(struct ustring* data, const struct ustring* key);

VOID FreeAll(HMODULE hNtdll, HMODULE hAdvapi32, HANDLE hEvent, HANDLE hTimerQueue);
VOID EkkoSleep(DWORD dwSleepTime);
BOOL Ekko();

#endif // EKKO_HPP