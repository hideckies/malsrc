#ifndef THREADSTACKSPOOFING_HPP
#define THREADSTACKSPOOFING_HPP

#include <Windows.h>
#include <iomanip>
#include <vector>

typedef void (WINAPI* _Sleep)(DWORD dwMills);

struct HookedSleep
{
	_Sleep origSleep;
	BYTE sleepStub[16];
};

struct HookTrampolineBuffers
{
	// (Input) Buffer containing bytes that should be restored while unhooking.
	BYTE* originalBytes;
	DWORD originalBytesSize;

	// (Output) Buffer that will receive bytes present prior to trampoline installation/restoring.
	BYTE* previousBytes;
	DWORD previousBytesSize;
};

typedef std::unique_ptr<std::remove_pointer<HANDLE>::type, decltype(&::CloseHandle)> HandlePtr;

typedef NTSTATUS(NTAPI* _NtFlushInstructionCache)(HANDLE ProcessHandle, PVOID BaseAddress, SIZE_T Length);

BOOL InitFunctions();
void WINAPI MySleep(DWORD dwMilliseconds);
BOOL FastTrampoline(
	BOOL bInstallHook,
	BYTE* addressToHook,
	LPVOID lpJumpAddr,
	HookTrampolineBuffers* buffers
);
BOOL HookSleep();
VOID RunShellcode(LPVOID param);
BOOL InjectShellcode(unsigned char* shellcode, DWORD dwShellcodeSize, HandlePtr& thread);
BOOL ThreadStackSpoofing();

#endif // THREADSTACKSPOOFING_HPP