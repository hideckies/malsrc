#ifndef DIRTYVANITY_HPP
#define DIRTYVANITY_HPP

#include <Windows.h>

#define RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES 0x00000002
#define RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE 0x00000004 // don't update synchronization objects

typedef struct _RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION
{
    HANDLE ReflectionProcessHandle;
    HANDLE ReflectionThreadHandle;
    CLIENT_ID ReflectionClientId;
} RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION, * PRTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION;

typedef NTSTATUS(NTAPI* _RtlCreateProcessReflection)(HANDLE ProcessHandle, ULONG Flags, PVOID StartRoutine, PVOID StartContext, HANDLE EventHandle, PRTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION ReflectionInformation);

VOID FreeAll(HMODULE hNtdll, HANDLE hProcess, LPVOID lpBaseAddr);
BOOL InitFunctions(HMODULE hNtdll);
BOOL DirtyVanity();

#endif // DIRTYVANITY_HPP