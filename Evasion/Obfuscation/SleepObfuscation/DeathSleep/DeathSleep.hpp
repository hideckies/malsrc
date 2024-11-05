#ifndef DEATHSLEEP_HPP
#define DEATHSLEEP_HPP

#include <Windows.h>

#define SIZE_MODULE_LIST 2
#define MAX_MODULE_NAME 100

#define InitializeCallbackInfo(ci, functionAddres, parameterAddres) \
    {                                                               \
        (ci)->timer = NULL;                                         \
        (ci)->isImpersonating = 0;                                  \
        (ci)->flags = 0;                                            \
        (ci)->callbackAddr = (WAITORTIMERCALLBACK)functionAddres;   \
        (ci)->paramAddr = parameterAddres;                          \
        (ci)->timerQueue = NULL;                                    \
        (ci)->isPeriodic = 0;                                       \
        (ci)->execControl = 0;                                      \
    }

typedef struct
{                                     //      NOTE                REQUIRED
    PTP_TIMER timer;                  // 0     Timer                   X
    DWORD64 m2;                       // 8     NULL
    DWORD64 isImpersonating;          // 16    0                       X
    ULONG flags;                      // 24    Flags                   X
    DWORD32 m5;                       // 28    NULL
    WAITORTIMERCALLBACK callbackAddr; // 32    Callback Address        X
    PVOID paramAddr;                  // 40    Parameter Address       X
    DWORD32 m7;                       // 48    0
    DWORD32 m8;                       // 52    Padding
    HANDLE timerQueue;                // 56    NULL                    X
    DWORD64 m9;                       // 64    0
    DWORD64 m10;                      // 72    0
    DWORD64 m11;                      // 80    0
    DWORD32 isPeriodic;               // 88    0                       X
    DWORD32 execControl;              // 92    0                       X
} CallbackInfo;

typedef NTSTATUS(NTAPI* _NtContinue)(PCONTEXT ContextRecord, BOOLEAN TestAlert);

extern "C" DWORD_PTR GetRsp();
extern "C" void      MoveRsp(DWORD, DWORD);

VOID InitFiletimeMs(FILETIME* ft, ULONGLONG millis);
BOOL Compare(const BYTE* data, const BYTE* bMask, const char* szMask);
DWORD_PTR FindPattern(DWORD_PTR dwAddr, DWORD dwLen, PBYTE bMask, PCHAR szMask);
DWORD_PTR FindInModule(LPCSTR lpModuleName, PBYTE bMask, PCHAR szMask);
PVOID FindGadget(PBYTE hdrParserFuncB, PCHAR hdrParserFuncMask);
VOID Awake(PVOID lpParam);
VOID Rebirth(PTP_CALLBACK_INSTANCE instance, PVOID lpParam, PTP_TIMER timer);
PVOID InitializeRopStack(
    PVOID pRopStackMemBlock,
    DWORD dwRopStackSize,
    PVOID pFunc,
    PVOID pArg,
    PVOID pRcxGadgetAddr,
    PVOID pShadowFixerGadgetAddr
);
VOID DeathSleep(ULONGLONG time);
DWORD WINAPI MainProgram();

#endif // DEATHSLEEP_HPP