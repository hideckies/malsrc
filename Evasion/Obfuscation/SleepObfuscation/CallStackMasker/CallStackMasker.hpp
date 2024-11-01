#ifndef CALLSTACKMASKER_HPP
#define CALLSTACKMASKER_HPP

#include <Windows.h>
#include <intrin.h>
#include <string>
#include <map>

#define RBP_OP_INFO 0x5

typedef enum _UNWIND_OP_CODES {
    UWOP_PUSH_NONVOL = 0, /* info == register number */
    UWOP_ALLOC_LARGE,     /* no info, alloc size in next 2 slots */
    UWOP_ALLOC_SMALL,     /* info == size of allocation / 8 - 1 */
    UWOP_SET_FPREG,       /* no info, FP = RSP + UNWIND_INFO.FPRegOffset*16 */
    UWOP_SAVE_NONVOL,     /* info == register number, offset in next slot */
    UWOP_SAVE_NONVOL_FAR, /* info == register number, offset in next 2 slots */
    UWOP_SAVE_XMM128 = 8, /* info == XMM reg number, offset in next slot */
    UWOP_SAVE_XMM128_FAR, /* info == XMM reg number, offset in next 2 slots */
    UWOP_PUSH_MACHFRAME   /* info == 0: no error-code, 1: error-code */
} UNWIND_CODE_OPS;

typedef std::map<std::string, HMODULE> imageMap;
std::map<std::wstring, HMODULE> imageBaseMap;

typedef struct
{
    DWORD dwPid;
    DWORD dwTid;
    PVOID startAddr;
    ULONG totalRequiredStackSize;
    PVOID pFakeStackBuffer;
} threadToSpoof;

struct StackFrame {
    std::wstring targetDll;
    std::string targetFunc;
    ULONG offset;
    ULONG totalStackSize;
    BOOL requiresLoadLibrary;
    BOOL setsFramePointer;
    PVOID returnAddress;
    BOOL pushRbp;
    ULONG countOfCodes;
    BOOL pushRbpIndex;
    StackFrame() = default;
    StackFrame(std::wstring dllPath, std::string function, ULONG targetOffset, ULONG targetStackSize, bool bDllLoad) :
        targetDll(dllPath),
        targetFunc(function),
        offset(targetOffset),
        totalStackSize(targetStackSize),
        requiresLoadLibrary(bDllLoad),
        setsFramePointer(false),
        returnAddress(0),
        pushRbp(false),
        countOfCodes(0),
        pushRbpIndex(0)
    {
    };
};

__declspec(noinline) void* GetChildSP() {
    return (PCHAR)_AddressOfReturnAddress() + 8;
}

template<typename T>
T readProcessMemory(HANDLE hProcess, LPVOID targetAddress)
{
    T returnValue;
    (void)ReadProcessMemory(hProcess, targetAddress, &returnValue, sizeof(T), NULL);
    return returnValue;
};

NTSTATUS NormalizeAddress(const HANDLE hProcess, const PVOID pRemoteAddr, PVOID& pLocalAddr, const BOOL bIgnoreExe, const imageMap& imageBaseMap = imageMap());
NTSTATUS GetModuleBaseNameWrapper(HANDLE hProcess, PVOID pTargetAddr, std::string& moduleName);
NTSTATUS GetImageBase(const StackFrame& stackFrame);
NTSTATUS GetThreadStartAddress(const HANDLE hThread, PVOID& pStartAddr);
BOOL IsThreadAMatch(const HANDLE hProcess, const DWORD pid, const DWORD tid, threadToSpoof& thread);
BOOL CheckIfAddressIsWithinTargetFunc(const PVOID pTargetAddr, const std::string targetModuleName, const std::string targetFuncName);
NTSTATUS CalculateReturnAddress(StackFrame& stackFrame);
NTSTATUS CalculateFunctionStackSize(PRUNTIME_FUNCTION pRuntimeFunc, const DWORD64 dwImageBase, StackFrame& stackFrame);
NTSTATUS CalculateFunctionStackSizeWrapper(StackFrame& stackFrame);
ULONG CalculateStaticStackSize(const std::vector<StackFrame>& targetCallStack);
NTSTATUS CalculateDynamicStackSize(const HANDLE hProcess, const CONTEXT ctx, ULONG& totalStackSize);
NTSTATUS CreateFakeStackInBuffer(const std::vector<StackFrame>& targetCallStack, const PVOID pSpoofedStack);
NTSTATUS InitializeSpoofedCallStack(std::vector<StackFrame>& targetCallStack);
NTSTATUS InitializeStaticCallStackSpoofing(std::vector<StackFrame>& targetCallStack, threadToSpoof& thread);
NTSTATUS InitializeDynamicCallStackSpoofing(const ULONG waitReason, threadToSpoof& thread);
VOID Go();
BOOL CallStackMasker();

#endif // CALLSTACKMASKER_HPP