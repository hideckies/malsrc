#ifndef CRONOS_HPP
#define CRONOS_HPP

#define SIZE_MODULE_LIST 2
#define MAX_MODULE_NAME 100

#define InitializeTimerMs(ft, sec) \
{ \
    (ft)->HighPart = (DWORD)(((ULONGLONG) - ((sec) * 1000 * 10 * 1000)) >> 32); \
    (ft)->LowPart  = (DWORD)(((ULONGLONG) - ((sec) * 1000 * 10 * 1000)) & 0xffffffff); \
}

typedef struct _CRYPT_BUFFER {
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
} CRYPT_BUFFER, * PCRYPT_BUFFER, DATA_KEY, * PDATA_KEY, CLEAR_DATA, * PCLEAR_DATA, CYPHER_DATA, * PCYPHER_DATA;

typedef NTSTATUS(NTAPI* _NtContinue)(PCONTEXT ContextRecord, BOOLEAN TestAlert);
typedef NTSTATUS(WINAPI* _SystemFunction032)(struct ustring* data, const struct ustring* key);

extern "C" void QuadSleep(PVOID, PVOID, PVOID, PVOID);

BOOL Compare(const BYTE* pData, const BYTE* bMask, const char* szMask);
DWORD_PTR FindPattern(DWORD_PTR dwAddress, DWORD dwLen, PBYTE bMask, PCHAR szMask);
DWORD_PTR FindInModule(LPCSTR moduleName, PBYTE bMask, PCHAR szMask);
PVOID FindGadget(PBYTE hdrParserFuncB, PCHAR hdrParserFunctMask);
VOID CronosSleep(DWORD dwSleepTime);
BOOL Cronos();

#endif // CRONOS_HPP