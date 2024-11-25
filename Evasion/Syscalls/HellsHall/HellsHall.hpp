#ifndef HELLSHALL_HPP
#define HELLSHALL_HPP

#define SEED    0xEDB88320
#define RANGE   0x1E

// Hashes (CRC32B) for nt functions to resolve
uint32_t crc32b(const uint8_t* str);
#define HASH(API) (crc32b((uint8_t*)API))

#define HASH_NTALLOCATEVIRTUALMEMORY	0xE0762FEB
#define HASH_NTPROTECTVIRTUALMEMORY		0x5C2D1A97
#define HASH_NTCREATETHREADEX			0x2073465A
#define HASH_NTWAITFORSINGLEOBJECT      0xdd554681

typedef struct _SysFunc {
    PVOID       pInst;          // address of a 'syscall' instruction in ntdll.dll
    PBYTE       pAddress;       // address of the syscall 
    WORD        wSSN;           // syscall number
    uint32_t    uHash;          // syscall name hash value
} SysFunc, * PSysFunc;

typedef struct _MyStruct {
	SysFunc NtAllocateVirtualMemory;
	SysFunc NtProtectVirtualMemory;
	SysFunc NtCreateThreadEx;
    SysFunc NtWaitForSingleObject;
} MyStruct, *PMyStruct;

// FROM AsmHell.asm
extern "C" VOID SetConfig(WORD wSystemCall, PVOID pSyscallInst);
extern "C" NTSTATUS HellsHall(...);

#define SYSCALL(sysFunc)(SetConfig(sysFunc.wSSN, sysFunc.pInst))

uint32_t crc32b(const uint8_t* str);
BOOL InitSysFunc(SysFunc* pSysFunc, UINT32 uSysFuncHash);
VOID GetSysFuncStruct(PSysFunc pSysFuncSrc, PSysFunc pSysFuncDest);
BOOL HellsHallMain();

#endif // HELLSHALL_HPP