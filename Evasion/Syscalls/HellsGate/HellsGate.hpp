#ifndef HELLSGATE_HPP
#define HELLSGATE_HPP

typedef struct _VX_TABLE_ENTRY {
	PVOID pAddress;
	DWORD64 dwHash;
	WORD wSystemCall;
} VX_TABLE_ENTRY, * PVX_TABLE_ENTRY;

typedef struct _VX_TABLE {
	VX_TABLE_ENTRY NtAllocateVirtualMemory;
	VX_TABLE_ENTRY NtProtectVirtualMemory;
	VX_TABLE_ENTRY NtCreateThreadEx;
	VX_TABLE_ENTRY NtWaitForSingleObject;
} VX_TABLE, * PVX_TABLE;

// See hellsgate.asm
extern "C" VOID HellsGate(WORD wSystemCall);
extern "C" NTSTATUS HellDescent(...);

// Function prototypes
DWORD64 djb2(PBYTE str);
BOOL GetVxTableEntry(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PVX_TABLE_ENTRY pVxTableEntry);
PVOID VxMoveMemory(PVOID dest, const PVOID src, SIZE_T len);
BOOL HellsGateMain();

#endif // HELLSGATE_HPP