#ifndef HIDESHELLCODEINPLAINSIGHT_HPP
#define HIDESHELLCODEINPLAINSIGHT_HPP

#include <Windows.h>

#define RANDOM_NUM(min, max) (rand() % (max + 1 - min) + min)

#define ALIGN_PAGE(n) ((n + 0x1000) & ~(0x1000))

#define FACTOR 2048

typedef struct _PAGE_SHELLCODE_CONTEXT {
	UINT8 u8Key;
	DWORD dwLocation;
	SIZE_T uSize;
	LPVOID lpPage;
} PAGE_SHELLCODE_CONTEXT, *PPAGE_SHELLCODE_CONTEXT;

VOID Cleanup(PPAGE_SHELLCODE_CONTEXT pCtx);
PPAGE_SHELLCODE_CONTEXT AllocateLargePage(HANDLE hTarget, DWORD dwPageSize);
BOOL HideShellcodeInPlainSight();

#endif // HIDESHELLCODEINPLAINSIGHT_HPP