#ifndef SHELLGHOST_HPP
#define SHELLGHOST_HPP

#include <Windows.h>

#define STATUS_UNSUCCESSFUL ((NTSTATUS)(0xC0000001L))

typedef enum {
	INSTRUCTION_OPCODES_QUOTA,
	INSTRUCTION_OPCODES_RVA,
	INSTRUCTION_OPCODES_NUMBER
} INSTR_INFO;

typedef struct USTRING {
	DWORD Length;
	DWORD MaximumLength;
	PVOID buffer;
} USTRING, * PUSTRING;

typedef struct CRYPT_BYTES_QUOTA {
	DWORD RVA;
	DWORD quota;
} CRYPT_BYTES_QUOTA, * PCRYPT_BYTES_QUOTA;

typedef NTSTATUS(WINAPI* _SystemFunction032)(USTRING* data, USTRING* key);

#endif // SHELLGHOST_HPP
