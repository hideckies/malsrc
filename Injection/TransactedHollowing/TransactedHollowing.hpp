#ifndef TRANSACTED_HOLLOWING_HPP
#define TRANSACTED_HOLLOWING_HPP

#include <Windows.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor; // PSECURITY_DESCRIPTOR;
    PVOID SecurityQualityOfService; // PSECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef NTSTATUS(NTAPI* _NtCreateSection)(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle);

VOID FreeAll(HMODULE hNtdll, BYTE* payloadBuf, HANDLE hSection);
BOOL InitFunctions(HMODULE hNtdll);
BYTE* MapPayload(const std::wstring& wPayloadPath, DWORD* dwPayloadSize);
HANDLE MakeTransactedSection(BYTE* payloadBuf, DWORD dwPayloadSize);
BOOL TransactedHollowing();

#endif // TRANSACTED_HOLLOWING_HPP