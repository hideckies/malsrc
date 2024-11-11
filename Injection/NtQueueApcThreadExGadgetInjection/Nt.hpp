#ifndef NT_HPP
#define NT_HPP

#include <Windows.h>

#define NT_SUCCESS(Status)  (((NTSTATUS)(Status)) >= 0)

typedef
VOID
(*PPS_APC_ROUTINE)(
	_In_opt_ PVOID ApcArgument1,
	_In_opt_ PVOID ApcArgument2,
	_In_opt_ PVOID ApcArgument3
);

typedef NTSTATUS(NTAPI* _NtQueueApcThreadEx)(HANDLE ThreadHandle, HANDLE UserApcReserveHandle, PPS_APC_ROUTINE ApcRoutine, PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3);
typedef NTSTATUS(NTAPI* _NtTestAlert)(VOID);

#endif // NT_HPP