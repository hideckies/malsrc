#ifndef NT_HPP
#define NT_HPP

#include <Windows.h>

#define NT_SUCCESS(Status)  (((NTSTATUS)(Status)) >= 0)

typedef NTSTATUS(NTAPI* _RtlGetVersion)(PRTL_OSVERSIONINFOEXW VersionInformation);

#endif // NT_HPP