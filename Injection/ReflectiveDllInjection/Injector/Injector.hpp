#ifndef INJECTOR_HPP
#define INJECTOR_HPP

#include <Windows.h>

#define DEREF(name)     *(UINT_PTR*)(name)
#define DEREF_64(name)  *(DWORD64*)(name)
#define DEREF_32(name)  *(DWORD*)(name)
#define DEREF_16(name)  *(WORD*)(name)
#define DEREF_8(name)   *(BYTE*)(name)

DWORD Rva2Offset(DWORD dwRva, UINT_PTR uBaseAddr);
DWORD GetFuncOffset(LPVOID lpBuffer, LPCSTR lpFuncName);

#endif // INJECTOR_HPP