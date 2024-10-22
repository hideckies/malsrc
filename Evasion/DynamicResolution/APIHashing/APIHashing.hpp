#ifndef API_HASHING_HPP
#define API_HASHING_HPP

#include <Windows.h>

constexpr DWORD KEY = 0x48;
constexpr DWORD RANDOM_ADDR = 0x14da703d;

constexpr DWORD HASH_MESSAGEBOXA = 0x006815eed;

typedef int (WINAPI* _MessageBoxA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);

DWORD StringToHashA(CHAR* s);
LPVOID GetProcAddressByHash(CHAR* sLibrary, DWORD dwHash);
BOOL APIHashing();

#endif // API_HASHING_HPP