#ifndef API_HASHING_HPP
#define API_HASHING_HPP

#include <Windows.h>

// Replace the following values with your own.
constexpr DWORD KEY = 0x48;
constexpr DWORD RANDOM_ADDR = 0x14da703d;

// Replace the following API hashes with your own.
constexpr DWORD HASH_MESSAGEBOXA = 0x0039a9d2d;

typedef int (WINAPI* _MessageBoxA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);

DWORD StringToHash(CHAR* s);
LPVOID GetProcAddressByHash(CHAR* sLibrary, DWORD dwHash);
BOOL APIHashing();

#endif // API_HASHING_HPP