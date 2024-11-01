/*
* Title: RC4 with SystemFunction032
* Resources:
*	- https://osandamalith.com/2022/11/10/encrypting-shellcode-using-systemfunction032-033/
*	- https://doxygen.reactos.org/d2/da1/dll_2win32_2advapi32_2wine_2crypt_8h.html#a66d55017b8625d505bd6c5707bdb9725
*/
#include <Windows.h>
#include <stdio.h>
#include "RC4WithSystemFunction032.hpp"

BOOL RC4WithSystemFunction032(const unsigned char* data, const unsigned char* key, unsigned char* result, DWORD* dwResultLength) {
	HMODULE hAdvapi32 = LoadLibraryA("advapi32.dll");
	if (!hAdvapi32) return FALSE;
	_SystemFunction032 systemFunction032 = reinterpret_cast<_SystemFunction032>(GetProcAddress(hAdvapi32, "SystemFunction032"));
	if (!systemFunction032) {
		FreeLibrary(hAdvapi32);
		return FALSE;
	}

	KEY k;
	k.Length = strlen((const char*)key);
	k.Buffer = (unsigned char*)key;
	DATA d;
	d.Length = strlen((const char*)data);
	d.Buffer = (unsigned char*)data;

	systemFunction032(&d, &k);

	// Store the results.
	memcpy(result, d.Buffer, d.Length);
	*dwResultLength = d.Length;

	return TRUE;
}

int main() {
	// Replace the following values.
	unsigned char data[] = "Hello, World!";
	unsigned char key[] = "secret";

    printf("original: %s\n", data);
	
    DWORD dwResultLength = 0;

	// Encrypt
	unsigned char encrypted[MAX_BUFFER] = {};
	RC4WithSystemFunction032(data, key, encrypted, &dwResultLength);
	printf("encrypted: ");
	for (int i = 0; i < dwResultLength; i++) {
		printf("%02x", encrypted[i]);
	}
	printf("\n");

	// Decrypt
	unsigned char decrypted[MAX_BUFFER] = {};
	RC4WithSystemFunction032(encrypted, key, decrypted, &dwResultLength);
	printf("decrypted: %s\n", decrypted);

	return 0;
}