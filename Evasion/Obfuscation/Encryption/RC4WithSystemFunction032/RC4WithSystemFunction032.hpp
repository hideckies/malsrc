#ifndef RC4WITHSYSTEMFUNCTION032_HPP
#define RC4WITHSYSTEMFUNCTION032_HPP

#include <Windows.h>

#define MAX_BUFFER 2048

typedef struct ustring {
	DWORD Length;
	DWORD MaximumLength;
	unsigned char* Buffer;
} DATA, KEY;

typedef NTSTATUS(NTAPI* _SystemFunction032)(struct ustring *data, struct ustring *key);

BOOL RC4WithSystemFunction032(const unsigned char* data, const unsigned char* key, unsigned char* result, DWORD* dwResultLength);

#endif // RC4WITHSYSTEMFUNCTION032_HPP