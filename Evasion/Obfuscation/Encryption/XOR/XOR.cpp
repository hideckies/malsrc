/*
* Title: XOR
*/
#include <Windows.h>
#include <stdio.h>

#define MAX_BUFFER 2048

VOID XOR(const unsigned char* data, size_t dwDataLength, const unsigned char* key, unsigned char* result) {
	for (size_t i = 0; i < dwDataLength; ++i) {
		result[i] = data[i] ^ key[i % dwDataLength];
	}
}

int main() {
	// Replace the following values.
	unsigned char data[] = "Hello, World!";
	unsigned char key[] = "secret";

	size_t dwDataLength = sizeof(data);

	unsigned char encoded[MAX_BUFFER] = {};
	XOR(data, dwDataLength, key, encoded);
	printf("encoded: ");
	for (int i = 0; i < dwDataLength; i++) {
		printf("%02x", encoded[i]);
	}
	printf("\n");

	unsigned char decoded[MAX_BUFFER] = {};
	XOR(encoded, dwDataLength, key, decoded);
	printf("decoded: %s\n", decoded);

	return 0;
}