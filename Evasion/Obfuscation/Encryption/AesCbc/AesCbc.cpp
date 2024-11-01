/*
* Title: AES-CBC Encryption/Decryption
* Resources:
*	- https://learn.microsoft.com/en-us/windows/win32/seccng/encrypting-data-with-cng
*/
#include <Windows.h>
#include <bcrypt.h>
#include <stdio.h>
#pragma comment(lib, "bcrypt.lib")

#define NT_SUCCESS(Status)	(((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL	((NTSTATUS)0xC0000001L)

VOID FreeAll(BCRYPT_ALG_HANDLE hAesAlg, BCRYPT_KEY_HANDLE hKey, PBYTE pbCiphertext, PBYTE pbPlaintext, PBYTE pbKeyObj, PBYTE pbIv) {
	if (hAesAlg)
		BCryptCloseAlgorithmProvider(hAesAlg, 0);
	if (hKey)
		BCryptDestroyKey(hKey);
	if (pbCiphertext)
		HeapFree(GetProcessHeap(), 0, pbCiphertext);
	if (pbPlaintext)
		HeapFree(GetProcessHeap(), 0, pbPlaintext);
	if (pbKeyObj)
		HeapFree(GetProcessHeap(), 0, pbKeyObj);
	if (pbIv)
		HeapFree(GetProcessHeap(), 0, pbIv);
}

BOOL AesCbcInit(
	BCRYPT_ALG_HANDLE* hAesAlg,
	BCRYPT_KEY_HANDLE* hKey,
	const BYTE* key,
	DWORD dwKeySize,
	PBYTE* pbKeyObj,
	DWORD* dwKeyObj,
	DWORD* dwBlockLen,
	const BYTE* iv,
	DWORD dwIvSize,
	PBYTE* pbIv,
	PBYTE* pbBlob,
	DWORD* dwBlob,
	const BYTE* plaintext,
	DWORD dwPlaintext,
	PBYTE* pbPlaintext,
	DWORD* dwResult
) {
	NTSTATUS status;

	status = BCryptOpenAlgorithmProvider(hAesAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
	if (!NT_SUCCESS(status)) return FALSE;

	// Calculate the size of the key object.
	status = BCryptGetProperty(*hAesAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)dwKeyObj, sizeof(DWORD), dwResult, 0);
	if (!NT_SUCCESS(status)) return FALSE;
	*pbKeyObj = (PBYTE)HeapAlloc(GetProcessHeap(), 0, *dwKeyObj);
	if (!pbKeyObj) return FALSE;

	// Calculate the block length for the IV.
	status = BCryptGetProperty(*hAesAlg, BCRYPT_BLOCK_LENGTH, (PBYTE)dwBlockLen, sizeof(DWORD), dwResult, 0);
	if (!NT_SUCCESS(status)) return FALSE;
	if (*dwBlockLen > dwIvSize) return FALSE;

	// Copy the IV to the allocated buffer.
	*pbIv = (PBYTE)HeapAlloc(GetProcessHeap(), 0, *dwBlockLen);
	if (!pbIv) return FALSE;
	memcpy(*pbIv, iv, *dwBlockLen);

	// Set the CBC mode
	status = BCryptSetProperty(*hAesAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
	if (!NT_SUCCESS(status)) return FALSE;

	// Generate the key from supplied input key bytes.
	status = BCryptGenerateSymmetricKey(*hAesAlg, hKey, *pbKeyObj, *dwKeyObj, (PBYTE)key, dwKeySize, 0);
	if (!NT_SUCCESS(status)) return FALSE;

	// Save another copy of the key for later.
	status = BCryptExportKey(*hKey, nullptr, BCRYPT_OPAQUE_KEY_BLOB, nullptr, 0, dwBlob, 0);
	if (!NT_SUCCESS(status)) return FALSE;
	*pbBlob = (PBYTE)HeapAlloc(GetProcessHeap(), 0, *dwBlob);
	if (!pbBlob) return FALSE;
	status = BCryptExportKey(*hKey, nullptr, BCRYPT_OPAQUE_KEY_BLOB, *pbBlob, *dwBlob, dwBlob, 0);
	if (!NT_SUCCESS(status)) return FALSE;

	// Copy the plaintext to the allocated buffer.
	*pbPlaintext = (PBYTE)HeapAlloc(GetProcessHeap(), 0, dwPlaintext);
	if (!pbPlaintext) return FALSE;
	memcpy(*pbPlaintext, plaintext, dwPlaintext);

	return TRUE;
}

BOOL AesCbcEncrypt(
	BCRYPT_KEY_HANDLE hKey,
	PBYTE pbPlaintext,
	DWORD dwPlaintext,
	PBYTE pbIv,
	DWORD dwBlockLen,
	PBYTE* pbCiphertext,
	DWORD* dwCiphertext,
	DWORD* dwResult
) {
	NTSTATUS status;

	// Get the output size.
	status = BCryptEncrypt(hKey, pbPlaintext, dwPlaintext, nullptr, pbIv, dwBlockLen, nullptr, 0, dwCiphertext, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(status)) return FALSE;

	*pbCiphertext = (PBYTE)HeapAlloc(GetProcessHeap(), 0, *dwCiphertext);
	if (!pbCiphertext) return FALSE;

	// Encrypt using the key.
	status = BCryptEncrypt(hKey, pbPlaintext, dwPlaintext, nullptr, pbIv, dwBlockLen, *pbCiphertext, *dwCiphertext, dwResult, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(status)) return FALSE;

	status = BCryptDestroyKey(hKey);
	if (!NT_SUCCESS(status)) return FALSE;
	hKey = nullptr;

	if (pbPlaintext)
		HeapFree(GetProcessHeap(), 0, pbPlaintext);
	pbPlaintext = nullptr;

	return TRUE;
}

BOOL AesCbcDecrypt(
	BCRYPT_KEY_HANDLE hKey,
	PBYTE pbCiphertext,
	DWORD dwCiphertext,
	PBYTE pbIv,
	DWORD dwBlockLen,
	PBYTE* pbPlaintext,
	DWORD* dwPlaintext
) {
	NTSTATUS status;

	// Get the output size.
	status = BCryptDecrypt(hKey, pbCiphertext, dwCiphertext, nullptr, pbIv, dwBlockLen, nullptr, 0, dwPlaintext, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(status)) return FALSE;

	// Decrypt using the key.
	*pbPlaintext = (PBYTE)HeapAlloc(GetProcessHeap(), 0, *dwPlaintext);
	if (!pbPlaintext) return FALSE;

	status = BCryptDecrypt(hKey, pbCiphertext, dwCiphertext, nullptr, pbIv, dwBlockLen, *pbPlaintext, *dwPlaintext, dwPlaintext, BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(status)) return FALSE;

	return TRUE;
}

BOOL AesCbc() {
	// Replace the following values.
	const BYTE key[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
	};
	const BYTE iv[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
	};
	const BYTE plaintext[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
	};

	// Print the original plaintext
	printf("plaintext: ");
	for (int i = 0; i < sizeof(plaintext); i++) {
		printf("%02x", plaintext[i]);
	}
	printf("\n");

	DWORD dwKey = sizeof(key);
	DWORD dwIv = sizeof(iv);
	DWORD dwPlaintext = sizeof(plaintext);

	BCRYPT_ALG_HANDLE hAesAlg = nullptr;
	BCRYPT_KEY_HANDLE hKey = nullptr;
	DWORD dwKeyObj = 0;
	DWORD dwResult = 0;
	DWORD dwBlockLen = 0;
	DWORD dwBlob = 0;
	PBYTE pbPlaintext = nullptr;
	PBYTE pbKeyObj = nullptr;
	PBYTE pbIv = nullptr;
	PBYTE pbBlob = nullptr;

	if (!AesCbcInit(
		&hAesAlg,
		&hKey,
		key,
		sizeof(key),
		&pbKeyObj,
		&dwKeyObj,
		&dwBlockLen,
		iv,
		sizeof(iv),
		&pbIv,
		&pbBlob,
		&dwBlob,
		plaintext,
		sizeof(plaintext),
		&pbPlaintext,
		&dwResult
	)) {
		FreeAll(hAesAlg, hKey, nullptr, pbPlaintext, pbKeyObj, pbIv);
		return FALSE;
	}

	// Encrypt
	PBYTE pbCiphertext = nullptr;
	DWORD dwCiphertext = 0;

	if (!AesCbcEncrypt(
		hKey,
		pbPlaintext,
		dwPlaintext,
		pbIv,
		dwBlockLen,
		&pbCiphertext,
		&dwCiphertext,
		&dwResult
	)) {
		FreeAll(hAesAlg, hKey, pbCiphertext, pbPlaintext, pbKeyObj, pbIv);
		return FALSE;
	}
	// Print
	printf("ciphertext: ");
	for (DWORD i = 0; i < dwCiphertext; i++) {
		printf("%02x", pbCiphertext[i]);
	}
	printf("\n");

	// Reinitialize
	memset(pbKeyObj, 0, dwKeyObj);
	memcpy(pbIv, iv, dwBlockLen);
	NTSTATUS status = BCryptImportKey(hAesAlg, nullptr, BCRYPT_OPAQUE_KEY_BLOB, &hKey, pbKeyObj, dwKeyObj, pbBlob, dwBlob, 0);
	if (!NT_SUCCESS(status)) {
		FreeAll(hAesAlg, hKey, pbCiphertext, pbPlaintext, pbKeyObj, pbIv);
		return FALSE;
	}

	// Decrypt
	if (!AesCbcDecrypt(
		hKey,
		pbCiphertext,
		dwCiphertext,
		pbIv,
		dwBlockLen,
		&pbPlaintext,
		&dwPlaintext
	)) {
		FreeAll(hAesAlg, hKey, pbCiphertext, pbPlaintext, pbKeyObj, pbIv);
		return FALSE;
	}
	// Print
	printf("decrypted: ");
	for (DWORD i = 0; i < dwPlaintext; i++) {
		printf("%02x", pbPlaintext[i]);
	}
	printf("\n");

	return TRUE;
}
