/*
* Title: RSA Encryption/Decryption
*/
#include <Windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <vector>
#pragma comment(lib, "bcrypt.lib")

BOOL RsaInit(BCRYPT_ALG_HANDLE* hAlg, BCRYPT_KEY_HANDLE* hKey) {
	NTSTATUS status;

	status = BCryptOpenAlgorithmProvider(hAlg, BCRYPT_RSA_ALGORITHM, nullptr, 0);
	if (!BCRYPT_SUCCESS(status)) {
		return FALSE;
	}

	// Generate key pair
	DWORD dwKeySize = 2048;
	status = BCryptGenerateKeyPair(*hAlg, hKey, dwKeySize, 0);
	if (!BCRYPT_SUCCESS(status)) {
		return FALSE;
	}

	status = BCryptFinalizeKeyPair(*hKey, 0);
	if (!BCRYPT_SUCCESS(status)) {
		return FALSE;
	}

	return TRUE;
}

std::vector<BYTE> RsaEncrypt(BCRYPT_KEY_HANDLE hKey, std::vector<BYTE>& plaintext) {
	NTSTATUS status;

	// Get the output size.
	DWORD dwCiphertextSize = 0;
	status = BCryptEncrypt(hKey, plaintext.data(), plaintext.size(), nullptr, nullptr, 0, nullptr, 0, &dwCiphertextSize, BCRYPT_PAD_PKCS1);
	if (!BCRYPT_SUCCESS(status)) return {};

	// Encrypt
	std::vector<BYTE> ciphertext(dwCiphertextSize);
	status = BCryptEncrypt(hKey, plaintext.data(), plaintext.size(), nullptr, nullptr, 0, ciphertext.data(), dwCiphertextSize, &dwCiphertextSize, BCRYPT_PAD_PKCS1);
	if (!BCRYPT_SUCCESS(status)) return {};

	return ciphertext;
}

std::vector<BYTE> RsaDecrypt(BCRYPT_KEY_HANDLE hKey, std::vector<BYTE>& ciphertext) {
	NTSTATUS status;

	// Get the output size
	DWORD dwDecryptedSize = 0;
	status = BCryptDecrypt(hKey, ciphertext.data(), ciphertext.size(), nullptr, nullptr, 0, nullptr, 0, &dwDecryptedSize, BCRYPT_PAD_PKCS1);
	if (!BCRYPT_SUCCESS(status)) return {};

	// Decrypt
	std::vector<BYTE> decrypted(dwDecryptedSize);
	status = BCryptDecrypt(hKey, ciphertext.data(), ciphertext.size(), nullptr, nullptr, 0, decrypted.data(), dwDecryptedSize, &dwDecryptedSize, BCRYPT_PAD_PKCS1);
	if (!BCRYPT_SUCCESS(status)) return {};

	return decrypted;
}

BOOL RSA() {
	// Replace it.
	const BYTE plaintext[] = "Hello, World!";

	// Convert the plaintext to vector
	size_t dwPlaintextSize = strlen((const char*)plaintext);
	std::vector<BYTE> plaintextVec(plaintext, plaintext + dwPlaintextSize);

	// Print
	printf("plaintext: %s\n", plaintext);

	BCRYPT_ALG_HANDLE hAlg = nullptr;
	BCRYPT_KEY_HANDLE hKey = nullptr;
	NTSTATUS status;

	// Intialize
	if (!RsaInit(&hAlg, &hKey)) return FALSE;

	// Encrypt
	std::vector<BYTE> ciphertext = RsaEncrypt(hKey, plaintextVec);
	if (ciphertext.size() == 0) return FALSE;
	// Print
	printf("ciphertext: ");
	for (auto c : ciphertext) {
		printf("%02x", c);
	}
	printf("\n");

	// Decrypt
	std::vector<BYTE> decrypted = RsaDecrypt(hKey, ciphertext);
	if (decrypted.size() == 0) return FALSE;

	// Print
	printf("decrypted: %s\n", decrypted.data());

	return TRUE;
}
