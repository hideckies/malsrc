/*
* Title: RC4 Encryption/Decryption
*/
#include <vector>
#include <string>
#include <iostream>

void RC4Init(std::vector<int>& S, const std::string& key) {
	S.resize(256);
	for (int i = 0; i < 256; i++) {
		S[i] = i;
	}

	int j = 0;
	for (int i = 0; i < 256; i++) {
		j = (j + S[i] + key[i % key.size()]) % 256;
		std::swap(S[i], S[j]);
	}
}

std::string RC4(const std::string& data, const std::string& key) {
	std::vector<int> S;
	RC4Init(S, key);

	std::string result = data;
	int i = 0, j = 0;
	for (size_t n = 0; n < data.size(); n++) {
		i = (i + 1) % 256;
		j = (j + S[i]) % 256;
		std::swap(S[i], S[j]);
		int k = S[(S[i] + S[j]) % 256];
		result[n] ^= k;
	}
	return result;
}

int main() {
	// Replace the following values.
	std::string key = "secret";
	std::string plaintext = "This is a plain text.";

	// Encryption
	std::string ciphertext = RC4(plaintext, key);
	std::cout << "Ciphertext: ";
	for (unsigned char c : ciphertext) {
		printf("%02x", c);
	}
	std::cout << std::endl;

	// Decryption
	std::string decrypted = RC4(ciphertext, key);
	std::cout << "Decrypted: " << decrypted << std::endl;

	return 0;
}