/*
* Title: ChaCha20
* Resources:
*	- https://github.com/983/ChaCha20
*/
#include <iostream>
#include <vector>
#include <cstdint>
#include <cstring>

constexpr uint32_t ROTL32(uint32_t x, int n) {
	return (x << n) | (x >> (32 - n));
}

#define QUARTERROUND(a, b, c, d) { \
	a += b; d ^= a; d = ROTL32(d, 16); \
	c += d; b ^= c; b = ROTL32(b, 12); \
	a += b; d ^= a; d = ROTL32(d, 8); \
	c += d; b ^= c; b = ROTL32(b, 7); \
}

void ChaCha20Block(const uint32_t input[16], uint32_t output[16]) {
	std::memcpy(output, input, sizeof(uint32_t) * 16);

	for (int i = 0; i < 10; i++) {
		// Odd rounds
		QUARTERROUND(output[0], output[4], output[8], output[12]);
		QUARTERROUND(output[1], output[5], output[9], output[13]);
		QUARTERROUND(output[2], output[6], output[10], output[14]);
		QUARTERROUND(output[3], output[7], output[11], output[15]);

		// Even rounds
		QUARTERROUND(output[0], output[5], output[10], output[15]);
		QUARTERROUND(output[1], output[6], output[11], output[12]);
		QUARTERROUND(output[2], output[7], output[8], output[13]);
		QUARTERROUND(output[3], output[4], output[9], output[14]);
	}

	for (int i = 0; i < 16; i++) {
		output[i] += input[i];
	}
}

// The function is used for not only encryption, but also decryption.
void ChaCha20Encrypt(std::vector<uint8_t>& data, const uint32_t key[8], const uint32_t nonce[3], uint32_t counter = 0) {
	const char* constants = "expand 32-byte k"; // Warning: This string must be used, so do not change it.

	uint32_t input[16] = {
		reinterpret_cast<const uint32_t*>(constants)[0],
		reinterpret_cast<const uint32_t*>(constants)[1],
		reinterpret_cast<const uint32_t*>(constants)[2],
		reinterpret_cast<const uint32_t*>(constants)[3],
		key[0], key[1], key[2], key[3],
		key[4], key[5], key[6], key[7],
		counter, nonce[0], nonce[1], nonce[2]
	};

	std::vector<uint8_t> keystream(data.size());
	size_t blockCount = (data.size() + 63) / 64;
	for (size_t i = 0; i < blockCount; i++) {
		uint32_t output[16];
		ChaCha20Block(input, output);

		for (size_t j = 0; j < 64 && (i * 64 + j) < data.size(); i++) {
			keystream[i * 64 + j] = reinterpret_cast<uint8_t*>(output)[j];
		}
		input[12]++;
	}

	for (size_t i = 0; i < data.size(); i++) {
		data[i] ^= keystream[i];
	}
}

int main() {
	// Key 256-bit (32 bytes) which is randomly generated.
	uint32_t key[8] = {
		0x00014203, 0x02253941, 0x072dc30c, 0x0a5d2d3e,
		0x104f0232, 0x15182af3, 0x1a54ba2b, 0x1c398a2d
	};

	// Nonce 64-bit (8 bytes) which is randomly generated.
	uint32_t nonce[3] = {0x00001009, 0x0000023b, 0x00000080};

	// Original data to encrypt/decrypt
	std::vector<uint8_t> data = {
		'H', 'e', 'l', 'l', 'o', ',', ' ', 'W', 'o', 'r', 'l', 'd', '!'
	};

	std::cout << "Original: ";
	for (auto c : data) std::cout << c;
	std::cout << std::endl;

	// Encrypt
	ChaCha20Encrypt(data, key, nonce);
	std::cout << "Encrypted: 0x";
	for (auto c : data) std::cout << std::hex << (int)c << "";
	std::cout << std::endl;

	// Decrypt
	ChaCha20Encrypt(data, key, nonce);
	std::cout << "Decrypted: ";
	for (auto c : data) std::cout << c;
	std::cout << std::endl;

	return 0;
}