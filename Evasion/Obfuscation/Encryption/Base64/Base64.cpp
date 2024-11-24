/*
* Title: Base64
*/
#include <vector>
#include <string>
#include <iostream>

const std::string BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

bool IsBase64(unsigned char c) {
	return (isalnum(c) || (c == '+') || (c == '/'));
}

std::string Base64Encode(const std::vector<unsigned char>& bytes) {
	std::string encodedString;
	size_t i = 0;
	unsigned char charArray3[3];
	unsigned char charArray4[4];

	for (unsigned char byte : bytes) {
		charArray3[i++] = byte;
		if (i == 3) {
			charArray4[0] = (charArray3[0] & 0xfc) >> 2;
			charArray4[1] = ((charArray3[0] & 0x03) << 4) + ((charArray3[1] & 0xf0) >> 4);
			charArray4[2] = ((charArray3[1] & 0x0f) << 2) + ((charArray3[2] & 0xc0) >> 6);
			charArray4[3] = charArray3[2] & 0x3f;

			for (i = 0; i < 4; i++) {
				encodedString += BASE64_CHARS[charArray4[i]];
			}
			i = 0;
		}
	}

	if (i > 0) {
		for (size_t j = i; j < 3; j++) {
			charArray3[j] = '\0';
		}

		charArray4[0] = (charArray3[0] & 0xfc) >> 2;
		charArray4[1] = ((charArray3[0] & 0x03) << 4) + ((charArray3[1] & 0xf0) >> 4);
		charArray4[2] = ((charArray3[1] & 0x0f) << 2) + ((charArray3[2] & 0xc0) >> 6);
		charArray4[3] = charArray3[2] & 0x3f;

		for (size_t j = 0; j < i + 1; j++) {
			encodedString += BASE64_CHARS[charArray4[j]];
		}

		while (i++ < 3) {
			encodedString += '=';
		}
	}

	return encodedString;
}

std::vector<unsigned char> Base64Decode(const std::string& encodedString) {
	size_t length = encodedString.size();
	size_t i = 0;
	size_t in_ = 0;
	unsigned char charArray4[4], charArray3[3];
	std::vector<unsigned char> decodedBytes;

	while (length-- && (encodedString[in_] != '=') && IsBase64(encodedString[in_])) {
		charArray4[i++] = encodedString[in_];
		in_++;
		if (i == 4) {
			for (i = 0; i < 4; i++) {
				charArray4[i] = BASE64_CHARS.find(charArray4[i]);
			}

			charArray3[0] = (charArray4[0] << 2) + ((charArray4[1] & 0x30) >> 4);
			charArray3[1] = ((charArray4[1] & 0xf) << 4) + ((charArray4[2] & 0x3c) >> 2);
			charArray3[2] = ((charArray4[2] & 0x3) << 6) + charArray4[3];

			for (i = 0; i < 3; i++) {
				decodedBytes.push_back(charArray3[i]);
			}
			i = 0;
		}
	}

	if (i > 0) {
		for (size_t j = i; j < 4; j++) {
			charArray4[j] = 0;
		}

		for (size_t j = 0; j < 4; j++) {
			charArray4[j] = BASE64_CHARS.find(charArray4[j]);
		}

		charArray3[0] = (charArray4[0] << 2) + ((charArray4[1] & 0x30) >> 4);
		charArray3[1] = ((charArray4[1] & 0xf) << 4) + ((charArray4[2] & 0x3c) >> 2);
		charArray3[2] = ((charArray4[2] & 0x3) << 6) + charArray4[3];

		for (size_t j = 0; j < i - 1; j++) {
			decodedBytes.push_back(charArray3[j]);
		}
	}

	return decodedBytes;
}

int main() {
	std::string input = "Hello, World!";
	std::vector<unsigned char> bytes(input.begin(), input.end());

	// Encode
	std::string encoded = Base64Encode(bytes);
	std::cout << "Encoded: " << encoded << std::endl;

	// Decode
	std::vector<unsigned char> decoded = Base64Decode(encoded);
	std::string decodedString(decoded.begin(), decoded.end());
	std::cout << "Decoded: " << decodedString << std::endl;

	return 0;
}
