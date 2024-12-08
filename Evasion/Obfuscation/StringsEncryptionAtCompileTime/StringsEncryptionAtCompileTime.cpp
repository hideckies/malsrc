/*
* This is just a PoC for checking if the encrypting strings at compile time are working correctly.
*/
#include <string>
#include <iostream>
#include "StringsEncryptionAtCompileTime.hpp"

int main() {
	// The "Hello" and the "World!" should be encrypted when reversing.
	std::string str1{ make_string("Hello") };
	std::string str2{ make_string("World!") };
	std::cout << str1 << ", " << str2 << std::endl;

	// This string should appear as is when reversing.
	std::string str3 = "I'm not encrypted.";

	return 0;
}