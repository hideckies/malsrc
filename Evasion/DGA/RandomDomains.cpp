/*
* Title: Generate Domain with Random String
*/
#include <Windows.h>
#include <random>
#include <string>
#include <iostream>

std::string RandomString(size_t length) {
	std::string result;
	const std::string chars = "abcdefghijklmnopqrstuvwxyz0123456789";
	std::uniform_int_distribution<> dist(0, chars.size() - 1);

	std::random_device rd;
	std::mt19937 generator(rd());

	for (size_t i = 0; i < length; i++) {
		result += chars[dist(generator)];
	}

	return result;
}

BOOL RandomDomains() {
	// Modify the following values.
	size_t numOfDomains = 50;
	size_t domainLength = 10;
	std::string tld = "com";

	for (int i = 0; i < numOfDomains; i++) {
		std::string randomString = RandomString(domainLength);
		std::string domain = randomString + "." + tld;

		std::cout << domain << std::endl;
	}

	return TRUE;
}
