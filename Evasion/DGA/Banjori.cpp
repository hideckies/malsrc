/*
* Title: DGA of Banjori
* Resources:
*	- https://github.com/baderj/domain_generation_algorithms/blob/master/banjori/dga.py
*/
#include <Windows.h>
#include <string>
#include <vector>
#include <iostream>

char MapToLowercaseLetter(int d) {
	return 'a' + ((d - 'a') % 26);
}

std::string NextDomain(const std::string& domain) {
	std::vector<int> dl;

	for (char c : domain) {
		int ord = static_cast<int>(c);
		dl.push_back(ord);
	}

	dl[0] = MapToLowercaseLetter(dl[0] + dl[3]);
	dl[1] = MapToLowercaseLetter(dl[0] + 2 * dl[1]);
	dl[2] = MapToLowercaseLetter(dl[0] + dl[2] - 1);
	dl[3] = MapToLowercaseLetter(dl[1] + dl[2] + dl[3]);

	std::string result = "";
	for (int d : dl) {
		result += static_cast<char>(d);
	}

	return result;
}

BOOL Banjori() {
	// Replace the following values.
	std::string seed = "myc2server.com";
	size_t numOfDomains = 50;

	std::string domain = seed;

	for (int i = 0; i < numOfDomains; i++) {
		domain = NextDomain(domain);
		std::cout << domain << std::endl;
	}

	return TRUE;
}
