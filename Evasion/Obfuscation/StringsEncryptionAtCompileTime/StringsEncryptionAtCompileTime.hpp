/*
* Title: Strings Encryption At Compile Time
* Resources:
*	- https://gist.github.com/EvanMcBroom/ace2a9af19fb5e7b2451b1cd4c07bf96
*	- https://gist.github.com/EvanMcBroom/ad683e394f84b623da63c2b95f6fb547
*/
#include <stdint.h>

// Park-Miller's "Multiplicative Linear Congruential Generator"
namespace mlcg {
	constexpr uint32_t modulus() {
		return 0x7fffffff;
	}

	template<size_t N>
	constexpr uint32_t seed(const char(&entropy)[N], const uint32_t iv = 0) {
		auto value{ iv };
		for (size_t i{ 0 }; i < N; i++) {
			// XOR 1st byte of seed with input byte
			value = (value & ((~0) << 8) | ((value & 0xFF) ^ entropy[i]));
			// Rotl 1 byte
			value = value << 8 | value >> ((sizeof(value) * 8) - 8);
		}
		// The seed is required to be less than the modulus and odd
		while (value > modulus()) value = value >> 1;
		return value << 1 | 1;
	}

	constexpr uint32_t prng(const uint32_t input) {
		return (input * 48271) % modulus();
	}
}

template<typename T, size_t N>
struct encrypted {
	int seed;
	T data[N];
};

template<size_t N>
constexpr auto crypt(const char(&input)[N], const uint32_t seed = 0) {
	encrypted<char, N> blob{};
	blob.seed = seed;
	for (uint32_t index{ 0 }, stream{ seed }; index < N; index++) {
		blob.data[index] = input[index] ^ stream;
		stream = mlcg::prng(stream);
	}
	return blob;
};

#define make_string(STRING) ([&] {                                     \
    constexpr auto _{ crypt(STRING, mlcg::seed(__FILE__, __LINE__)) }; \
    return std::string{ crypt(_.data, _.seed).data };                  \
}())
