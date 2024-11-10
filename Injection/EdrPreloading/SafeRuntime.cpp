#include "Windows.h"
#include "SafeRuntime.hpp"

size_t SafeRuntime::strlen(const char* str) {
	size_t i = 0;

	while (str[i] != 0)
		i++;

	return i;
}

int SafeRuntime::memcmp(const void* s1, const void* s2, size_t length) {
	const unsigned char* p1 = (const unsigned char*)s1, *p2 = (const unsigned char*)s2;
	while (length--) {
		if (*p1 != *p2) {
			return *p1 - *p2;
		}
		p1++;
		p2++;
	}
	return 0;
}

void SafeRuntime::memcpy(void* dest, void* src, size_t length) {
	char* d = (char*)dest;
	const char* s = (const char*)src;

	while (length--) {
		*d++ = *s++;
	}
}

wchar_t SafeRuntime::towlower(wchar_t wc) {
	if (wc >= L'A' && wc <= L'Z') {
		return wc + (L'a' - L'A');
	}
	return wc;
}

int SafeRuntime::wstring_compare_i(const wchar_t* s1, const wchar_t* s2) {
	wchar_t c1, c2;
	do {
		c1 = towlower(*s1++);
		c2 = towlower(*s2++);
		if (c1 == L'\0')
			break;
	} while (c1 == c2);

	return (c1 < c2) ? -1 : (c1 > c2);
}