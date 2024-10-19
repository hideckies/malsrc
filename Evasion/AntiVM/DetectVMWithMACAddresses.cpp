/*
Title: Detect VM with MAC Addresses
Resources:
	- https://unprotect.it/technique/detecting-mac-address/
	- https://evasions.checkpoint.com/src/Evasions/techniques/network.html
*/
#include <Winsock2.h>
#include <iphlpapi.h>
#include <stdio.h>
#pragma comment(lib, "iphlpapi.lib")

BOOL CheckMACAddress(const CHAR* macAddrToCheck) {
	ULONG uSize = 0;
	if (GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, nullptr, &uSize) == ERROR_BUFFER_OVERFLOW) {
		PIP_ADAPTER_ADDRESSES pAddrs = (PIP_ADAPTER_ADDRESSES)LocalAlloc(LMEM_ZEROINIT, uSize);
		PVOID pAddrsFree = pAddrs;

		if (pAddrs) {
			GetAdaptersAddresses(AF_UNSPEC, 0, nullptr, pAddrs, &uSize);
			CHAR macAddr[6] = { 0 };
			while (pAddrs) {
				if (pAddrs->PhysicalAddressLength == 0x6) {
					memcpy(macAddr, pAddrs->PhysicalAddress, 0x6);
					if (!memcmp(macAddrToCheck, macAddr, 3)) { // Check if the first 3 bytes are same.
						LocalFree(pAddrsFree);
						return TRUE;
					}
				}
				pAddrs = pAddrs->Next;
			}
			LocalFree(pAddrsFree);
		}
	}

	return FALSE;
}

VOID DetectVMWithMACAddresses() {
	const CHAR* macAddrsToCheck[] = {
		// VirtualBox
		"\x08\x00\x27", // "08:00:27",
		// VMWare
		"\x00\x0C\x29", //"00:0C:29",
		"\x00\x1C\x14", // "00:1C:14",
		"\x00\x50\x56", // "00:50:56",
		"\x00\x05\x69"	// "00:05:69"
	};

	for (auto& addr : macAddrsToCheck) {
		if (CheckMACAddress(addr)) {
			printf("VM detected! Exit the process.\n");
			return;
		}
	}
}
