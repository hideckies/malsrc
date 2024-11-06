/*
* Title: System Information Gathering
*/
#include <WinSock2.h> // this header file must appear above windows.h.
#include <Windows.h>
#include <VersionHelpers.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <timezoneapi.h>
#include <stdio.h>
#include "Nt.hpp"
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

BOOL GetSystemVersion() {
	RTL_OSVERSIONINFOEXW versionInfo;
	versionInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOEXW);

	HMODULE hNtdll = GetModuleHandleA("ntdll");
	if (!hNtdll) return FALSE;
	_RtlGetVersion rtlGetVersion = reinterpret_cast<_RtlGetVersion>(GetProcAddress(hNtdll, "RtlGetVersion"));
	if (!rtlGetVersion) return FALSE;

	NTSTATUS status = rtlGetVersion(&versionInfo);
	if (!NT_SUCCESS(status)) {
		return FALSE;
	}

	printf("OS version: %d.%d.%d\n", versionInfo.dwMajorVersion, versionInfo.dwMinorVersion, versionInfo.dwBuildNumber);

	return TRUE;
}

BOOL GetSystemLanguage() {
	LANGID langId = GetSystemDefaultLangID();

	// Get language name.
	char langName[256];
	switch (langId & 0xFF) {
	case LANG_CHINESE:
		strcpy_s(langName, 256, "Chinese");
		break;
	case LANG_GERMAN:
		strcpy_s(langName, 256, "German");
		break;
	case LANG_ENGLISH:
		strcpy_s(langName, 256, "English");
		break;
	case LANG_SPANISH:
		strcpy_s(langName, 256, "Spanish");
		break;
	case LANG_FRENCH:
		strcpy_s(langName, 256, "French");
		break;
	case LANG_ITALIAN:
		strcpy_s(langName, 256, "Italian");
		break;
	case LANG_JAPANESE:
		strcpy_s(langName, 256, "Japanese");
		break;
	case LANG_KOREAN:
		strcpy_s(langName, 256, "Korean");
		break;
	case LANG_PORTUGUESE:
		strcpy_s(langName, 256, "Portuguese");
		break;
	case LANG_RUSSIAN:
		strcpy_s(langName, 256, "Russian");
		break;
	default:
		strcpy_s(langName, 256, "<unknown>");
		break;
	}

	printf("Language: %s\n", langName);

	return TRUE;
}

BOOL GetTimezone() {
	TIME_ZONE_INFORMATION tzInfo;
	if (GetTimeZoneInformation(&tzInfo) == TIME_ZONE_ID_INVALID)
		return FALSE;

	wprintf(L"Timezone: %s\n", tzInfo.StandardName);
	printf("UTC offset: %d hours\n", tzInfo.Bias / 60);

	return TRUE;
}

BOOL GetComputerNameAndUserName() {
	DWORD dwLength = 0;

	// Get computer name
	char computerName[MAX_COMPUTERNAME_LENGTH + 1];
	dwLength = sizeof(computerName);
	if (!GetComputerNameA(computerName, &dwLength))
		return FALSE;
	printf("Computer name: %s\n", computerName);

	// Get username
	char userName[UNLEN + 1];
	dwLength = sizeof(userName);
	if (!GetUserNameA(userName, &dwLength))
		return FALSE;
	printf("Username: %s\n", userName);

	return TRUE;
}

BOOL GetNetworkInfo() {
	WSADATA wsaData;
	WORD versionRequested = MAKEWORD(2, 2); // version 2.2
	if (WSAStartup(versionRequested, &wsaData))
		return FALSE;

	ULONG outBufLen = 15000;
	PIP_ADAPTER_ADDRESSES pAdapterAddresses = (PIP_ADAPTER_ADDRESSES)malloc(outBufLen);
	DWORD dwRetVal = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr, pAdapterAddresses, &outBufLen);
	if (dwRetVal == NO_ERROR) {
		PIP_ADAPTER_ADDRESSES pCurrAdapter = pAdapterAddresses;
		while (pCurrAdapter) {
			//PrintAdapterInfo(pCurrAdapter);
			printf("Adapter %s:\n", pCurrAdapter->AdapterName);
			wprintf(L"  Name: %s\n", pCurrAdapter->Description);

			// Print IP addresses
			PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurrAdapter->FirstUnicastAddress;
			while (pUnicast) {
				// IPv4
				if (pUnicast->Address.lpSockaddr->sa_family == AF_INET) {
					char ipAddr[INET_ADDRSTRLEN];
					sockaddr_in* saIn = (sockaddr_in*)pUnicast->Address.lpSockaddr;
					inet_ntop(AF_INET, &(saIn->sin_addr), ipAddr, INET_ADDRSTRLEN);
					printf("  IPv4: %s\n", ipAddr);
				}
				// Ipv6
				if (pUnicast->Address.lpSockaddr->sa_family == AF_INET6) {
					char ipAddr[INET6_ADDRSTRLEN];
					sockaddr_in6* saIn6 = (sockaddr_in6*)pUnicast->Address.lpSockaddr;
					inet_ntop(AF_INET6, &(saIn6->sin6_addr), ipAddr, INET6_ADDRSTRLEN);
					printf("  IPv6: %s\n", ipAddr);
				}

				pUnicast = pUnicast->Next;
			}

			pCurrAdapter = pCurrAdapter->Next;
		}
	}
	else {
		printf("Error: Failed to get adapter addresses.\n");
		free(pAdapterAddresses);
		WSACleanup();
		return FALSE;
	}

	return TRUE;
}

BOOL SystemInfoGathering() {
	GetSystemVersion();
	GetSystemLanguage();
	GetTimezone();
	GetComputerNameAndUserName();
	GetNetworkInfo();
	
	return TRUE;
}
