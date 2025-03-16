/*
Title: Extract WiFi Passwords
*/

#include <Windows.h>
#include <wlanapi.h>
#include <iostream>
#include <string>

#pragma comment(lib, "wlanapi.lib")

BOOL ExtractWiFiPasswords() {
	DWORD dwMaxClient = 2;
	DWORD dwCurVersion = 0;
	HANDLE hClient = NULL;

	DWORD dwResult = WlanOpenHandle(dwMaxClient, NULL, &dwCurVersion, &hClient);
	if (dwResult != ERROR_SUCCESS)
		return FALSE;

	// Enumerate the interfaces
	PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
	dwResult = WlanEnumInterfaces(hClient, NULL, &pIfList);
	if (dwResult != ERROR_SUCCESS) {
		WlanCloseHandle(hClient, NULL);
		return FALSE;
	}

	// Enumerate profiles of each interface
	for (DWORD i = 0; i < pIfList->dwNumberOfItems; i++) {
		PWLAN_INTERFACE_INFO pIfInfo = &pIfList->InterfaceInfo[i];

		PWLAN_PROFILE_INFO_LIST pProfileList = NULL;
		dwResult = WlanGetProfileList(hClient, &pIfInfo->InterfaceGuid, NULL, &pProfileList);
		if (dwResult != ERROR_SUCCESS)
			continue;
		
		// Enumerate details of each profile
		for (DWORD j = 0; j < pProfileList->dwNumberOfItems; j++) {
			LPWSTR lpProfileXml = NULL;
			DWORD dwFlags = WLAN_PROFILE_GET_PLAINTEXT_KEY; // For getting the WiFi password in plain text
			DWORD dwGrantedAccess = 0;

			dwResult = WlanGetProfile(
				hClient,
				&pIfInfo->InterfaceGuid,
				pProfileList->ProfileInfo[j].strProfileName,
				NULL,
				&lpProfileXml,
				&dwFlags,
				&dwGrantedAccess
			);
			if (dwResult != ERROR_SUCCESS)
				continue;

			// Extract the WiFi password
			std::wstring xml(lpProfileXml);
			std::wstring keyStart = L"<keyMaterial>";
			std::wstring keyEnd = L"</keyMaterial>";

			std::wcout << L"SSID: " << pProfileList->ProfileInfo[j].strProfileName << std::endl;

			size_t startPos = xml.find(keyStart);
			size_t endPos = xml.find(keyEnd);
			if (startPos != std::wstring::npos && endPos != std::wstring::npos) {
				startPos += keyStart.length();
				std::wstring password = xml.substr(startPos, endPos - startPos);
				std::wcout << L"Password: " << password << std::endl;
			}
			else {
				std::wcout << L"Password: Not found" << std::endl;
			}
			std::wcout << std::endl;

			WlanFreeMemory(lpProfileXml);
		}
		WlanFreeMemory(pProfileList);
	}

	WlanFreeMemory(pIfList);
	WlanCloseHandle(hClient, NULL);

	return TRUE;
}
