/*
* Title: TypeLib Hijacking
* Resources:
*	- https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661
*	- https://github.com/CICADA8-Research/TypeLibWalker
* Notes:
*	- It's recommended to run as Administrator for finding writable paths.
*/
#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>

std::vector<std::wstring> GetAllCLSIDs() {
	std::vector<std::wstring> clsidList;
	HKEY hKey;

	if (RegOpenKeyEx(HKEY_CLASSES_ROOT, L"CLSID", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
		DWORD dwIndex = 0;
		WCHAR wName[MAX_PATH];
		DWORD dwNameSize = _countof(wName);
		FILETIME ftLastWriteTime;

		while (RegEnumKeyEx(hKey, dwIndex, wName, &dwNameSize, nullptr, nullptr, nullptr, &ftLastWriteTime) == ERROR_SUCCESS) {
			clsidList.push_back(wName);
			dwNameSize = _countof(wName);
			dwIndex++;
		}

		RegCloseKey(hKey);
	}

	return clsidList;
}

BOOL CheckRegistryPermissions(HKEY hRootKey, const std::wstring& wSubKeyPath) {
	REGSAM samDesired = KEY_WRITE | KEY_CREATE_SUB_KEY;

	// Check if the registry (writable or creatable) already exists.
	HKEY hKey;
	if (RegOpenKeyEx(hRootKey, wSubKeyPath.c_str(), 0, samDesired, &hKey) == ERROR_SUCCESS) {
		RegCloseKey(hKey);
		return TRUE;
	}

	// If not, temporalily create a new one and check again.
	if (RegCreateKeyEx(
		hRootKey,
		wSubKeyPath.c_str(),
		0,
		nullptr,
		REG_OPTION_VOLATILE,
		samDesired,
		nullptr,
		&hKey,
		nullptr) == ERROR_SUCCESS) {

		RegCloseKey(hKey);
		RegDeleteKey(hRootKey, wSubKeyPath.c_str());

		return TRUE;
	}

	return FALSE;
}

std::wstring ExpandEnvironmentStringsIfNeeded(const std::wstring& input) {
	if (input.empty())
		return input;

	std::vector<wchar_t> expandedPath(MAX_PATH);
	DWORD dwResult = ExpandEnvironmentStrings(input.c_str(), expandedPath.data(), MAX_PATH);
	if (dwResult == 0 || dwResult > MAX_PATH) {
		return input;
	}

	return std::wstring(expandedPath.data());
}

std::wstring GetRegistryStringValue(HKEY hRootKey, const std::wstring& wSubKeyPath) {
	HKEY hKey;
	if (RegOpenKeyEx(hRootKey, wSubKeyPath.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS)
		return L"";

	DWORD dwType = 0;
	DWORD dwSize = 0;
	if (RegQueryValueEx(hKey, nullptr, nullptr, &dwType, nullptr, &dwSize) != ERROR_SUCCESS ||
		(dwType != REG_SZ && dwType != REG_EXPAND_SZ)) {

		RegCloseKey(hKey);
		return L"";
	}

	std::wstring wValue(dwSize / sizeof(wchar_t), L'\0');
	if (RegQueryValueEx(hKey, nullptr, nullptr, nullptr, reinterpret_cast<LPBYTE>(&wValue[0]), &dwSize) != ERROR_SUCCESS) {
		RegCloseKey(hKey);
		return L"";
	}

	if (!wValue.empty() && wValue.back() == L'\0') {
		wValue.pop_back();
	}
	if (dwType == REG_EXPAND_SZ) {
		wValue = ExpandEnvironmentStringsIfNeeded(wValue);
	}

	return wValue;
}

BOOL CheckFileWriteAccess(const std::wstring& wFilePath) {
	DWORD dwFilePermissions = GENERIC_WRITE;
	HANDLE hFile = CreateFile(wFilePath.c_str(), dwFilePermissions, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (!hFile) {
		return FALSE;
	}
	else {
		CloseHandle(hFile);
		return TRUE;
	}
}

VOID AnalyzeCLSID(std::wstring& wClsid) {
	std::wstring wSubkey = L"CLSID\\" + wClsid + L"\\TypeLib";
	std::wstring wSubkeyVersion = L"CLSID\\" + wClsid + L"\\Version";

	// Get TypeLib.
	HKEY hKey;
	if (RegOpenKeyExW(HKEY_CLASSES_ROOT, wSubkey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS)
		return;
	WCHAR typeLibBuffer[256];
	DWORD dwTypeLibBufferSize = sizeof(typeLibBuffer);
	if (RegQueryValueExW(hKey, nullptr, nullptr, nullptr, (LPBYTE)typeLibBuffer, &dwTypeLibBufferSize) != ERROR_SUCCESS) {
		RegCloseKey(hKey);
		return;
	}
	RegCloseKey(hKey);

	// Get version.
	if (RegOpenKeyExW(HKEY_CLASSES_ROOT, wSubkeyVersion.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS)
		return;
	WCHAR versionBuffer[256];
	DWORD dwVersionBufferSize = sizeof(versionBuffer);
	if (RegQueryValueExW(hKey, nullptr, nullptr, nullptr, (LPBYTE)versionBuffer, &dwVersionBufferSize) != ERROR_SUCCESS) {
		RegCloseKey(hKey);
		return;
	}
	RegCloseKey(hKey);

	std::wstring wTypeLibId(typeLibBuffer);
	std::wstring wVersion(versionBuffer);

	//std::wcout << L"---------------------------" << std::endl;
	//std::wcout << L"CLSID: " << wClsid << std::endl;
	//std::wcout << L"TypeLib: " << wTypeLibId << std::endl;
	//std::wcout << L"Version: " << wVersion << std::endl;

	// Check if the write permission exists in the sub key.
	std::wstring wRootPaths[] = { L"HKCU\\Software\\Classes\\TypeLib\\", L"HKLM\\Software\\Classes\\TypeLib\\"};

	for (size_t i = 0; i < std::size(wRootPaths); ++i) {
		const auto& wRootPath = wRootPaths[i];

		HKEY hRootKey = (wRootPath.find(L"HKCU") != std::wstring::npos) ? HKEY_CURRENT_USER : HKEY_LOCAL_MACHINE;
		std::wstring wTypeLibPath = wRootPath + typeLibBuffer + L"\\" + versionBuffer;
		std::wstring wTypeLibPathSub = wTypeLibPath.substr(wTypeLibPath.find_first_of(L'\\') + 1);

		if (!CheckRegistryPermissions(hRootKey, wTypeLibPathSub))
			continue;
		std::wcout << "[WRITABLE] " << wTypeLibPath << std::endl;

		std::wstring archs[] = {L"WIN64", L"WIN32"};
		for (const auto& arch : archs) {
			std::wstring wFullPath = wTypeLibPath + L"\\0\\" + arch;
			std::wstring wFullPathSub = wFullPath.substr(wFullPath.find_first_of(L'\\') + 1);

			if (!CheckRegistryPermissions(hRootKey, wFullPathSub.c_str()))
				continue;
			std::wcout << "  - " << wFullPath << std::endl;

			std::wstring wDiskPath = GetRegistryStringValue(hRootKey, wFullPathSub.c_str());
			if (!wDiskPath.empty()) {
				std::wcout << L"      [?] Value: " << wDiskPath << std::endl;
				if (CheckFileWriteAccess(wDiskPath)) {
					std::wcout << L"      [+] Writable path on disk: " << wDiskPath << std::endl;
				}
			}
		}

		std::wcout << std::endl;
	}
}

BOOL TypeLibHijacking() {
	// Get all CLSIDs under HKEY_CLASSES_ROOT/CLSID/
	std::vector<std::wstring> clsidList = GetAllCLSIDs();

	CoInitialize(nullptr);
	for (std::wstring& wClsid : clsidList) {
		AnalyzeCLSID(wClsid);
	}
	CoUninitialize();

	return TRUE;
}
