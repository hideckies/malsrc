/*
* Title: CallStackMasker
* Resources:
*	- https://github.com/Cobalt-Strike/CallStackMasker
*/
#include <Windows.h>
#include <ehdata.h>
#include <vector>
#include <exception>
#include <iostream>
#include <Psapi.h>
#include "Nt.hpp"
#include "CallStackMasker.hpp"

std::vector<StackFrame> spoofedCallStack =
{
	StackFrame(L"C:\\Windows\\SYSTEM32\\kernelbase.dll", "WaitForSingleObjectEx", 0x8e, 0, FALSE),
	StackFrame(L"C:\\Windows\\SYSTEM32\\localspl.dll", "InitializePrintMonitor2", 0xb7a, 0 , TRUE),
	StackFrame(L"C:\\Windows\\SYSTEM32\\kernel32.dll", "BaseThreadInitThunk", 0x14, 0, FALSE),
	StackFrame(L"C:\\Windows\\SYSTEM32\\ntdll.dll", "RtlUserThreadStart", 0x21, 0, FALSE),
};

// Global struct to store target thread info.
threadToSpoof targetThreadToSpoof = {};

NTSTATUS NormalizeAddress(
	const HANDLE hProcess,
	const PVOID pRemoteAddr,
	PVOID& pLocalAddr,
	const BOOL bIgnoreExe,
	const imageMap& imageBaseMap
) {
	NTSTATUS status = STATUS_SUCCESS;

	MEMORY_BASIC_INFORMATION mbi = { 0 };

	if (!VirtualQueryEx(hProcess, (PVOID)pRemoteAddr, &mbi, sizeof(mbi))) {
		return STATUS_UNSUCCESSFUL;
	}

	ULONG64 offset = (PCHAR)pRemoteAddr - (PCHAR)mbi.AllocationBase;

	std::string moduleName;
	status = GetModuleBaseNameWrapper(hProcess, mbi.AllocationBase, moduleName);
	if (!NT_SUCCESS(status)) {
		return STATUS_UNSUCCESSFUL;
	}

	if (bIgnoreExe) {
		if ((moduleName.find(".exe") != std::string::npos) || (moduleName.find(".EXE") != std::string::npos)) {
			return STATUS_UNSUCCESSFUL;
		}
	}

	HMODULE hModule = GetModuleHandleA(moduleName.c_str());
	if (!hModule) {
		hModule = LoadLibraryA(moduleName.c_str());
		if (!hModule) {
			return STATUS_UNSUCCESSFUL;
		}
		// Add to map so that if we fail later on in the stack unwinding process we can upload any dlls no longer needed.
		(const_cast<imageMap&>(imageBaseMap)).insert({ moduleName, hModule });
	}
	pLocalAddr = (PCHAR)hModule + offset;

	return STATUS_SUCCESS;
}

NTSTATUS GetModuleBaseNameWrapper(HANDLE hProcess, PVOID pTargetAddr, std::string& moduleName) {
	char szModuleBaseName[MAX_PATH];

	if (GetModuleBaseNameA(hProcess, (HMODULE)pTargetAddr, szModuleBaseName, sizeof(szModuleBaseName))) {
		moduleName = szModuleBaseName;
	}
	else {
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}

NTSTATUS GetImageBase(const StackFrame& stackFrame) {
	HMODULE hTmpImageBase = nullptr;

	// Check if image base has already been resolved.
	if (imageBaseMap.count(stackFrame.targetDll)) {
		return STATUS_SUCCESS;
	}

	// Check if current frame contains a non-standard dll and load if so.
	if (stackFrame.requiresLoadLibrary) {
		hTmpImageBase = LoadLibrary(stackFrame.targetDll.c_str());
		if (!hTmpImageBase) {
			return STATUS_DLL_NOT_FOUND;
		}
	}

	// If we haven't already recorded the image base capture it now.
	if (!hTmpImageBase) {
		hTmpImageBase = GetModuleHandle(stackFrame.targetDll.c_str());
		if (!hTmpImageBase) {
			return STATUS_DLL_NOT_FOUND;
		}
	}

	// Add to image base map to avoid superflous recalculating.
	imageBaseMap.insert({ stackFrame.targetDll, hTmpImageBase });

	return STATUS_SUCCESS;
}

NTSTATUS CalculateReturnAddress(StackFrame& stackFrame) {
	try {
		const PVOID pTargetImageBaseAddr = imageBaseMap.at(stackFrame.targetDll);
		if (!pTargetImageBaseAddr) {
			return STATUS_DLL_NOT_FOUND;
		}
		auto funcAddr = GetProcAddress((HMODULE)pTargetImageBaseAddr, stackFrame.targetFunc.c_str());
		if (!funcAddr) {
			return STATUS_ORDINAL_NOT_FOUND;
		}
		stackFrame.returnAddress = (PCHAR)funcAddr + stackFrame.offset;
	}
	catch (const std::out_of_range&) {
		return STATUS_DLL_NOT_FOUND;
	}

	return STATUS_SUCCESS;
}

NTSTATUS CalculateFunctionStackSize(PRUNTIME_FUNCTION pRuntimeFunc, const DWORD64 dwImageBase, StackFrame& stackFrame) {
	if (!pRuntimeFunc) {
		return STATUS_INVALID_PARAMETER;
	}

	// Loop over unwind info.
	PUNWIND_INFO pUnwindInfo = (PUNWIND_INFO)(pRuntimeFunc->UnwindData + dwImageBase);
	ULONG index = 0;
	ULONG unwindOp = 0;
	ULONG opInfo = 0;
	ULONG frameOffset = 0;
	while (index < pUnwindInfo->CountOfCodes) {
		unwindOp = pUnwindInfo->UnwindCode[index].UnwindOp;
		opInfo = pUnwindInfo->UnwindCode[index].OpInfo;
		// Loop over unwind codes and calculate total stack size space used by target function.
		switch (unwindOp) {
		case UWOP_PUSH_NONVOL:
			// UWOP_PUSH_NONVOL is 8 bytes.
			stackFrame.totalStackSize += 8;

			if (opInfo == RBP_OP_INFO) {
				stackFrame.pushRbp = true;
				stackFrame.countOfCodes = pUnwindInfo->CountOfCodes;
				stackFrame.pushRbpIndex = index + 1;
			}
			break;
		case UWOP_SAVE_NONVOL:
			index += 1;
			break;
		case UWOP_ALLOC_SMALL:
			stackFrame.totalStackSize += ((opInfo * 8) + 8);
			break;
		case UWOP_ALLOC_LARGE:
			index += 1;
			frameOffset = pUnwindInfo->UnwindCode[index].FrameOffset;
			if (opInfo == 0) {
				frameOffset *= 8;
			}
			else {
				index += 1;
				frameOffset += (pUnwindInfo->UnwindCode[index].FrameOffset << 16);
			}
			stackFrame.totalStackSize += frameOffset;
			break;
		case UWOP_SET_FPREG:
			stackFrame.setsFramePointer = true;
			break;
		default:
			return STATUS_ASSERTION_FAILURE;
		}

		index += 1;
	}

	if (pUnwindInfo->Flags & UNW_FLAG_CHAININFO) {
		index = pUnwindInfo->CountOfCodes;
		if ((index & 1) != 0) {
			index += 1;
		}
		pRuntimeFunc = (PRUNTIME_FUNCTION)(&pUnwindInfo->UnwindCode[index]);
		return CalculateFunctionStackSize(pRuntimeFunc, dwImageBase, stackFrame);
	}

	// Add the size of the return address (8 bytes).
	stackFrame.totalStackSize += 8;
}

NTSTATUS CalculateFunctionStackSizeWrapper(StackFrame& stackFrame) {
	if (!stackFrame.returnAddress) {
		return STATUS_INVALID_PARAMETER;
	}

	DWORD64 dwImageBase = 0;
	PUNWIND_HISTORY_TABLE pHistoryTable = nullptr;

	PRUNTIME_FUNCTION pRuntimeFunc = RtlLookupFunctionEntry(
		(DWORD64)stackFrame.returnAddress,
		&dwImageBase,
		pHistoryTable
	);
	if (!pRuntimeFunc) {
		return STATUS_ASSERTION_FAILURE;
	}

	return CalculateFunctionStackSize(pRuntimeFunc, dwImageBase, stackFrame);
}

NTSTATUS InitializeSpoofedCallStack(std::vector<StackFrame>& targetCallStack) {
	NTSTATUS status = STATUS_SUCCESS;

	for (auto stackFrame = targetCallStack.begin(); stackFrame != targetCallStack.end(); stackFrame++) {
		// Get image base for current stack frame.
		status = GetImageBase(*stackFrame);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		// Calculate ret address for current stack frame.
		status = CalculateReturnAddress(*stackFrame);
		if (!NT_SUCCESS(status)) {
			return status;
		}

		// Calculate the total stack size for ret function.
		status = CalculateFunctionStackSizeWrapper(*stackFrame);
		if (!NT_SUCCESS(status)) {
			return status;
		}
	}

	return status;
}

ULONG CalculateStaticStackSize(const std::vector<StackFrame>& targetCallStack) {
	ULONG totalStackCount = 0x0;
	for (auto entry : targetCallStack) {
		totalStackCount += entry.totalStackSize;
	}
	// Add 0x8 so we can write 0x0 as last address and stop stack unwinding.
	totalStackCount += 0x8;
	return totalStackCount;
}

NTSTATUS CalculateDynamicStackSize(const HANDLE hProcess, const CONTEXT ctx, ULONG& totalStackSize) {
	NTSTATUS status = STATUS_SUCCESS;

	BOOL bFinishedUnwinding = FALSE;
	BOOL bHandledFirstFrame = FALSE;
	PVOID pReturnAddr = nullptr;
	PVOID pPrevReturnAddr = nullptr;
	imageMap imageBaseMap = {};

	PVOID pCurrentChildSP = (PVOID)ctx.Rsp;
	PVOID pStackIndex = (PVOID)ctx.Rsp;

	// Start unwinding the target thread stack.
	while (!bFinishedUnwinding) {
		if (!bHandledFirstFrame) {
			pReturnAddr = (PVOID)ctx.Rip;
			bHandledFirstFrame = TRUE;
		}
		else {
			pPrevReturnAddr = pReturnAddr;
			pReturnAddr = readProcessMemory<PVOID>(hProcess, (LPVOID)pStackIndex);
		}

		// Windows unwinds until it finds ret address of 0x0.
		if (pReturnAddr == 0x0) {
			if (!CheckIfAddressIsWithinTargetFunc(pPrevReturnAddr, "ntdll", "RtlUserThreadStart")) {
				goto Cleanup;
			}
			status = STATUS_SUCCESS;
			bFinishedUnwinding = TRUE;
		}
		else {
			StackFrame targetFrame = {};

			status = NormalizeAddress(hProcess, pReturnAddr, targetFrame.returnAddress, TRUE, imageBaseMap);
			if (!NT_SUCCESS(status)) {
				goto Cleanup;
			}

			DWORD64 dwImageBase = 0;
			PUNWIND_HISTORY_TABLE pHistoryTable = nullptr;
			ULONG functionStackSize = 0;

			// Calculate function size.
			PRUNTIME_FUNCTION pRuntimeFunc = RtlLookupFunctionEntry(
				(DWORD64)targetFrame.returnAddress,
				&dwImageBase,
				pHistoryTable
			);
			status = CalculateFunctionStackSize(pRuntimeFunc, dwImageBase, targetFrame);
			if (!NT_SUCCESS(status)) {
				goto Cleanup;
			}

			totalStackSize += targetFrame.totalStackSize;
			functionStackSize = targetFrame.totalStackSize;

			// Find next child SP
			pCurrentChildSP = (PCHAR)pCurrentChildSP + functionStackSize;

			// Find next return address.
			pStackIndex = (PCHAR)pCurrentChildSP - 0x8;
		}
	}

Cleanup:
	if (!NT_SUCCESS(status)) {
		for (auto const& lib : imageBaseMap) {
			(void)FreeLibrary(lib.second);
		}
	}
	return status;
}

BOOL IsThreadAMatch(const HANDLE hProcess, const DWORD pid, const DWORD tid, threadToSpoof& thread) {
	BOOL bMatch = FALSE;

	HANDLE hThread = INVALID_HANDLE_VALUE;
	HANDLE hHeap = INVALID_HANDLE_VALUE;
	BOOL bIsWow64 = false;
	CONTEXT ctx = { 0 };

	PVOID returnAddress = NULL;
	PVOID remoteStartAddress = NULL;
	ULONG totalStackSize = 0;

	// [1] Open handle to thread.
	hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
	if (!hThread)
	{
		std::cout << "[-] Failed to open a handle to thread: " << tid << "\n";
		goto Cleanup;
	}

	// [2] Get thread context.
	std::cout << "[+] Scanning tid: " << std::dec << tid << "\n";
	ctx.ContextFlags = CONTEXT_FULL;
	if (!GetThreadContext(hThread, &ctx))
	{
		std::cout << "[-] Failed to get thread context for: " << tid << "\n";
		goto Cleanup;
	}

	// [3] Retrieve the last return address on the stack and check if it is
	// our target function to spoof.
	returnAddress = readProcessMemory<PVOID>(hProcess, (LPVOID)ctx.Rsp);
	if (!CheckIfAddressIsWithinTargetFunc(returnAddress, std::string("kernelbase"), std::string("WaitForSingleObjectEx")))
	{
		goto Cleanup;
	}

	// [4] Now try and confirm we can unwind the stack and calculate total required stack size.
	if (!NT_SUCCESS(CalculateDynamicStackSize(hProcess, ctx, totalStackSize)))
	{
		goto Cleanup;
	}

	// [5] Lastly, we need to retrieve the threads starting address in order to spoof it.
	if (!NT_SUCCESS(GetThreadStartAddress(hThread, remoteStartAddress)))
	{
		std::cout << "[-] Error retrieving thread start address\n";
		goto Cleanup;
	}

	// [6] The start address is specific to context of remote process, so ensure the
	// offset is correct for wherever the dll is loaded in our memory space.
	if (!NT_SUCCESS(NormalizeAddress(hProcess, remoteStartAddress, thread.startAddr, FALSE, imageMap())))
	{
		std::cout << "[-] Error re-calculating thread start address\n";
		goto Cleanup;
	}

	// [7] At this stage, the thread stack is a match so make a copy.
	// To simplify this PoC (and to avoid any TOCTOU style issues) copy the stack
	// now and use the same buffer repeatedly. NB this is currently never freed,
	// but it is irrelevant as PoC runs on while true loop.
	hHeap = GetProcessHeap();
	thread.pFakeStackBuffer = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, totalStackSize);
	if (!ReadProcessMemory(hProcess, (LPCVOID)ctx.Rsp, thread.pFakeStackBuffer, totalStackSize, NULL))
	{
		HeapFree(hHeap, NULL, thread.pFakeStackBuffer);
		thread.pFakeStackBuffer = NULL;
		goto Cleanup;
	}

	thread.dwPid = pid;
	thread.dwTid = tid;
	thread.totalRequiredStackSize = totalStackSize;

	bMatch = TRUE;

Cleanup:
	CloseHandle(hThread);
	return bMatch;
}

NTSTATUS InitializeDynamicCallStackSpoofing(const ULONG waitReason, threadToSpoof& thread) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	ULONG uBufferSize = 0;
	PVOID pBuffer = NULL;
	_NtQuerySystemInformation ntQuerySystemInformation = NULL;
	SYSTEM_PROCESS_INFORMATION* pSystemProcessInformation = NULL;
	SYSTEM_THREAD_INFORMATION systemThreadInformation = { 0 };

	// [1] Enumerate threads system wide and locate a thread with desired WaitReason.
	ntQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
	if (!ntQuerySystemInformation)
	{
		status = STATUS_UNSUCCESSFUL;
		goto Cleanup;
	}
	status = ntQuerySystemInformation(SystemProcessInformation, pBuffer, uBufferSize, &uBufferSize);
	if (STATUS_INFO_LENGTH_MISMATCH != status)
	{
		status = STATUS_UNSUCCESSFUL;
		goto Cleanup;
	}
	pBuffer = LocalAlloc(LMEM_FIXED, uBufferSize);
	if (!pBuffer)
	{
		status = STATUS_UNSUCCESSFUL;
		goto Cleanup;
	}
	if (!NT_SUCCESS(ntQuerySystemInformation(SystemProcessInformation, pBuffer, uBufferSize, &uBufferSize)))
	{
		status = STATUS_UNSUCCESSFUL;
		goto Cleanup;
	}
	pSystemProcessInformation = (SYSTEM_PROCESS_INFORMATION*)pBuffer;

	// [2] Loop over threads and attempt to find one where the last address on the
	// stack is located within out target waiting function (e.g. WaitForSingleObjectEx).
	while (pSystemProcessInformation && pSystemProcessInformation->NextEntryOffset)
	{
		BOOL bEnumThreads = true;
		HANDLE hProcess = INVALID_HANDLE_VALUE;
		BOOL bIsWow64 = false;

		if (NULL != pSystemProcessInformation->ImageName.Buffer)
		{
			std::wcout << "[+] Searching process: " << pSystemProcessInformation->ImageName.Buffer << " (" << pSystemProcessInformation->ProcessId << ")" << "\n";
		}

		// [3] Attempt to open a handle to target process.
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pSystemProcessInformation->ProcessId);
		if (!hProcess)
		{
			std::cout << "[-] Failed to open a handle to process: " << pSystemProcessInformation->ProcessId << "\n";
			bEnumThreads = false;
		}

		// [4] Ignore WOW64.
		if (bEnumThreads && IsWow64Process(hProcess, &bIsWow64))
		{
			if (bIsWow64)
			{
				std::cout << "[-] Ignoring WOW64\n";
				bEnumThreads = false;
			}
		}

		// [5] Enumerate threads.
		if (bEnumThreads)
		{
			for (ULONG i = 0; i < pSystemProcessInformation->NumberOfThreads; i++)
			{
				systemThreadInformation = pSystemProcessInformation->ThreadInfos[i];

				// Ignore any threads not in our desired wait state.
				if (waitReason != systemThreadInformation.WaitReason)
				{
					continue;
				}

				// [6] Attempt to unwind the stack and check if stack is in our desired wait state.
				if (IsThreadAMatch(hProcess, pSystemProcessInformation->ProcessId, (DWORD)systemThreadInformation.ClientId.UniqueThread, thread))
				{
					// We have found a thread to clone!
					std::cout << "    [+] Successfully located a thread call stack to clone!" << "\n";
					std::wcout << "    [+] Cloning call stack from process: " << pSystemProcessInformation->ImageName.Buffer << "\n";
					std::cout << "    [+] Cloning call stack from pid: " << std::dec << pSystemProcessInformation->ProcessId << "\n";
					std::cout << "    [+] Cloning call stack from tid: " << std::dec << (DWORD)systemThreadInformation.ClientId.UniqueThread << "\n";
					std::cout << "    [+] Target thread start address is: 0x" << std::hex << thread.startAddr << "\n";
					std::cout << "    [+] Total stack size required: 0x" << thread.totalRequiredStackSize << "\n";
					status = STATUS_SUCCESS;
					CloseHandle(hProcess);
					goto Cleanup;
				}
			}
		}
		// Avoid leaking handles.
		if (hProcess)
		{
			CloseHandle(hProcess);
		}
		pSystemProcessInformation = (SYSTEM_PROCESS_INFORMATION*)((LPBYTE)pSystemProcessInformation + pSystemProcessInformation->NextEntryOffset);
	}

	// [7] If we reached here we did not find a suitable thread call stack to spoof.
	std::cout << "[!] Could not find a suitable callstack to clone.\n";

Cleanup:
	LocalFree(pBuffer);
	return status;
}

NTSTATUS CreateFakeStackInBuffer(const std::vector<StackFrame>& targetCallStack, const PVOID pSpoofedStack) {
	NTSTATUS status = STATUS_SUCCESS;

	if (!pSpoofedStack) {
		return STATUS_INVALID_PARAMETER;
	}

	// Loop over buffer and create desired stack layout.
	int64_t* index = (int64_t*)pSpoofedStack;
	for (auto entry : targetCallStack) {
		*index = (int64_t)entry.returnAddress;
		auto offset = entry.totalStackSize / sizeof(int64_t);
		index += offset;
	}

	// Stop stack unwinding by writing 0x0 at end of buffer.
	*index = 0x0;

	return status;
}

NTSTATUS InitializeStaticCallStackSpoofing(std::vector<StackFrame>& targetCallStack, threadToSpoof& thread) {
	NTSTATUS status = STATUS_SUCCESS;

	status = InitializeSpoofedCallStack(targetCallStack);
	if (!NT_SUCCESS(status)) {
		return STATUS_UNSUCCESSFUL;	
	}

	// Calculate total stack space required for fake call stack.
	thread.totalRequiredStackSize = CalculateStaticStackSize(targetCallStack);

	// Allocate heap memory for required fake call stack.
	HANDLE hHeap = GetProcessHeap();
	if (!hHeap) {
		return STATUS_UNSUCCESSFUL;
	}
	thread.pFakeStackBuffer = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, thread.totalRequiredStackSize);
	if (!thread.pFakeStackBuffer) {
		return STATUS_UNSUCCESSFUL;
	}

	// Create fake stack.
	status = CreateFakeStackInBuffer(targetCallStack, thread.pFakeStackBuffer);
	if (!NT_SUCCESS(status)) {
		return STATUS_UNSUCCESSFUL;
	}

	return status;
}

NTSTATUS GetThreadStartAddress(const HANDLE hThread, PVOID& pStartAddr) {
	NTSTATUS status = STATUS_SUCCESS;

	ntQueryInformationThread = reinterpret_cast<_NtQueryInformationThread>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread"));
	if (!ntQueryInformationThread) {
		return STATUS_UNSUCCESSFUL;
	}

	status = ntQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, &pStartAddr, sizeof(pStartAddr), nullptr);
	if (!NT_SUCCESS(status)) {
		return STATUS_UNSUCCESSFUL;
	}

	return status;
}

BOOL CheckIfAddressIsWithinTargetFunc(const PVOID pTargetAddr, const std::string targetModuleName, const std::string targetFuncName) {
	HMODULE hModule = GetModuleHandleA(targetModuleName.c_str());
	if (!hModule) return FALSE;
	PVOID pTargetFunc = GetProcAddress(hModule, targetFuncName.c_str());
	if (!pTargetFunc) return FALSE;

	DWORD64 dwImageBase = 0;
	PUNWIND_HISTORY_TABLE pHistoryTable = nullptr;

	PRUNTIME_FUNCTION pRuntimeFunc = RtlLookupFunctionEntry(
		(DWORD64)pTargetFunc,
		&dwImageBase,
		pHistoryTable
	);
	if (!pRuntimeFunc) return FALSE;

	void* pTargetFuncStart = (PCHAR)hModule + pRuntimeFunc->BeginAddress;
	void* pTargetFuncEnd = (PCHAR)hModule + pRuntimeFunc->EndAddress;
	if ((pTargetFuncStart < pTargetAddr) && (pTargetAddr < pTargetFuncEnd)) {
		return TRUE;
	}

	return FALSE;
}

VOID CallStackMaskerSleep(DWORD dwSleepTime) {
	CONTEXT ctxThread = { 0 };

	CONTEXT ropBackUpStack = { 0 };
	CONTEXT ropSpoofStack = { 0 };
	CONTEXT ropRestoreStack = { 0 };
	CONTEXT ropSetEvent = { 0 };

	PVOID ntContinue = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtContinue");

	HANDLE hTimerQueue = CreateTimerQueue();
	HANDLE hEvent = CreateEventW(0, 0, 0, 0);

	// Create a buffer to backup current state of stack.
	HANDLE hHeap = GetProcessHeap();
	PVOID pCopyOfStack = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, targetThreadToSpoof.totalRequiredStackSize);

	// Work out Child-SP of current frame.
	void* pChildSP = GetChildSP();

	// Calculate RSP at the point when NtWaitForSingleObject sys call
	void* pRsp = (PCHAR)pChildSP - spoofedCallStack.front().totalStackSize - 0x8;

	// Setup timers.
	HANDLE hNewTimer = nullptr;
	if (CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)RtlCaptureContext, &ctxThread, 0, 0, WT_EXECUTEINTIMERTHREAD)) {
		WaitForSingleObject(hEvent, 0x32);

		memcpy(&ropBackUpStack, &ctxThread, sizeof(CONTEXT));
		memcpy(&ropSpoofStack, &ctxThread, sizeof(CONTEXT));
		memcpy(&ropRestoreStack, &ctxThread, sizeof(CONTEXT));
		memcpy(&ropSetEvent, &ctxThread, sizeof(CONTEXT));

		// Backup the stack.
		ropBackUpStack.Rsp -= 8;
		ropBackUpStack.Rip = (DWORD64)memcpy; // VCRUNTIME140!memcpy
		ropBackUpStack.Rcx = (DWORD64)pCopyOfStack; // Destination
		ropBackUpStack.Rdx = (DWORD64)pRsp; // Source
		ropBackUpStack.R8 = (DWORD64)targetThreadToSpoof.totalRequiredStackSize; // Length

		// Overwrite the stack with fake callstack.
		ropSpoofStack.Rsp -= 8;
		ropSpoofStack.Rip = (DWORD64)memcpy;
		ropSpoofStack.Rcx = (DWORD64)pRsp; // Destination
		ropSpoofStack.Rdx = (DWORD64)targetThreadToSpoof.pFakeStackBuffer; // Source
		ropSpoofStack.R8 = (DWORD64)targetThreadToSpoof.totalRequiredStackSize; // Length

		// Restore original call stack.
		ropRestoreStack.Rsp -= 8;
		ropRestoreStack.Rip = (DWORD64)memcpy;
		ropRestoreStack.Rcx = (DWORD64)pRsp; // Destination
		ropRestoreStack.Rdx = (DWORD64)pCopyOfStack; // Source
		ropRestoreStack.R8 = (DWORD64)targetThreadToSpoof.totalRequiredStackSize; // Length

		// Set event.
		ropSetEvent.Rsp -= 8;
		ropSetEvent.Rip = (DWORD64)SetEvent;
		ropSetEvent.Rcx = (DWORD64)hEvent;

		CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)ntContinue, &ropBackUpStack, 1, 0, WT_EXECUTEINTIMERTHREAD);
		CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)ntContinue, &ropSpoofStack, 10, 0, WT_EXECUTEINTIMERTHREAD);
		CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)ntContinue, &ropRestoreStack, dwSleepTime, 0, WT_EXECUTEINTIMERTHREAD);
		CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)ntContinue, &ropSetEvent, dwSleepTime + 10, 0, WT_EXECUTEINTIMERTHREAD);
	}

	// Wait for event to be set by timer. Call stack will be masked throughout this period.
	WaitForSingleObject(hEvent, INFINITE);

	// Cleanup
	DeleteTimerQueue(hTimerQueue);
	HeapFree(hHeap, 0, pCopyOfStack);
}

VOID Go() {
	DWORD dwSleepTime = 4000;

	do {
		printf("CallStackMaskerSleep: Start\n");
		CallStackMaskerSleep(dwSleepTime);
		printf("CallStackMaskerSleep: Finish\n");
	} while (TRUE);
}

BOOL CallStackMasker() {
	// Replace the following values with your preffered ones.
	DWORD dwSleepTime = 4000; // Milliseconds
	BOOL bStaticCallStack = TRUE;

	NTSTATUS status = STATUS_SUCCESS;
	PVOID pStartAddr = nullptr;

	if (bStaticCallStack) {
		status = InitializeStaticCallStackSpoofing(spoofedCallStack, targetThreadToSpoof);
		if (!NT_SUCCESS(status)) return FALSE;

		pStartAddr = (PCHAR)(GetProcAddress(GetModuleHandleA("localspl"), "InitializePrintMonitor2")) + 0xb20;
		if (!pStartAddr) return FALSE;
	}
	else {
		status = InitializeDynamicCallStackSpoofing(UserRequest, targetThreadToSpoof);
		if (!NT_SUCCESS(status)) return FALSE;

		pStartAddr = targetThreadToSpoof.startAddr;
	}

	// Start thread at fake start address.
	DWORD dwThreadId = 0;
	HANDLE hThread = CreateThread(
		nullptr,
		0,
		(LPTHREAD_START_ROUTINE)pStartAddr,
		0,
		CREATE_SUSPENDED,
		&dwThreadId
	);

	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_CONTROL;
	GetThreadContext(hThread, &ctx);
	ctx.Rip = (DWORD64)&Go;
	SetThreadContext(hThread, &ctx);

	ResumeThread(hThread);
	CloseHandle(hThread);

	ExitThread(0);

	return TRUE;
}
