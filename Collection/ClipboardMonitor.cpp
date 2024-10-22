/*
Title: Clipboard Monitor
*/
#include <Windows.h>
#include <vector>
#include <stdio.h>

#define MAX_BUFFER 1024

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

LRESULT CALLBACK WindowProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	return DefWindowProc(hWnd, uMsg, wParam, lParam);
}

BOOL ClipboardMonitor() {
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

	// Clipboard contents will be stored to this.
	std::vector<char*> clipboardContents;
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
					clipboardContents.push_back(pContent);
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

	// Results
	printf("Clipboard contents:\n");
	for (char* content : clipboardContents) {
		printf("[+] %s\n", content);
		delete[] content;
	}

	return TRUE;
}
