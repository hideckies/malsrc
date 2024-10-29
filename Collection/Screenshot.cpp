/*
* Title: Screenshot
* Resources:
*   - https://gist.github.com/prashanthrajagopal/05f8ad157ece964d8c4d
*/
#include <Windows.h>
#include <gdiplus.h>
#include <string>
#include <stdio.h>
#pragma comment(lib, "Gdiplus.lib")

using namespace Gdiplus;

BOOL GetEncoderClsid(const WCHAR* format, CLSID* pClsid) {
	UINT num = 0;
	UINT size = 0;

	ImageCodecInfo* pImageCodecInfo = nullptr;

	GetImageEncodersSize(&num, &size);
	if (size == 0) return FALSE;

	pImageCodecInfo = (ImageCodecInfo*)(malloc(size));
	if (!pImageCodecInfo) return -1;

	if (GetImageEncoders(num, size, pImageCodecInfo) != 0) // OK = 0
		return FALSE;

	for (UINT i = 0; i < num; i++) {
		if (wcscmp(pImageCodecInfo[i].MimeType, format) == 0) {
			*pClsid = pImageCodecInfo[i].Clsid;
			free(pImageCodecInfo);
			return TRUE;
		}
	}
	free(pImageCodecInfo);
	return FALSE;
}

VOID GdiScreen(LPCWSTR wPathToSave) {
	IStream* pIstream;
	HRESULT res = CreateStreamOnHGlobal(nullptr, TRUE, &pIstream);

	ULONG_PTR token;
	GdiplusStartupInput gsi;
	if (GdiplusStartup(&token, &gsi, nullptr) == 0) { // OK = 0
		HDC hDc = ::GetDC(nullptr);
		if (!hDc) return;

		int height = GetSystemMetrics(SM_CYSCREEN);
		if (height == 0) {
			::ReleaseDC(nullptr, hDc);
			return;
		}
		int width = GetSystemMetrics(SM_CXSCREEN);
		if (width == 0) {
			::ReleaseDC(nullptr, hDc);
			return;
		}

		HDC hMemDc = CreateCompatibleDC(hDc);
		if (!hMemDc) {
			::ReleaseDC(nullptr, hDc);
			return;
		}

		HBITMAP hMembit = CreateCompatibleBitmap(hDc, width, height);
		if (!hMembit) {
			::ReleaseDC(nullptr, hDc);
			DeleteObject(hMemDc);
			return;
		}

		HBITMAP hOldBitmap = (HBITMAP)SelectObject(hMemDc, hMembit);
		if (!hOldBitmap) {
			::ReleaseDC(nullptr, hDc);
			DeleteObject(hMemDc);
			return;
		}
		if (!BitBlt(hMemDc, 0, 0, width, height, hDc, 0, 0, SRCCOPY)) {
			::ReleaseDC(nullptr, hDc);
			DeleteObject(hMemDc);
			return;
		}

		Gdiplus::Bitmap bitmap(hMembit, 0);
		CLSID clsId;
		if (!GetEncoderClsid(L"image/png", &clsId)) {
			::ReleaseDC(nullptr, hDc);
			DeleteObject(hMemDc);
			return;
		}
		bitmap.Save(wPathToSave, &clsId, nullptr);
	}
	GdiplusShutdown(token);
}

BOOL Screenshot() {
	// Replace the following values.
	int num = 10;
	DWORD dwInterval = 1 * 1000; // millisceonds
	std::wstring wSaveDir = L"C:\\screenshots";

	for (int i = 0; i < num; i++) {
		std::wstring wPathToSave = wSaveDir + L"\\screenshot_" + std::to_wstring(i) + L".png";
		GdiScreen(wPathToSave.c_str());

		Sleep(dwInterval);
	}

	return TRUE;
}
