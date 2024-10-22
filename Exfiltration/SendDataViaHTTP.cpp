/*
Title: Send Data via HTTP
*/
#include <Windows.h>
#include <winhttp.h>
#include <string>
#include <stdio.h>
#pragma comment(lib, "winhttp.lib")

VOID FreeAll(HINTERNET hSession, HINTERNET hConnect, HINTERNET hRequest) {
	if (hSession)
		WinHttpCloseHandle(hSession);
	if (hConnect)
		WinHttpCloseHandle(hConnect);
	if (hRequest)
		WinHttpCloseHandle(hRequest);
}

BOOL SendDataViaHTTP() {
	// ----------------------------------------------------------- //
	// Replace the following values.

	BOOL bHTTPS = TRUE; // HTTPS or HTTP
	
	LPCWSTR lpUrl = L"httpbin.org";
	INTERNET_PORT wPort = 443;
	LPCWSTR lpUrlPath = L"/post";
	
	LPCWSTR lpMethod = L"POST";
	
	LPCWSTR lpUserAgent = L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36";
	
	LPCWSTR lpHeaders = L"Accept: application/json"; // If we don't want to set additional headers, set WINHTTP_NO_ADDITIONAL_HEADERS.
	DWORD dwHeadersLength = (DWORD)wcslen(lpHeaders);
	
	const char* sData = "data=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"; // Data to send
	DWORD dwDataLength = (DWORD)strlen(sData);
	// ----------------------------------------------------------- //

	HINTERNET hSession = WinHttpOpen(
		lpUserAgent,
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS,
		0
	);
	if (!hSession) return FALSE;

	HINTERNET hConnect = WinHttpConnect(
		hSession,
		lpUrl,
		wPort,
		0
	);
	if (!hConnect) {
		FreeAll(hSession, nullptr, nullptr);
		return FALSE;
	}

	DWORD dwFlag = WINHTTP_FLAG_SECURE;
	if (!bHTTPS) dwFlag = 0;

	HINTERNET hRequest = WinHttpOpenRequest(
		hConnect,
		lpMethod,
		lpUrlPath,
		nullptr,
		WINHTTP_NO_REFERER,
		WINHTTP_DEFAULT_ACCEPT_TYPES,
		dwFlag
	);
	if (!hRequest) {
		FreeAll(hSession, hConnect, nullptr);
		return FALSE;
	}

	if (!WinHttpSendRequest(
		hRequest,
		lpHeaders,
		0,
		(LPVOID)sData,
		dwDataLength,
		dwDataLength,
		0
	)) {
		FreeAll(hSession, hConnect, hRequest);
		return FALSE;
	}

	if (!WinHttpReceiveResponse(hRequest, nullptr)) {
		FreeAll(hSession, hConnect, hRequest);
		return FALSE;
	}

	// ----------------------------------------------------------- //
	// Receive the response from the server.
	// ----------------------------------------------------------- //

	DWORD dwSize = 0;
	LPSTR pszBuffer;
	DWORD dwBytesRead = 0;

	char* sRespData = nullptr;
	size_t dwTotalSize = 0;

	do {
		dwSize = 0;
		if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
			break;
		}

		if (dwSize > 0) {
			pszBuffer = new char[dwSize + 1];
			ZeroMemory(pszBuffer, dwSize + 1);

			if (!WinHttpReadData(hRequest, (LPVOID)pszBuffer, dwSize, &dwBytesRead)) {
				delete[] pszBuffer;
				break;
			}

			// Append to the sRespData
			char* sTmpRespData = new char[dwTotalSize + dwBytesRead + 1];
			if (sRespData) {
				memcpy(sTmpRespData, sRespData, dwTotalSize);
				delete[] sRespData;
			}
			memcpy(sTmpRespData + dwTotalSize, pszBuffer, dwBytesRead);
			dwTotalSize += dwBytesRead;
			sTmpRespData[dwTotalSize] = '\0';

			sRespData = sTmpRespData;

			delete[] pszBuffer;
		}
	} while (dwSize > 0);

	if (sRespData) {
		printf("Response:\n%s\n", sRespData);
		delete[] sRespData;
	}

	FreeAll(hSession, hConnect, hRequest);

	return TRUE;
}
