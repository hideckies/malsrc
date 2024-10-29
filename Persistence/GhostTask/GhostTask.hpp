#ifndef GHOSTTASK_HPP
#define GHOSTTASK_HPP

#include <Windows.h>
#include <stdint.h>

#define COPY_DATA(dest, src, size) \
	memcpy(dest, src, size); \
	dest += size;

typedef struct Actions {
    SHORT version;
    DWORD dwAuthorSize; // 0xc
    BYTE author[12];
    SHORT magic;
    DWORD id;
    DWORD dwCmdSize;
    wchar_t* wCmd;
    DWORD dwArgumentSize;
    wchar_t* wArgument;
    DWORD dwWorkingDirectorySize;
    wchar_t* wWorkingDirectory;
    short flags;
} Actions;

typedef struct DynamicInfo {
    DWORD dwMagic;
    FILETIME ftCreate;
    FILETIME ftLastRun;
    DWORD dwTaskState;
    DWORD dwLastErrorCode;
    FILETIME ftLastSuccessfulRun;
} DynamicInfo;

typedef struct AlignedByte {
    BYTE value;
    BYTE padding[7];
} AlignedByte;

typedef struct TSTIME {
    AlignedByte isLocalized;
    FILETIME time;
} TSTIME;

// Total size is 0x68
typedef struct TimeTrigger {
    uint32_t magic;
    DWORD unknown0;
    TSTIME startBoundary;
    TSTIME endBoundary;
    TSTIME unknown1;
    DWORD repetitionIntervalSeconds;
    DWORD repetitionDurationSeconds;
    DWORD timeoutSeconds;
    DWORD mode;
    short data0;
    short data1;
    short data2;
    short pad0;
    byte stopTasksAtDurationEnd;
    byte enabled;
    short pad1;
    DWORD unknown2;
    DWORD maxDelaySeconds;
    DWORD pad2;
    uint64_t triggerId;
} TimeTrigger;

// Total size is 0x60
typedef struct LogonTrigger {
    uint32_t magic;
    DWORD unknown0;
    TSTIME startBoundary;
    TSTIME endBoundary;
    DWORD delaySeconds;
    DWORD timeoutSeconds;
    DWORD repetitionIntervalSeconds;
    DWORD repetitionDurationSeconds;
    DWORD repetitionDurationSeconds2;
    DWORD stopAtDurationEnd;
    AlignedByte enabled;
    AlignedByte unknown1;
    DWORD triggerId;
    DWORD blockPadding;
    AlignedByte skipUser; // 0x00 0x48484848484848
} LogonTrigger;

typedef struct Header {
    AlignedByte version;
    TSTIME startBoundary; // The earliest startBoundary of all triggers
    TSTIME endBoundary; // The latest endBoundary of all triggers
} Header;

// Local accounts
typedef struct UserInfoLocal {
    AlignedByte skipUser; // 0x00 0x48484848484848
    AlignedByte skipSid; // 0x00 0x48484848484848
    DWORD sidType; // 0x1
    DWORD pad0; // 0x48484848
    DWORD sizeOfSid;
    DWORD pad1; // 0x48484848
    BYTE sid[12];
    DWORD pad2; // 0x48484848
    DWORD sizeOfUsername; // can be 0
    DWORD pad3; // 0x48484848
} UserInfoLocal;

typedef struct OptionalSettings {
    DWORD idleDurationSeconds;
    DWORD idleWaitTimeoutSeconds;
    DWORD executionTimeLimitSeconds;
    DWORD deleteExpiredTaskAfter;
    DWORD priority;
    DWORD restartOnFailureDelay;
    DWORD restartOnFailureRetries;
    GUID networkId;
    // Padding for networkId
    DWORD pad0;
} OptionalSettings;

typedef struct JobBucketLocal {
    DWORD flags;
    DWORD pad0; // 0x48484848
    DWORD crc32;
    DWORD pad1; // 0x48484848
    DWORD sizeOfAuthor; // 0xe
    DWORD pad2; // 0x48484848
    BYTE author[12]; // Author
    DWORD pad3;
    DWORD displayName;
    DWORD pad4; // 0x48484848
    UserInfoLocal userInfoLocal;
    DWORD sizeOfOptionalSettings;
    DWORD pad5;
    OptionalSettings optionalSettings;
} JobBucketLocal;

typedef struct TriggerLocal {
    Header header;
    JobBucketLocal jobBucketLocal;
    BYTE trigger[];
} TriggerLocal;



#endif // GHOSTTASK_HPP