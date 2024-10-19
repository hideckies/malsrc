#ifndef PROCESS_HERPADERPING_HPP
#define PROCESS_HERPADERPING_HPP

#include <Windows.h>
#include <winternl.h>

#define NtCurrentPeb() (NtCurrentTeb()->ProcessEnvironmentBlock)
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)

#define Add2Ptr(_P_, _X_) reinterpret_cast<void*>(reinterpret_cast<ULONGLONG>(_P_) + _X_)

#define GDI_HANDLE_BUFFER_SIZE32 34
#define GDI_HANDLE_BUFFER_SIZE64 60
#ifdef _WIN64
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE64
#else
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE32
#endif

#define PROCESS_CREATE_FLAGS_INHERIT_HANDLES 0x00000004

#define RTL_MAX_DRIVE_LETTERS 32

constexpr static SIZE_T PATTERN_LENGTH{ 0x200 };
constexpr static DWORD MAX_FILE_BUFFER{ 0x8000 };

typedef ULONG GDI_HANDLE_BUFFER[GDI_HANDLE_BUFFER_SIZE];

typedef struct _API_SET_NAMESPACE
{
    ULONG Version;
    ULONG Size;
    ULONG Flags;
    ULONG Count;
    ULONG EntryOffset;
    ULONG HashOffset;
    ULONG HashFactor;
} API_SET_NAMESPACE, * PAPI_SET_NAMESPACE;

typedef struct _RTL_BITMAP
{
    ULONG SizeOfBitMap;
    PULONG Buffer;
} RTL_BITMAP, * PRTL_BITMAP;

typedef enum _NT_PRODUCT_TYPE
{
    NtProductWinNt = 1,
    NtProductLanManNt,
    NtProductServer
} NT_PRODUCT_TYPE, * PNT_PRODUCT_TYPE;

typedef struct _KSYSTEM_TIME
{
    ULONG LowPart;
    LONG High1Time;
    LONG High2Time;
} KSYSTEM_TIME, * PKSYSTEM_TIME;

typedef struct _ACTIVATION_CONTEXT_DATA
{
    ULONG Magic;
    ULONG HeaderSize;
    ULONG FormatVersion;
    ULONG TotalSize;
    ULONG DefaultTocOffset; // to ACTIVATION_CONTEXT_DATA_TOC_HEADER
    ULONG ExtendedTocOffset; // to ACTIVATION_CONTEXT_DATA_EXTENDED_TOC_HEADER
    ULONG AssemblyRosterOffset; // to ACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_HEADER
    ULONG Flags; // ACTIVATION_CONTEXT_FLAG_*
} ACTIVATION_CONTEXT_DATA, * PACTIVATION_CONTEXT_DATA;

typedef struct _SILO_USER_SHARED_DATA
{
    ULONG ServiceSessionId;
    ULONG ActiveConsoleId;
    LONGLONG ConsoleSessionForegroundProcessId;
    NT_PRODUCT_TYPE NtProductType;
    ULONG SuiteMask;
    ULONG SharedUserSessionId; // since RS2
    BOOLEAN IsMultiSessionSku;
    BOOLEAN IsStateSeparationEnabled;
    WCHAR NtSystemRoot[260];
    USHORT UserModeGlobalLogger[16];
    ULONG TimeZoneId; // since 21H2
    LONG TimeZoneBiasStamp;
    KSYSTEM_TIME TimeZoneBias;
    LARGE_INTEGER TimeZoneBiasEffectiveStart;
    LARGE_INTEGER TimeZoneBiasEffectiveEnd;
} SILO_USER_SHARED_DATA, * PSILO_USER_SHARED_DATA;

typedef struct _ASSEMBLY_STORAGE_MAP_ENTRY
{
    ULONG Flags;
    UNICODE_STRING DosPath;
    HANDLE Handle;
} ASSEMBLY_STORAGE_MAP_ENTRY, * PASSEMBLY_STORAGE_MAP_ENTRY;

typedef struct _ASSEMBLY_STORAGE_MAP
{
    ULONG Flags;
    ULONG AssemblyCount;
    PASSEMBLY_STORAGE_MAP_ENTRY* AssemblyArray;
} ASSEMBLY_STORAGE_MAP, * PASSEMBLY_STORAGE_MAP;

typedef struct _TELEMETRY_COVERAGE_HEADER
{
    UCHAR MajorVersion;
    UCHAR MinorVersion;
    struct
    {
        USHORT TracingEnabled : 1;
        USHORT Reserved1 : 15;
    };
    ULONG HashTableEntries;
    ULONG HashIndexMask;
    ULONG TableUpdateVersion;
    ULONG TableSizeInBytes;
    ULONG LastResetTick;
    ULONG ResetRound;
    ULONG Reserved2;
    ULONG RecordedCount;
    ULONG Reserved3[4];
    ULONG HashTable[ANYSIZE_ARRAY];
} TELEMETRY_COVERAGE_HEADER, * PTELEMETRY_COVERAGE_HEADER;

typedef struct _LEAP_SECOND_DATA* PLEAP_SECOND_DATA;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
    USHORT Flags;
    USHORT Length;
    ULONG TimeStamp;
    STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

typedef struct _CURDIR
{
    UNICODE_STRING DosPath;
    HANDLE Handle;
} CURDIR, * PCURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS_T
{
    ULONG MaximumLength;
    ULONG Length;

    ULONG Flags;
    ULONG DebugFlags;

    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;

    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;

    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;

    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

    ULONG_PTR EnvironmentSize;
    ULONG_PTR EnvironmentVersion;

    PVOID PackageDependencyData;
    ULONG ProcessGroupId;
    ULONG LoaderThreads;
    UNICODE_STRING RedirectionDllName; // REDSTONE4
    UNICODE_STRING HeapPartitionName; // 19H1
    PULONGLONG DefaultThreadpoolCpuSetMasks;
    ULONG DefaultThreadpoolCpuSetMaskCount;
    ULONG DefaultThreadpoolThreadMaximum;
    ULONG HeapMemoryTypeMask; // WIN11
} RTL_USER_PROCESS_PARAMETERS_T, * PRTL_USER_PROCESS_PARAMETERS_T;

typedef struct _PEB_T
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union
    {
        BOOLEAN BitField;
        struct
        {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN IsPackagedProcess : 1;
            BOOLEAN IsAppContainer : 1;
            BOOLEAN IsProtectedProcessLight : 1;
            BOOLEAN IsLongPathAwareProcess : 1;
        };
    };

    HANDLE Mutant;

    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PRTL_CRITICAL_SECTION FastPebLock;
    PSLIST_HEADER AtlThunkSListPtr;
    PVOID IFEOKey;

    union
    {
        ULONG CrossProcessFlags;
        struct
        {
            ULONG ProcessInJob : 1;
            ULONG ProcessInitializing : 1;
            ULONG ProcessUsingVEH : 1;
            ULONG ProcessUsingVCH : 1;
            ULONG ProcessUsingFTH : 1;
            ULONG ProcessPreviouslyThrottled : 1;
            ULONG ProcessCurrentlyThrottled : 1;
            ULONG ProcessImagesHotPatched : 1; // REDSTONE5
            ULONG ReservedBits0 : 24;
        };
    };
    union
    {
        PVOID KernelCallbackTable;
        PVOID UserSharedInfoPtr;
    };

    ULONG SystemReserved;
    ULONG AtlThunkSListPtr32;
    PAPI_SET_NAMESPACE ApiSetMap;
    ULONG TlsExpansionCounter;
    PRTL_BITMAP TlsBitmap;
    ULONG TlsBitmapBits[2]; // TLS_MINIMUM_AVAILABLE

    PVOID ReadOnlySharedMemoryBase;
    PSILO_USER_SHARED_DATA SharedData; // HotpatchInformation
    PVOID* ReadOnlyStaticServerData;

    PVOID AnsiCodePageData; // PCPTABLEINFO
    PVOID OemCodePageData; // PCPTABLEINFO
    PVOID UnicodeCaseTableData; // PNLSTABLEINFO

    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;

    ULARGE_INTEGER CriticalSectionTimeout;
    SIZE_T HeapSegmentReserve;
    SIZE_T HeapSegmentCommit;
    SIZE_T HeapDeCommitTotalFreeThreshold;
    SIZE_T HeapDeCommitFreeBlockThreshold;

    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PVOID* ProcessHeaps; // PHEAP

    PVOID GdiSharedHandleTable; // PGDI_SHARED_MEMORY
    PVOID ProcessStarterHelper;
    ULONG GdiDCAttributeList;

    PRTL_CRITICAL_SECTION LoaderLock;

    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    KAFFINITY ActiveProcessAffinityMask;
    GDI_HANDLE_BUFFER GdiHandleBuffer;
    PVOID PostProcessInitRoutine;

    PRTL_BITMAP TlsExpansionBitmap;
    ULONG TlsExpansionBitmapBits[32]; // TLS_EXPANSION_SLOTS

    ULONG SessionId;

    ULARGE_INTEGER AppCompatFlags; // KACF_*
    ULARGE_INTEGER AppCompatFlagsUser;
    PVOID pShimData;
    PVOID AppCompatInfo; // APPCOMPAT_EXE_DATA

    UNICODE_STRING CSDVersion;

    PACTIVATION_CONTEXT_DATA ActivationContextData;
    PASSEMBLY_STORAGE_MAP ProcessAssemblyStorageMap;
    PACTIVATION_CONTEXT_DATA SystemDefaultActivationContextData;
    PASSEMBLY_STORAGE_MAP SystemAssemblyStorageMap;

    SIZE_T MinimumStackCommit;

    PVOID SparePointers[2]; // 19H1 (previously FlsCallback to FlsHighIndex)
    PVOID PatchLoaderData;
    PVOID ChpeV2ProcessInfo; // _CHPEV2_PROCESS_INFO

    ULONG AppModelFeatureState;
    ULONG SpareUlongs[2];

    USHORT ActiveCodePage;
    USHORT OemCodePage;
    USHORT UseCaseMapping;
    USHORT UnusedNlsField;

    PVOID WerRegistrationData;
    PVOID WerShipAssertPtr;

    union
    {
        PVOID pContextData; // WIN7
        PVOID pUnused; // WIN10
        PVOID EcCodeBitMap; // WIN11
    };

    PVOID pImageHeaderHash;
    union
    {
        ULONG TracingFlags;
        struct
        {
            ULONG HeapTracingEnabled : 1;
            ULONG CritSecTracingEnabled : 1;
            ULONG LibLoaderTracingEnabled : 1;
            ULONG SpareTracingBits : 29;
        };
    };
    ULONGLONG CsrServerReadOnlySharedMemoryBase;
    PRTL_CRITICAL_SECTION TppWorkerpListLock;
    LIST_ENTRY TppWorkerpList;
    PVOID WaitOnAddressHashTable[128];
    PTELEMETRY_COVERAGE_HEADER TelemetryCoverageHeader; // REDSTONE3
    ULONG CloudFileFlags;
    ULONG CloudFileDiagFlags; // REDSTONE4
    CHAR PlaceholderCompatibilityMode;
    CHAR PlaceholderCompatibilityModeReserved[7];
    PLEAP_SECOND_DATA LeapSecondData; // REDSTONE5
    union
    {
        ULONG LeapSecondFlags;
        struct
        {
            ULONG SixtySecondEnabled : 1;
            ULONG Reserved : 31;
        };
    };
    ULONG NtGlobalFlag2;
    ULONGLONG ExtendedFeatureDisableMask; // since WIN11
} PEB_T, * PPEB_T;

typedef struct _PS_ATTRIBUTE
{
    ULONG_PTR Attribute;
    SIZE_T Size;
    union
    {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

FORCEINLINE VOID RtlInitUnicodeString(
    _Out_ PUNICODE_STRING DestinationString,
    _In_opt_z_ PCWSTR SourceString
) {
    if (SourceString)
        DestinationString->MaximumLength = (DestinationString->Length = (USHORT)(wcslen(SourceString) * sizeof(WCHAR))) + sizeof(UNICODE_NULL);
    else
        DestinationString->MaximumLength = DestinationString->Length = 0;

    DestinationString->Buffer = (PWCH)SourceString;
}

typedef NTSTATUS(NTAPI* _NtCreateProcessEx) (PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ParentProcess, ULONG Flags, HANDLE SectionHandle, HANDLE DebugPort, HANDLE TokenHandle, ULONG Reserved);
typedef NTSTATUS(NTAPI* _NtCreateSection) (PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle);
typedef NTSTATUS(NTAPI* _NtCreateThreadEx) (PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PPS_ATTRIBUTE_LIST AttributeList);
typedef NTSTATUS(NTAPI* _NtQueryInformationProcess) (HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
typedef NTSTATUS(NTAPI* _RtlCreateProcessParametersEx) (PRTL_USER_PROCESS_PARAMETERS* pProcessParameters, PUNICODE_STRING ImagePathName, PUNICODE_STRING DllPath, PUNICODE_STRING CurrentDirectory, PUNICODE_STRING CommandLine, PVOID Environment, PUNICODE_STRING WindowTitle, PUNICODE_STRING DesktopInfo, PUNICODE_STRING ShellInfo, PUNICODE_STRING RuntimeData, ULONG Flags);

VOID FreeAll(HMODULE hNtdll, HANDLE hPayloadFile, HANDLE hTargetFile, HANDLE hSection, HANDLE hProcess, HANDLE hThread);
BOOL InitFunctions(HMODULE hNtdll);
BOOL CopyDataToFile(HANDLE hSrcFile, HANDLE hDestFile);
BOOL FillBufferWithPattern(std::vector<BYTE> &buffer, std::vector<BYTE> pattern);
BOOL OverwriteFileWithPattern(HANDLE hFile, std::vector<BYTE> pattern);
ULONGLONG GetImageEntryPointRVA(HANDLE hFile);
BOOL WriteRemoteProcessParameters(HANDLE hProcess, const std::wstring wImagePath);
BOOL ProcessHerpaderping();

#endif // PROCESS_HERPADERPING_HPP