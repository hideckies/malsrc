#ifndef HELPER_HPP
#define HELPER_HPP

#include <windows.h>

#define RTL_MAX_DRIVE_LETTERS           32

#define GDI_BATCH_BUFFER_SIZE           310
#define GDI_HANDLE_BUFFER_SIZE32        34
#define GDI_HANDLE_BUFFER_SIZE64        60

#define STATIC_UNICODE_BUFFER_LENGTH    261

#define WIN32_CLIENT_INFO_LENGTH        62

#if !defined(_M_X64)
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE32
#else
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE64
#endif

typedef _Return_type_success_(return >= 0) long NTSTATUS;

// Forward Declaration --------------------------------------------------------
struct _ACTIVATION_CONTEXT;
typedef _ACTIVATION_CONTEXT* PACTIVATION_CONTEXT;
// ----------------------------------------------------------------------------

typedef ULONG GDI_HANDLE_BUFFER[GDI_HANDLE_BUFFER_SIZE];
typedef LONG KPRIORITY, * PKPRIORITY;
typedef ULONGLONG REGHANDLE, * PREGHANDLE;
typedef struct _EVENT_DATA_DESCRIPTOR EVENT_DATA_DESCRIPTOR, * PEVENT_DATA_DESCRIPTOR;

typedef enum _NT_PRODUCT_TYPE {
    NtProductWinNt = 1,
    NtProductLanManNt,
    NtProductServer
} NT_PRODUCT_TYPE, * PNT_PRODUCT_TYPE;

typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation, // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
    ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
    ProcessIoCounters, // q: IO_COUNTERS
    ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
    ProcessTimes, // q: KERNEL_USER_TIMES
    ProcessBasePriority, // s: KPRIORITY
    ProcessRaisePriority, // s: ULONG
    ProcessDebugPort, // q: HANDLE
    ProcessExceptionPort, // s: PROCESS_EXCEPTION_PORT (requires SeTcbPrivilege)
    ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
    ProcessLdtInformation, // qs: PROCESS_LDT_INFORMATION // 10
    ProcessLdtSize, // s: PROCESS_LDT_SIZE
    ProcessDefaultHardErrorMode, // qs: ULONG
    ProcessIoPortHandlers, // (kernel-mode only) // s: PROCESS_IO_PORT_HANDLER_INFORMATION
    ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
    ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
    ProcessUserModeIOPL, // qs: ULONG (requires SeTcbPrivilege)
    ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
    ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
    ProcessWx86Information, // qs: ULONG (requires SeTcbPrivilege) (VdmAllowed)
    ProcessHandleCount, // q: ULONG, PROCESS_HANDLE_INFORMATION // 20
    ProcessAffinityMask, // (q >WIN7)s: KAFFINITY, qs: GROUP_AFFINITY
    ProcessPriorityBoost, // qs: ULONG
    ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
    ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
    ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
    ProcessWow64Information, // q: ULONG_PTR
    ProcessImageFileName, // q: UNICODE_STRING
    ProcessLUIDDeviceMapsEnabled, // q: ULONG
    ProcessBreakOnTermination, // qs: ULONG
    ProcessDebugObjectHandle, // q: HANDLE // 30
    ProcessDebugFlags, // qs: ULONG
    ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: PROCESS_HANDLE_TRACING_ENABLE[_EX] or void to disable
    ProcessIoPriority, // qs: IO_PRIORITY_HINT
    ProcessExecuteFlags, // qs: ULONG (MEM_EXECUTE_OPTION_*)
    ProcessTlsInformation, // PROCESS_TLS_INFORMATION // ProcessResourceManagement
    ProcessCookie, // q: ULONG
    ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
    ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
    ProcessPagePriority, // qs: PAGE_PRIORITY_INFORMATION
    ProcessInstrumentationCallback, // s: PVOID or PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION // 40
    ProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
    ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]; s: void
    ProcessImageFileNameWin32, // q: UNICODE_STRING
    ProcessImageFileMapping, // q: HANDLE (input)
    ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
    ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
    ProcessGroupInformation, // q: USHORT[]
    ProcessTokenVirtualizationEnabled, // s: ULONG
    ProcessConsoleHostProcess, // qs: ULONG_PTR // ProcessOwnerInformation
    ProcessWindowInformation, // q: PROCESS_WINDOW_INFORMATION // 50
    ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
    ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
    ProcessDynamicFunctionTableInformation, // s: PROCESS_DYNAMIC_FUNCTION_TABLE_INFORMATION
    ProcessHandleCheckingMode, // qs: ULONG; s: 0 disables, otherwise enables
    ProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
    ProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
    ProcessWorkingSetControl, // s: PROCESS_WORKING_SET_CONTROL (requires SeDebugPrivilege)
    ProcessHandleTable, // q: ULONG[] // since WINBLUE
    ProcessCheckStackExtentsMode, // qs: ULONG // KPROCESS->CheckStackExtents (CFG)
    ProcessCommandLineInformation, // q: UNICODE_STRING // 60
    ProcessProtectionInformation, // q: PS_PROTECTION
    ProcessMemoryExhaustion, // s: PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
    ProcessFaultInformation, // s: PROCESS_FAULT_INFORMATION
    ProcessTelemetryIdInformation, // q: PROCESS_TELEMETRY_ID_INFORMATION
    ProcessCommitReleaseInformation, // qs: PROCESS_COMMIT_RELEASE_INFORMATION
    ProcessDefaultCpuSetsInformation, // qs: SYSTEM_CPU_SET_INFORMATION[5]
    ProcessAllowedCpuSetsInformation, // qs: SYSTEM_CPU_SET_INFORMATION[5]
    ProcessSubsystemProcess,
    ProcessJobMemoryInformation, // q: PROCESS_JOB_MEMORY_INFO
    ProcessInPrivate, // q: BOOLEAN; s: void // ETW // since THRESHOLD2 // 70
    ProcessRaiseUMExceptionOnInvalidHandleClose, // qs: ULONG; s: 0 disables, otherwise enables
    ProcessIumChallengeResponse,
    ProcessChildProcessInformation, // q: PROCESS_CHILD_PROCESS_INFORMATION
    ProcessHighGraphicsPriorityInformation, // qs: BOOLEAN (requires SeTcbPrivilege)
    ProcessSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
    ProcessEnergyValues, // q: PROCESS_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES
    ProcessPowerThrottlingState, // qs: POWER_THROTTLING_PROCESS_STATE
    ProcessReserved3Information, // ProcessActivityThrottlePolicy // PROCESS_ACTIVITY_THROTTLE_POLICY
    ProcessWin32kSyscallFilterInformation, // q: WIN32K_SYSCALL_FILTER
    ProcessDisableSystemAllowedCpuSets, // s: BOOLEAN // 80
    ProcessWakeInformation, // q: PROCESS_WAKE_INFORMATION
    ProcessEnergyTrackingState, // qs: PROCESS_ENERGY_TRACKING_STATE
    ProcessManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
    ProcessCaptureTrustletLiveDump,
    ProcessTelemetryCoverage, // q: TELEMETRY_COVERAGE_HEADER; s: TELEMETRY_COVERAGE_POINT
    ProcessEnclaveInformation,
    ProcessEnableReadWriteVmLogging, // qs: PROCESS_READWRITEVM_LOGGING_INFORMATION
    ProcessUptimeInformation, // q: PROCESS_UPTIME_INFORMATION
    ProcessImageSection, // q: HANDLE
    ProcessDebugAuthInformation, // since REDSTONE4 // 90
    ProcessSystemResourceManagement, // s: PROCESS_SYSTEM_RESOURCE_MANAGEMENT
    ProcessSequenceNumber, // q: ULONGLONG
    ProcessLoaderDetour, // since REDSTONE5
    ProcessSecurityDomainInformation, // q: PROCESS_SECURITY_DOMAIN_INFORMATION
    ProcessCombineSecurityDomainsInformation, // s: PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION
    ProcessEnableLogging, // qs: PROCESS_LOGGING_INFORMATION
    ProcessLeapSecondInformation, // qs: PROCESS_LEAP_SECOND_INFORMATION
    ProcessFiberShadowStackAllocation, // s: PROCESS_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION // since 19H1
    ProcessFreeFiberShadowStackAllocation, // s: PROCESS_FREE_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION
    ProcessAltSystemCallInformation, // s: PROCESS_SYSCALL_PROVIDER_INFORMATION // since 20H1 // 100
    ProcessDynamicEHContinuationTargets, // s: PROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION
    ProcessDynamicEnforcedCetCompatibleRanges, // s: PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE_INFORMATION // since 20H2
    ProcessCreateStateChange, // since WIN11
    ProcessApplyStateChange,
    ProcessEnableOptionalXStateFeatures, // s: ULONG64 // optional XState feature bitmask
    ProcessAltPrefetchParam, // since 22H1
    ProcessAssignCpuPartitions,
    ProcessPriorityClassEx, // s: PROCESS_PRIORITY_CLASS_EX
    ProcessMembershipInformation, // q: PROCESS_MEMBERSHIP_INFORMATION
    ProcessEffectiveIoPriority, // q: IO_PRIORITY_HINT
    ProcessEffectivePagePriority, // q: ULONG
    MaxProcessInfoClass
} PROCESSINFOCLASS;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation, // q: SYSTEM_BASIC_INFORMATION
    SystemProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
    SystemPerformanceInformation, // q: SYSTEM_PERFORMANCE_INFORMATION
    SystemTimeOfDayInformation, // q: SYSTEM_TIMEOFDAY_INFORMATION
    SystemPathInformation, // not implemented
    SystemProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
    SystemCallCountInformation, // q: SYSTEM_CALL_COUNT_INFORMATION
    SystemDeviceInformation, // q: SYSTEM_DEVICE_INFORMATION
    SystemProcessorPerformanceInformation, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemFlagsInformation, // q: SYSTEM_FLAGS_INFORMATION
    SystemCallTimeInformation, // not implemented // SYSTEM_CALL_TIME_INFORMATION // 10
    SystemModuleInformation, // q: RTL_PROCESS_MODULES
    SystemLocksInformation, // q: RTL_PROCESS_LOCKS
    SystemStackTraceInformation, // q: RTL_PROCESS_BACKTRACES
    SystemPagedPoolInformation, // not implemented
    SystemNonPagedPoolInformation, // not implemented
    SystemHandleInformation, // q: SYSTEM_HANDLE_INFORMATION
    SystemObjectInformation, // q: SYSTEM_OBJECTTYPE_INFORMATION mixed with SYSTEM_OBJECT_INFORMATION
    SystemPageFileInformation, // q: SYSTEM_PAGEFILE_INFORMATION
    SystemVdmInstemulInformation, // q: SYSTEM_VDM_INSTEMUL_INFO
    SystemVdmBopInformation, // not implemented // 20
    SystemFileCacheInformation, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemCache)
    SystemPoolTagInformation, // q: SYSTEM_POOLTAG_INFORMATION
    SystemInterruptInformation, // q: SYSTEM_INTERRUPT_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemDpcBehaviorInformation, // q: SYSTEM_DPC_BEHAVIOR_INFORMATION; s: SYSTEM_DPC_BEHAVIOR_INFORMATION (requires SeLoadDriverPrivilege)
    SystemFullMemoryInformation, // not implemented // SYSTEM_MEMORY_USAGE_INFORMATION
    SystemLoadGdiDriverInformation, // s (kernel-mode only)
    SystemUnloadGdiDriverInformation, // s (kernel-mode only)
    SystemTimeAdjustmentInformation, // q: SYSTEM_QUERY_TIME_ADJUST_INFORMATION; s: SYSTEM_SET_TIME_ADJUST_INFORMATION (requires SeSystemtimePrivilege)
    SystemSummaryMemoryInformation, // not implemented // SYSTEM_MEMORY_USAGE_INFORMATION
    SystemMirrorMemoryInformation, // s (requires license value "Kernel-MemoryMirroringSupported") (requires SeShutdownPrivilege) // 30
    SystemPerformanceTraceInformation, // q; s: (type depends on EVENT_TRACE_INFORMATION_CLASS)
    SystemObsolete0, // not implemented
    SystemExceptionInformation, // q: SYSTEM_EXCEPTION_INFORMATION
    SystemCrashDumpStateInformation, // s: SYSTEM_CRASH_DUMP_STATE_INFORMATION (requires SeDebugPrivilege)
    SystemKernelDebuggerInformation, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION
    SystemContextSwitchInformation, // q: SYSTEM_CONTEXT_SWITCH_INFORMATION
    SystemRegistryQuotaInformation, // q: SYSTEM_REGISTRY_QUOTA_INFORMATION; s (requires SeIncreaseQuotaPrivilege)
    SystemExtendServiceTableInformation, // s (requires SeLoadDriverPrivilege) // loads win32k only
    SystemPrioritySeperation, // s (requires SeTcbPrivilege)
    SystemVerifierAddDriverInformation, // s (requires SeDebugPrivilege) // 40
    SystemVerifierRemoveDriverInformation, // s (requires SeDebugPrivilege)
    SystemProcessorIdleInformation, // q: SYSTEM_PROCESSOR_IDLE_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemLegacyDriverInformation, // q: SYSTEM_LEGACY_DRIVER_INFORMATION
    SystemCurrentTimeZoneInformation, // q; s: RTL_TIME_ZONE_INFORMATION
    SystemLookasideInformation, // q: SYSTEM_LOOKASIDE_INFORMATION
    SystemTimeSlipNotification, // s: HANDLE (NtCreateEvent) (requires SeSystemtimePrivilege)
    SystemSessionCreate, // not implemented
    SystemSessionDetach, // not implemented
    SystemSessionInformation, // not implemented (SYSTEM_SESSION_INFORMATION)
    SystemRangeStartInformation, // q: SYSTEM_RANGE_START_INFORMATION // 50
    SystemVerifierInformation, // q: SYSTEM_VERIFIER_INFORMATION; s (requires SeDebugPrivilege)
    SystemVerifierThunkExtend, // s (kernel-mode only)
    SystemSessionProcessInformation, // q: SYSTEM_SESSION_PROCESS_INFORMATION
    SystemLoadGdiDriverInSystemSpace, // s: SYSTEM_GDI_DRIVER_INFORMATION (kernel-mode only) (same as SystemLoadGdiDriverInformation)
    SystemNumaProcessorMap, // q: SYSTEM_NUMA_INFORMATION
    SystemPrefetcherInformation, // q; s: PREFETCHER_INFORMATION // PfSnQueryPrefetcherInformation
    SystemExtendedProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
    SystemRecommendedSharedDataAlignment, // q: ULONG // KeGetRecommendedSharedDataAlignment
    SystemComPlusPackage, // q; s: ULONG
    SystemNumaAvailableMemory, // q: SYSTEM_NUMA_INFORMATION // 60
    SystemProcessorPowerInformation, // q: SYSTEM_PROCESSOR_POWER_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemEmulationBasicInformation, // q: SYSTEM_BASIC_INFORMATION
    SystemEmulationProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
    SystemExtendedHandleInformation, // q: SYSTEM_HANDLE_INFORMATION_EX
    SystemLostDelayedWriteInformation, // q: ULONG
    SystemBigPoolInformation, // q: SYSTEM_BIGPOOL_INFORMATION
    SystemSessionPoolTagInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION
    SystemSessionMappedViewInformation, // q: SYSTEM_SESSION_MAPPED_VIEW_INFORMATION
    SystemHotpatchInformation, // q; s: SYSTEM_HOTPATCH_CODE_INFORMATION
    SystemObjectSecurityMode, // q: ULONG // 70
    SystemWatchdogTimerHandler, // s: SYSTEM_WATCHDOG_HANDLER_INFORMATION // (kernel-mode only)
    SystemWatchdogTimerInformation, // q: SYSTEM_WATCHDOG_TIMER_INFORMATION // (kernel-mode only)
    SystemLogicalProcessorInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemWow64SharedInformationObsolete, // not implemented
    SystemRegisterFirmwareTableInformationHandler, // s: SYSTEM_FIRMWARE_TABLE_HANDLER // (kernel-mode only)
    SystemFirmwareTableInformation, // SYSTEM_FIRMWARE_TABLE_INFORMATION
    SystemModuleInformationEx, // q: RTL_PROCESS_MODULE_INFORMATION_EX
    SystemVerifierTriageInformation, // not implemented
    SystemSuperfetchInformation, // q; s: SUPERFETCH_INFORMATION // PfQuerySuperfetchInformation
    SystemMemoryListInformation, // q: SYSTEM_MEMORY_LIST_INFORMATION; s: SYSTEM_MEMORY_LIST_COMMAND (requires SeProfileSingleProcessPrivilege) // 80
    SystemFileCacheInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (same as SystemFileCacheInformation)
    SystemThreadPriorityClientIdInformation, // s: SYSTEM_THREAD_CID_PRIORITY_INFORMATION (requires SeIncreaseBasePriorityPrivilege)
    SystemProcessorIdleCycleTimeInformation, // q: SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION[] (EX in: USHORT ProcessorGroup)
    SystemVerifierCancellationInformation, // SYSTEM_VERIFIER_CANCELLATION_INFORMATION // name:wow64:whNT32QuerySystemVerifierCancellationInformation
    SystemProcessorPowerInformationEx, // not implemented
    SystemRefTraceInformation, // q; s: SYSTEM_REF_TRACE_INFORMATION // ObQueryRefTraceInformation
    SystemSpecialPoolInformation, // q; s: SYSTEM_SPECIAL_POOL_INFORMATION (requires SeDebugPrivilege) // MmSpecialPoolTag, then MmSpecialPoolCatchOverruns != 0
    SystemProcessIdInformation, // q: SYSTEM_PROCESS_ID_INFORMATION
    SystemErrorPortInformation, // s (requires SeTcbPrivilege)
    SystemBootEnvironmentInformation, // q: SYSTEM_BOOT_ENVIRONMENT_INFORMATION // 90
    SystemHypervisorInformation, // q: SYSTEM_HYPERVISOR_QUERY_INFORMATION
    SystemVerifierInformationEx, // q; s: SYSTEM_VERIFIER_INFORMATION_EX
    SystemTimeZoneInformation, // q; s: RTL_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege)
    SystemImageFileExecutionOptionsInformation, // s: SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION (requires SeTcbPrivilege)
    SystemCoverageInformation, // q: COVERAGE_MODULES s: COVERAGE_MODULE_REQUEST // ExpCovQueryInformation (requires SeDebugPrivilege)
    SystemPrefetchPatchInformation, // SYSTEM_PREFETCH_PATCH_INFORMATION
    SystemVerifierFaultsInformation, // s: SYSTEM_VERIFIER_FAULTS_INFORMATION (requires SeDebugPrivilege)
    SystemSystemPartitionInformation, // q: SYSTEM_SYSTEM_PARTITION_INFORMATION
    SystemSystemDiskInformation, // q: SYSTEM_SYSTEM_DISK_INFORMATION
    SystemProcessorPerformanceDistribution, // q: SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION (EX in: USHORT ProcessorGroup) // 100
    SystemNumaProximityNodeInformation, // q; s: SYSTEM_NUMA_PROXIMITY_MAP
    SystemDynamicTimeZoneInformation, // q; s: RTL_DYNAMIC_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege)
    SystemCodeIntegrityInformation, // q: SYSTEM_CODEINTEGRITY_INFORMATION // SeCodeIntegrityQueryInformation
    SystemProcessorMicrocodeUpdateInformation, // s: SYSTEM_PROCESSOR_MICROCODE_UPDATE_INFORMATION
    SystemProcessorBrandString, // q: CHAR[] // HaliQuerySystemInformation -> HalpGetProcessorBrandString, info class 23
    SystemVirtualAddressInformation, // q: SYSTEM_VA_LIST_INFORMATION[]; s: SYSTEM_VA_LIST_INFORMATION[] (requires SeIncreaseQuotaPrivilege) // MmQuerySystemVaInformation
    SystemLogicalProcessorAndGroupInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX (EX in: LOGICAL_PROCESSOR_RELATIONSHIP RelationshipType) // since WIN7 // KeQueryLogicalProcessorRelationship
    SystemProcessorCycleTimeInformation, // q: SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION[] (EX in: USHORT ProcessorGroup)
    SystemStoreInformation, // q; s: SYSTEM_STORE_INFORMATION (requires SeProfileSingleProcessPrivilege) // SmQueryStoreInformation
    SystemRegistryAppendString, // s: SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS // 110
    SystemAitSamplingValue, // s: ULONG (requires SeProfileSingleProcessPrivilege)
    SystemVhdBootInformation, // q: SYSTEM_VHD_BOOT_INFORMATION
    SystemCpuQuotaInformation, // q; s: PS_CPU_QUOTA_QUERY_INFORMATION
    SystemNativeBasicInformation, // q: SYSTEM_BASIC_INFORMATION
    SystemErrorPortTimeouts, // SYSTEM_ERROR_PORT_TIMEOUTS
    SystemLowPriorityIoInformation, // q: SYSTEM_LOW_PRIORITY_IO_INFORMATION
    SystemTpmBootEntropyInformation, // q: TPM_BOOT_ENTROPY_NT_RESULT // ExQueryTpmBootEntropyInformation
    SystemVerifierCountersInformation, // q: SYSTEM_VERIFIER_COUNTERS_INFORMATION
    SystemPagedPoolInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypePagedPool)
    SystemSystemPtesInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemPtes) // 120
    SystemNodeDistanceInformation, // q: USHORT[4*NumaNodes] // (EX in: USHORT NodeNumber)
    SystemAcpiAuditInformation, // q: SYSTEM_ACPI_AUDIT_INFORMATION // HaliQuerySystemInformation -> HalpAuditQueryResults, info class 26
    SystemBasicPerformanceInformation, // q: SYSTEM_BASIC_PERFORMANCE_INFORMATION // name:wow64:whNtQuerySystemInformation_SystemBasicPerformanceInformation
    SystemQueryPerformanceCounterInformation, // q: SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION // since WIN7 SP1
    SystemSessionBigPoolInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION // since WIN8
    SystemBootGraphicsInformation, // q; s: SYSTEM_BOOT_GRAPHICS_INFORMATION (kernel-mode only)
    SystemScrubPhysicalMemoryInformation, // q; s: MEMORY_SCRUB_INFORMATION
    SystemBadPageInformation,
    SystemProcessorProfileControlArea, // q; s: SYSTEM_PROCESSOR_PROFILE_CONTROL_AREA
    SystemCombinePhysicalMemoryInformation, // s: MEMORY_COMBINE_INFORMATION, MEMORY_COMBINE_INFORMATION_EX, MEMORY_COMBINE_INFORMATION_EX2 // 130
    SystemEntropyInterruptTimingInformation, // q; s: SYSTEM_ENTROPY_TIMING_INFORMATION
    SystemConsoleInformation, // q; s: SYSTEM_CONSOLE_INFORMATION
    SystemPlatformBinaryInformation, // q: SYSTEM_PLATFORM_BINARY_INFORMATION (requires SeTcbPrivilege)
    SystemPolicyInformation, // q: SYSTEM_POLICY_INFORMATION (Warbird/Encrypt/Decrypt/Execute)
    SystemHypervisorProcessorCountInformation, // q: SYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION
    SystemDeviceDataInformation, // q: SYSTEM_DEVICE_DATA_INFORMATION
    SystemDeviceDataEnumerationInformation, // q: SYSTEM_DEVICE_DATA_INFORMATION
    SystemMemoryTopologyInformation, // q: SYSTEM_MEMORY_TOPOLOGY_INFORMATION
    SystemMemoryChannelInformation, // q: SYSTEM_MEMORY_CHANNEL_INFORMATION
    SystemBootLogoInformation, // q: SYSTEM_BOOT_LOGO_INFORMATION // 140
    SystemProcessorPerformanceInformationEx, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX // (EX in: USHORT ProcessorGroup) // since WINBLUE
    SystemCriticalProcessErrorLogInformation,
    SystemSecureBootPolicyInformation, // q: SYSTEM_SECUREBOOT_POLICY_INFORMATION
    SystemPageFileInformationEx, // q: SYSTEM_PAGEFILE_INFORMATION_EX
    SystemSecureBootInformation, // q: SYSTEM_SECUREBOOT_INFORMATION
    SystemEntropyInterruptTimingRawInformation,
    SystemPortableWorkspaceEfiLauncherInformation, // q: SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION
    SystemFullProcessInformation, // q: SYSTEM_PROCESS_INFORMATION with SYSTEM_PROCESS_INFORMATION_EXTENSION (requires admin)
    SystemKernelDebuggerInformationEx, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
    SystemBootMetadataInformation, // 150
    SystemSoftRebootInformation, // q: ULONG
    SystemElamCertificateInformation, // s: SYSTEM_ELAM_CERTIFICATE_INFORMATION
    SystemOfflineDumpConfigInformation, // q: OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2
    SystemProcessorFeaturesInformation, // q: SYSTEM_PROCESSOR_FEATURES_INFORMATION
    SystemRegistryReconciliationInformation, // s: NULL (requires admin) (flushes registry hives)
    SystemEdidInformation, // q: SYSTEM_EDID_INFORMATION
    SystemManufacturingInformation, // q: SYSTEM_MANUFACTURING_INFORMATION // since THRESHOLD
    SystemEnergyEstimationConfigInformation, // q: SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION
    SystemHypervisorDetailInformation, // q: SYSTEM_HYPERVISOR_DETAIL_INFORMATION
    SystemProcessorCycleStatsInformation, // q: SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION (EX in: USHORT ProcessorGroup) // 160
    SystemVmGenerationCountInformation,
    SystemTrustedPlatformModuleInformation, // q: SYSTEM_TPM_INFORMATION
    SystemKernelDebuggerFlags, // SYSTEM_KERNEL_DEBUGGER_FLAGS
    SystemCodeIntegrityPolicyInformation, // q; s: SYSTEM_CODEINTEGRITYPOLICY_INFORMATION
    SystemIsolatedUserModeInformation, // q: SYSTEM_ISOLATED_USER_MODE_INFORMATION
    SystemHardwareSecurityTestInterfaceResultsInformation,
    SystemSingleModuleInformation, // q: SYSTEM_SINGLE_MODULE_INFORMATION
    SystemAllowedCpuSetsInformation, // s: SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION
    SystemVsmProtectionInformation, // q: SYSTEM_VSM_PROTECTION_INFORMATION (previously SystemDmaProtectionInformation)
    SystemInterruptCpuSetsInformation, // q: SYSTEM_INTERRUPT_CPU_SET_INFORMATION // 170
    SystemSecureBootPolicyFullInformation, // q: SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION
    SystemCodeIntegrityPolicyFullInformation,
    SystemAffinitizedInterruptProcessorInformation, // (requires SeIncreaseBasePriorityPrivilege)
    SystemRootSiloInformation, // q: SYSTEM_ROOT_SILO_INFORMATION
    SystemCpuSetInformation, // q: SYSTEM_CPU_SET_INFORMATION // since THRESHOLD2
    SystemCpuSetTagInformation, // q: SYSTEM_CPU_SET_TAG_INFORMATION
    SystemWin32WerStartCallout,
    SystemSecureKernelProfileInformation, // q: SYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION
    SystemCodeIntegrityPlatformManifestInformation, // q: SYSTEM_SECUREBOOT_PLATFORM_MANIFEST_INFORMATION // since REDSTONE
    SystemInterruptSteeringInformation, // q: in: SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT, out: SYSTEM_INTERRUPT_STEERING_INFORMATION_OUTPUT // NtQuerySystemInformationEx // 180
    SystemSupportedProcessorArchitectures, // p: in opt: HANDLE, out: SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION[] // NtQuerySystemInformationEx
    SystemMemoryUsageInformation, // q: SYSTEM_MEMORY_USAGE_INFORMATION
    SystemCodeIntegrityCertificateInformation, // q: SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION
    SystemPhysicalMemoryInformation, // q: SYSTEM_PHYSICAL_MEMORY_INFORMATION // since REDSTONE2
    SystemControlFlowTransition, // (Warbird/Encrypt/Decrypt/Execute)
    SystemKernelDebuggingAllowed, // s: ULONG
    SystemActivityModerationExeState, // SYSTEM_ACTIVITY_MODERATION_EXE_STATE
    SystemActivityModerationUserSettings, // SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS
    SystemCodeIntegrityPoliciesFullInformation,
    SystemCodeIntegrityUnlockInformation, // SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION // 190
    SystemIntegrityQuotaInformation,
    SystemFlushInformation, // q: SYSTEM_FLUSH_INFORMATION
    SystemProcessorIdleMaskInformation, // q: ULONG_PTR[ActiveGroupCount] // since REDSTONE3
    SystemSecureDumpEncryptionInformation,
    SystemWriteConstraintInformation, // SYSTEM_WRITE_CONSTRAINT_INFORMATION
    SystemKernelVaShadowInformation, // SYSTEM_KERNEL_VA_SHADOW_INFORMATION
    SystemHypervisorSharedPageInformation, // SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION // since REDSTONE4
    SystemFirmwareBootPerformanceInformation,
    SystemCodeIntegrityVerificationInformation, // SYSTEM_CODEINTEGRITYVERIFICATION_INFORMATION
    SystemFirmwarePartitionInformation, // SYSTEM_FIRMWARE_PARTITION_INFORMATION // 200
    SystemSpeculationControlInformation, // SYSTEM_SPECULATION_CONTROL_INFORMATION // (CVE-2017-5715) REDSTONE3 and above.
    SystemDmaGuardPolicyInformation, // SYSTEM_DMA_GUARD_POLICY_INFORMATION
    SystemEnclaveLaunchControlInformation, // SYSTEM_ENCLAVE_LAUNCH_CONTROL_INFORMATION
    SystemWorkloadAllowedCpuSetsInformation, // SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION // since REDSTONE5
    SystemCodeIntegrityUnlockModeInformation, // SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION
    SystemLeapSecondInformation, // SYSTEM_LEAP_SECOND_INFORMATION
    SystemFlags2Information, // q: SYSTEM_FLAGS_INFORMATION
    SystemSecurityModelInformation, // SYSTEM_SECURITY_MODEL_INFORMATION // since 19H1
    SystemCodeIntegritySyntheticCacheInformation,
    SystemFeatureConfigurationInformation, // SYSTEM_FEATURE_CONFIGURATION_INFORMATION // since 20H1 // 210
    SystemFeatureConfigurationSectionInformation, // SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION
    SystemFeatureUsageSubscriptionInformation, // SYSTEM_FEATURE_USAGE_SUBSCRIPTION_DETAILS
    SystemSecureSpeculationControlInformation, // SECURE_SPECULATION_CONTROL_INFORMATION
    SystemSpacesBootInformation, // since 20H2
    SystemFwRamdiskInformation, // SYSTEM_FIRMWARE_RAMDISK_INFORMATION
    SystemWheaIpmiHardwareInformation,
    SystemDifSetRuleClassInformation, // SYSTEM_DIF_VOLATILE_INFORMATION
    SystemDifClearRuleClassInformation,
    SystemDifApplyPluginVerificationOnDriver, // SYSTEM_DIF_PLUGIN_DRIVER_INFORMATION
    SystemDifRemovePluginVerificationOnDriver, // SYSTEM_DIF_PLUGIN_DRIVER_INFORMATION // 220
    SystemShadowStackInformation, // SYSTEM_SHADOW_STACK_INFORMATION
    SystemBuildVersionInformation, // q: in: ULONG (LayerNumber), out: SYSTEM_BUILD_VERSION_INFORMATION // NtQuerySystemInformationEx // 222
    SystemPoolLimitInformation, // SYSTEM_POOL_LIMIT_INFORMATION (requires SeIncreaseQuotaPrivilege)
    SystemCodeIntegrityAddDynamicStore,
    SystemCodeIntegrityClearDynamicStores,
    SystemDifPoolTrackingInformation,
    SystemPoolZeroingInformation, // q: SYSTEM_POOL_ZEROING_INFORMATION
    SystemDpcWatchdogInformation, // q; s: SYSTEM_DPC_WATCHDOG_CONFIGURATION_INFORMATION
    SystemDpcWatchdogInformation2, // q; s: SYSTEM_DPC_WATCHDOG_CONFIGURATION_INFORMATION_V2
    SystemSupportedProcessorArchitectures2, // q: in opt: HANDLE, out: SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION[] // NtQuerySystemInformationEx // 230
    SystemSingleProcessorRelationshipInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX // (EX in: PROCESSOR_NUMBER Processor)
    SystemXfgCheckFailureInformation, // q: SYSTEM_XFG_FAILURE_INFORMATION
    SystemIommuStateInformation, // SYSTEM_IOMMU_STATE_INFORMATION // since 22H1
    SystemHypervisorMinrootInformation, // SYSTEM_HYPERVISOR_MINROOT_INFORMATION
    SystemHypervisorBootPagesInformation, // SYSTEM_HYPERVISOR_BOOT_PAGES_INFORMATION
    SystemPointerAuthInformation, // SYSTEM_POINTER_AUTH_INFORMATION
    SystemSecureKernelDebuggerInformation,
    SystemOriginalImageFeatureInformation, // q: in: SYSTEM_ORIGINAL_IMAGE_FEATURE_INFORMATION_INPUT, out: SYSTEM_ORIGINAL_IMAGE_FEATURE_INFORMATION_OUTPUT // NtQuerySystemInformationEx
    MaxSystemInfoClass
} SYSTEM_INFORMATION_CLASS;

typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation, // q: MEMORY_BASIC_INFORMATION
    MemoryWorkingSetInformation, // q: MEMORY_WORKING_SET_INFORMATION
    MemoryMappedFilenameInformation, // q: UNICODE_STRING
    MemoryRegionInformation, // q: MEMORY_REGION_INFORMATION
    MemoryWorkingSetExInformation, // q: MEMORY_WORKING_SET_EX_INFORMATION // since VISTA
    MemorySharedCommitInformation, // q: MEMORY_SHARED_COMMIT_INFORMATION // since WIN8
    MemoryImageInformation, // q: MEMORY_IMAGE_INFORMATION
    MemoryRegionInformationEx, // MEMORY_REGION_INFORMATION
    MemoryPrivilegedBasicInformation, // MEMORY_BASIC_INFORMATION
    MemoryEnclaveImageInformation, // MEMORY_ENCLAVE_IMAGE_INFORMATION // since REDSTONE3
    MemoryBasicInformationCapped, // 10
    MemoryPhysicalContiguityInformation, // MEMORY_PHYSICAL_CONTIGUITY_INFORMATION // since 20H1
    MemoryBadInformation, // since WIN11
    MemoryBadInformationAllProcesses, // since 22H1
    MaxMemoryInfoClass
} MEMORY_INFORMATION_CLASS;

typedef enum _FILE_INFORMATION_CLASS {
    FileDirectoryInformation = 1, // q: FILE_DIRECTORY_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
    FileFullDirectoryInformation, // q: FILE_FULL_DIR_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
    FileBothDirectoryInformation, // q: FILE_BOTH_DIR_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
    FileBasicInformation, // q; s: FILE_BASIC_INFORMATION (q: requires FILE_READ_ATTRIBUTES; s: requires FILE_WRITE_ATTRIBUTES)
    FileStandardInformation, // q: FILE_STANDARD_INFORMATION, FILE_STANDARD_INFORMATION_EX
    FileInternalInformation, // q: FILE_INTERNAL_INFORMATION
    FileEaInformation, // q: FILE_EA_INFORMATION
    FileAccessInformation, // q: FILE_ACCESS_INFORMATION
    FileNameInformation, // q: FILE_NAME_INFORMATION
    FileRenameInformation, // s: FILE_RENAME_INFORMATION (requires DELETE) // 10
    FileLinkInformation, // s: FILE_LINK_INFORMATION
    FileNamesInformation, // q: FILE_NAMES_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
    FileDispositionInformation, // s: FILE_DISPOSITION_INFORMATION (requires DELETE)
    FilePositionInformation, // q; s: FILE_POSITION_INFORMATION
    FileFullEaInformation, // FILE_FULL_EA_INFORMATION
    FileModeInformation, // q; s: FILE_MODE_INFORMATION
    FileAlignmentInformation, // q: FILE_ALIGNMENT_INFORMATION
    FileAllInformation, // q: FILE_ALL_INFORMATION (requires FILE_READ_ATTRIBUTES)
    FileAllocationInformation, // s: FILE_ALLOCATION_INFORMATION (requires FILE_WRITE_DATA)
    FileEndOfFileInformation, // s: FILE_END_OF_FILE_INFORMATION (requires FILE_WRITE_DATA) // 20
    FileAlternateNameInformation, // q: FILE_NAME_INFORMATION
    FileStreamInformation, // q: FILE_STREAM_INFORMATION
    FilePipeInformation, // q; s: FILE_PIPE_INFORMATION (q: requires FILE_READ_ATTRIBUTES; s: requires FILE_WRITE_ATTRIBUTES)
    FilePipeLocalInformation, // q: FILE_PIPE_LOCAL_INFORMATION (requires FILE_READ_ATTRIBUTES)
    FilePipeRemoteInformation, // q; s: FILE_PIPE_REMOTE_INFORMATION (q: requires FILE_READ_ATTRIBUTES; s: requires FILE_WRITE_ATTRIBUTES)
    FileMailslotQueryInformation, // q: FILE_MAILSLOT_QUERY_INFORMATION
    FileMailslotSetInformation, // s: FILE_MAILSLOT_SET_INFORMATION
    FileCompressionInformation, // q: FILE_COMPRESSION_INFORMATION
    FileObjectIdInformation, // q: FILE_OBJECTID_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
    FileCompletionInformation, // s: FILE_COMPLETION_INFORMATION // 30
    FileMoveClusterInformation, // s: FILE_MOVE_CLUSTER_INFORMATION (requires FILE_WRITE_DATA)
    FileQuotaInformation, // q: FILE_QUOTA_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
    FileReparsePointInformation, // q: FILE_REPARSE_POINT_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
    FileNetworkOpenInformation, // q: FILE_NETWORK_OPEN_INFORMATION (requires FILE_READ_ATTRIBUTES)
    FileAttributeTagInformation, // q: FILE_ATTRIBUTE_TAG_INFORMATION (requires FILE_READ_ATTRIBUTES)
    FileTrackingInformation, // s: FILE_TRACKING_INFORMATION (requires FILE_WRITE_DATA)
    FileIdBothDirectoryInformation, // q: FILE_ID_BOTH_DIR_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
    FileIdFullDirectoryInformation, // q: FILE_ID_FULL_DIR_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex])
    FileValidDataLengthInformation, // s: FILE_VALID_DATA_LENGTH_INFORMATION (requires FILE_WRITE_DATA and/or SeManageVolumePrivilege)
    FileShortNameInformation, // s: FILE_NAME_INFORMATION (requires DELETE) // 40
    FileIoCompletionNotificationInformation, // q; s: FILE_IO_COMPLETION_NOTIFICATION_INFORMATION (q: requires FILE_READ_ATTRIBUTES) // since VISTA
    FileIoStatusBlockRangeInformation, // s: FILE_IOSTATUSBLOCK_RANGE_INFORMATION (requires SeLockMemoryPrivilege)
    FileIoPriorityHintInformation, // q; s: FILE_IO_PRIORITY_HINT_INFORMATION, FILE_IO_PRIORITY_HINT_INFORMATION_EX (q: requires FILE_READ_DATA)
    FileSfioReserveInformation, // q; s: FILE_SFIO_RESERVE_INFORMATION (q: requires FILE_READ_DATA)
    FileSfioVolumeInformation, // q: FILE_SFIO_VOLUME_INFORMATION (requires FILE_READ_ATTRIBUTES)
    FileHardLinkInformation, // q: FILE_LINKS_INFORMATION
    FileProcessIdsUsingFileInformation, // q: FILE_PROCESS_IDS_USING_FILE_INFORMATION (requires FILE_READ_ATTRIBUTES)
    FileNormalizedNameInformation, // q: FILE_NAME_INFORMATION
    FileNetworkPhysicalNameInformation, // q: FILE_NETWORK_PHYSICAL_NAME_INFORMATION
    FileIdGlobalTxDirectoryInformation, // q: FILE_ID_GLOBAL_TX_DIR_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex]) // since WIN7 // 50
    FileIsRemoteDeviceInformation, // q: FILE_IS_REMOTE_DEVICE_INFORMATION (requires FILE_READ_ATTRIBUTES)
    FileUnusedInformation,
    FileNumaNodeInformation, // q: FILE_NUMA_NODE_INFORMATION
    FileStandardLinkInformation, // q: FILE_STANDARD_LINK_INFORMATION
    FileRemoteProtocolInformation, // q: FILE_REMOTE_PROTOCOL_INFORMATION
    FileRenameInformationBypassAccessCheck, // (kernel-mode only); s: FILE_RENAME_INFORMATION // since WIN8
    FileLinkInformationBypassAccessCheck, // (kernel-mode only); s: FILE_LINK_INFORMATION
    FileVolumeNameInformation, // q: FILE_VOLUME_NAME_INFORMATION
    FileIdInformation, // q: FILE_ID_INFORMATION
    FileIdExtdDirectoryInformation, // q: FILE_ID_EXTD_DIR_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex]) // 60
    FileReplaceCompletionInformation, // s: FILE_COMPLETION_INFORMATION // since WINBLUE
    FileHardLinkFullIdInformation, // q: FILE_LINK_ENTRY_FULL_ID_INFORMATION // FILE_LINKS_FULL_ID_INFORMATION
    FileIdExtdBothDirectoryInformation, // q: FILE_ID_EXTD_BOTH_DIR_INFORMATION (requires FILE_LIST_DIRECTORY) (NtQueryDirectoryFile[Ex]) // since THRESHOLD
    FileDispositionInformationEx, // s: FILE_DISPOSITION_INFO_EX (requires DELETE) // since REDSTONE
    FileRenameInformationEx, // s: FILE_RENAME_INFORMATION_EX
    FileRenameInformationExBypassAccessCheck, // (kernel-mode only); s: FILE_RENAME_INFORMATION_EX
    FileDesiredStorageClassInformation, // q; s: FILE_DESIRED_STORAGE_CLASS_INFORMATION (q: requires FILE_READ_ATTRIBUTES; s: requires FILE_WRITE_ATTRIBUTES) // since REDSTONE2
    FileStatInformation, // q: FILE_STAT_INFORMATION (requires FILE_READ_ATTRIBUTES)
    FileMemoryPartitionInformation, // s: FILE_MEMORY_PARTITION_INFORMATION // since REDSTONE3
    FileStatLxInformation, // q: FILE_STAT_LX_INFORMATION (requires FILE_READ_ATTRIBUTES and FILE_READ_EA) // since REDSTONE4 // 70
    FileCaseSensitiveInformation, // q; s: FILE_CASE_SENSITIVE_INFORMATION (q: requires FILE_READ_ATTRIBUTES; s: requires FILE_WRITE_ATTRIBUTES)
    FileLinkInformationEx, // s: FILE_LINK_INFORMATION_EX // since REDSTONE5
    FileLinkInformationExBypassAccessCheck, // (kernel-mode only); s: FILE_LINK_INFORMATION_EX
    FileStorageReserveIdInformation, // q; s: FILE_STORAGE_RESERVE_ID_INFORMATION (q: requires FILE_READ_ATTRIBUTES; s: requires FILE_WRITE_ATTRIBUTES)
    FileCaseSensitiveInformationForceAccessCheck, // q; s: FILE_CASE_SENSITIVE_INFORMATION
    FileKnownFolderInformation, // q; s: FILE_KNOWN_FOLDER_INFORMATION (q: requires FILE_READ_ATTRIBUTES; s: requires FILE_WRITE_ATTRIBUTES) // since WIN11
    FileStatBasicInformation, // since 23H2
    FileId64ExtdDirectoryInformation,
    FileId64ExtdBothDirectoryInformation,
    FileIdAllExtdDirectoryInformation,
    FileIdAllExtdBothDirectoryInformation,
    FileMaximumInformation
} FILE_INFORMATION_CLASS, * PFILE_INFORMATION_CLASS;

typedef enum _LDR_HOT_PATCH_STATE {
    LdrHotPatchBaseImage,
    LdrHotPatchNotApplied,
    LdrHotPatchAppliedReverse,
    LdrHotPatchAppliedForward,
    LdrHotPatchFailedToPatch,
    LdrHotPatchStateMax,
} LDR_HOT_PATCH_STATE, * PLDR_HOT_PATCH_STATE;

typedef enum _LDR_DLL_LOAD_REASON {
    LoadReasonStaticDependency,
    LoadReasonStaticForwarderDependency,
    LoadReasonDynamicForwarderDependency,
    LoadReasonDelayloadDependency,
    LoadReasonDynamicLoad,
    LoadReasonAsImageLoad,
    LoadReasonAsDataLoad,
    LoadReasonEnclavePrimary, // since REDSTONE3
    LoadReasonEnclaveDependency,
    LoadReasonPatchImage, // since WIN11
    LoadReasonUnknown = -1
} LDR_DLL_LOAD_REASON, * PLDR_DLL_LOAD_REASON;

typedef enum _LDR_DDAG_STATE {
    LdrModulesMerged = -5,
    LdrModulesInitError = -4,
    LdrModulesSnapError = -3,
    LdrModulesUnloaded = -2,
    LdrModulesUnloading = -1,
    LdrModulesPlaceHolder = 0,
    LdrModulesMapping = 1,
    LdrModulesMapped = 2,
    LdrModulesWaitingForDependencies = 3,
    LdrModulesSnapping = 4,
    LdrModulesSnapped = 5,
    LdrModulesCondensed = 6,
    LdrModulesReadyToInit = 7,
    LdrModulesInitializing = 8,
    LdrModulesReadyToRun = 9
} LDR_DDAG_STATE;

typedef struct _EVENT_DESCRIPTOR {
    USHORT Id;
    UCHAR Version;
    UCHAR Channel;
    UCHAR Level;
    UCHAR Opcode;
    USHORT Task;
    ULONGLONG Keyword;
} EVENT_DESCRIPTOR, * PEVENT_DESCRIPTOR;

typedef const EVENT_DESCRIPTOR* PCEVENT_DESCRIPTOR;

typedef struct _ACTIVATION_CONTEXT_DATA {
    ULONG Magic;
    ULONG HeaderSize;
    ULONG FormatVersion;
    ULONG TotalSize;
    ULONG DefaultTocOffset; // to ACTIVATION_CONTEXT_DATA_TOC_HEADER
    ULONG ExtendedTocOffset; // to ACTIVATION_CONTEXT_DATA_EXTENDED_TOC_HEADER
    ULONG AssemblyRosterOffset; // to ACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_HEADER
    ULONG Flags; // ACTIVATION_CONTEXT_FLAG_*
} ACTIVATION_CONTEXT_DATA, * PACTIVATION_CONTEXT_DATA;

typedef struct _KSYSTEM_TIME {
    ULONG LowPart;
    LONG High1Time;
    LONG High2Time;
} KSYSTEM_TIME, * PKSYSTEM_TIME;

typedef struct _STRING {
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_opt_(MaximumLength, Length) PCHAR Buffer;
} STRING, * PSTRING, ANSI_STRING, * PANSI_STRING, OEM_STRING, * POEM_STRING;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct {
    WORD	offset : 12;
    WORD	type : 4;
} IMAGE_RELOC, * PIMAGE_RELOC;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor; // PSECURITY_DESCRIPTOR;
    PVOID SecurityQualityOfService; // PSECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _ASSEMBLY_STORAGE_MAP_ENTRY {
    ULONG Flags;
    UNICODE_STRING DosPath;
    HANDLE Handle;
} ASSEMBLY_STORAGE_MAP_ENTRY, * PASSEMBLY_STORAGE_MAP_ENTRY;

typedef struct _ASSEMBLY_STORAGE_MAP {
    ULONG Flags;
    ULONG AssemblyCount;
    PASSEMBLY_STORAGE_MAP_ENTRY* AssemblyArray;
} ASSEMBLY_STORAGE_MAP, * PASSEMBLY_STORAGE_MAP;

typedef struct _LEAP_SECOND_DATA* PLEAP_SECOND_DATA;

typedef struct _TELEMETRY_COVERAGE_HEADER {
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

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _IO_STATUS_BLOCK {
    union
    {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef VOID(NTAPI* PIO_APC_ROUTINE)(
    _In_ PVOID ApcContext,
    _In_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG Reserved
);

typedef struct _CURDIR {
    UNICODE_STRING DosPath;
    HANDLE Handle;
} CURDIR, * PCURDIR;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
    USHORT Flags;
    USHORT Length;
    ULONG TimeStamp;
    STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
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
    ULONG_PTR DefaultThreadpoolCpuSetMasks;
    ULONG DefaultThreadpoolCpuSetMaskCount;
    ULONG DefaultThreadpoolThreadMaximum;
    ULONG HeapMemoryTypeMask; // WIN11
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _RTL_BALANCED_NODE {
    union
    {
        struct _RTL_BALANCED_NODE* Children[2];
        struct
        {
            struct _RTL_BALANCED_NODE* Left;
            struct _RTL_BALANCED_NODE* Right;
        };
    };
    union
    {
        UCHAR Red : 1;
        UCHAR Balance : 2;
        ULONG_PTR ParentValue;
    };
} RTL_BALANCED_NODE, * PRTL_BALANCED_NODE;

typedef struct _API_SET_NAMESPACE {
    ULONG Version;
    ULONG Size;
    ULONG Flags;
    ULONG Count;
    ULONG EntryOffset;
    ULONG HashOffset;
    ULONG HashFactor;
} API_SET_NAMESPACE, * PAPI_SET_NAMESPACE;

typedef struct _RTL_BITMAP {
    ULONG SizeOfBitMap;
    PULONG Buffer;
} RTL_BITMAP, * PRTL_BITMAP;

typedef struct _SILO_USER_SHARED_DATA {
    ULONG ServiceSessionId;
    ULONG ActiveConsoleId;
    LONGLONG ConsoleSessionForegroundProcessId;
    NT_PRODUCT_TYPE NtProductType;
    ULONG SuiteMask;
    ULONG SharedUserSessionId; // since RS2
    BOOLEAN IsMultiSessionSku;
    WCHAR NtSystemRoot[260];
    USHORT UserModeGlobalLogger[16];
    ULONG TimeZoneId; // since 21H2
    LONG TimeZoneBiasStamp;
    KSYSTEM_TIME TimeZoneBias;
    LARGE_INTEGER TimeZoneBiasEffectiveStart;
    LARGE_INTEGER TimeZoneBiasEffectiveEnd;
} SILO_USER_SHARED_DATA, * PSILO_USER_SHARED_DATA;

typedef BOOLEAN(NTAPI* PLDR_INIT_ROUTINE)(
    _In_ PVOID DllHandle,
    _In_ ULONG Reason,
    _In_opt_ PVOID Context
);

typedef struct _LDRP_LOAD_CONTEXT* PLDRP_LOAD_CONTEXT;

typedef struct _LDR_SERVICE_TAG_RECORD {
    struct _LDR_SERVICE_TAG_RECORD* Next;
    ULONG ServiceTag;
} LDR_SERVICE_TAG_RECORD, * PLDR_SERVICE_TAG_RECORD;

typedef struct _LDRP_CSLIST {
    PSINGLE_LIST_ENTRY Tail;
} LDRP_CSLIST, * PLDRP_CSLIST;

typedef struct _LDR_DDAG_NODE {
    LIST_ENTRY Modules;
    PLDR_SERVICE_TAG_RECORD ServiceTagList;
    ULONG LoadCount;
    ULONG LoadWhileUnloadingCount;
    ULONG LowestLink;
    union
    {
        LDRP_CSLIST Dependencies;
        SINGLE_LIST_ENTRY RemovalLink;
    };
    LDRP_CSLIST IncomingDependencies;
    LDR_DDAG_STATE State;
    SINGLE_LIST_ENTRY CondenseLink;
    ULONG PreorderNumber;
} LDR_DDAG_NODE, * PLDR_DDAG_NODE;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PLDR_INIT_ROUTINE EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    union
    {
        UCHAR FlagGroup[4];
        ULONG Flags;
        struct
        {
            ULONG PackagedBinary : 1;
            ULONG MarkedForRemoval : 1;
            ULONG ImageDll : 1;
            ULONG LoadNotificationsSent : 1;
            ULONG TelemetryEntryProcessed : 1;
            ULONG ProcessStaticImport : 1;
            ULONG InLegacyLists : 1;
            ULONG InIndexes : 1;
            ULONG ShimDll : 1;
            ULONG InExceptionTable : 1;
            ULONG ReservedFlags1 : 2;
            ULONG LoadInProgress : 1;
            ULONG LoadConfigProcessed : 1;
            ULONG EntryProcessed : 1;
            ULONG ProtectDelayLoad : 1;
            ULONG ReservedFlags3 : 2;
            ULONG DontCallForThreads : 1;
            ULONG ProcessAttachCalled : 1;
            ULONG ProcessAttachFailed : 1;
            ULONG CorDeferredValidate : 1;
            ULONG CorImage : 1;
            ULONG DontRelocate : 1;
            ULONG CorILOnly : 1;
            ULONG ChpeImage : 1;
            ULONG ChpeEmulatorImage : 1;
            ULONG ReservedFlags5 : 1;
            ULONG Redirected : 1;
            ULONG ReservedFlags6 : 2;
            ULONG CompatDatabaseProcessed : 1;
        };
    };
    USHORT ObsoleteLoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    ULONG TimeDateStamp;
    PACTIVATION_CONTEXT EntryPointActivationContext;
    PVOID Lock; // RtlAcquireSRWLockExclusive
    PLDR_DDAG_NODE DdagNode;
    LIST_ENTRY NodeModuleLink;
    PLDRP_LOAD_CONTEXT LoadContext;
    PVOID ParentDllBase;
    PVOID SwitchBackContext;
    RTL_BALANCED_NODE BaseAddressIndexNode;
    RTL_BALANCED_NODE MappingInfoIndexNode;
    ULONG_PTR OriginalBase;
    LARGE_INTEGER LoadTime;
    ULONG BaseNameHashValue;
    LDR_DLL_LOAD_REASON LoadReason; // since WIN8
    ULONG ImplicitPathOptions;
    ULONG ReferenceCount; // since WIN10
    ULONG DependentLoadFlags;
    UCHAR SigningLevel; // since REDSTONE2
    ULONG CheckSum; // since 22H1
    PVOID ActivePatchImageBase;
    LDR_HOT_PATCH_STATE HotPatchState;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
    BOOLEAN ShutdownInProgress;
    HANDLE ShutdownThreadId;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
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
} PEB, * PPEB;

typedef struct _GDI_TEB_BATCH
{
    ULONG Offset;
    ULONG_PTR HDC;
    ULONG Buffer[GDI_BATCH_BUFFER_SIZE];
} GDI_TEB_BATCH, * PGDI_TEB_BATCH;

typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME
{
    struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME* Previous;
    PACTIVATION_CONTEXT ActivationContext;
    ULONG Flags; // RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_*
} RTL_ACTIVATION_CONTEXT_STACK_FRAME, * PRTL_ACTIVATION_CONTEXT_STACK_FRAME;

typedef struct _ACTIVATION_CONTEXT_STACK {
    PRTL_ACTIVATION_CONTEXT_STACK_FRAME ActiveFrame;
    LIST_ENTRY FrameListCache;
    ULONG Flags; // ACTIVATION_CONTEXT_STACK_FLAG_*
    ULONG NextCookieSequenceNumber;
    ULONG StackId;
} ACTIVATION_CONTEXT_STACK, * PACTIVATION_CONTEXT_STACK;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT {
    ULONG Flags;
    PSTR FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, * PTEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME {
    ULONG Flags;
    struct _TEB_ACTIVE_FRAME* Previous;
    PTEB_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, * PTEB_ACTIVE_FRAME;

typedef struct _TEB {
    NT_TIB NtTib;

    PVOID EnvironmentPointer;
    CLIENT_ID ClientId;
    PVOID ActiveRpcHandle;
    PVOID ThreadLocalStoragePointer;
    PPEB ProcessEnvironmentBlock;

    ULONG LastErrorValue;
    ULONG CountOfOwnedCriticalSections;
    PVOID CsrClientThread;
    PVOID Win32ThreadInfo;
    ULONG User32Reserved[26];
    ULONG UserReserved[5];
    PVOID WOW32Reserved;
    LCID CurrentLocale;
    ULONG FpSoftwareStatusRegister;
    PVOID ReservedForDebuggerInstrumentation[16];
#ifdef _WIN64
    PVOID SystemReserved1[30];
#else
    PVOID SystemReserved1[26];
#endif

    CHAR PlaceholderCompatibilityMode;
    BOOLEAN PlaceholderHydrationAlwaysExplicit;
    CHAR PlaceholderReserved[10];

    ULONG ProxiedProcessId;
    ACTIVATION_CONTEXT_STACK ActivationStack;

    UCHAR WorkingOnBehalfTicket[8];
    NTSTATUS ExceptionCode;

    PACTIVATION_CONTEXT_STACK ActivationContextStackPointer;
    ULONG_PTR InstrumentationCallbackSp;
    ULONG_PTR InstrumentationCallbackPreviousPc;
    ULONG_PTR InstrumentationCallbackPreviousSp;
#ifdef _WIN64
    ULONG TxFsContext;
#endif

    BOOLEAN InstrumentationCallbackDisabled;
#ifdef _WIN64
    BOOLEAN UnalignedLoadStoreExceptions;
#endif
#ifndef _WIN64
    UCHAR SpareBytes[23];
    ULONG TxFsContext;
#endif
    GDI_TEB_BATCH GdiTebBatch;
    CLIENT_ID RealClientId;
    HANDLE GdiCachedProcessHandle;
    ULONG GdiClientPID;
    ULONG GdiClientTID;
    PVOID GdiThreadLocalInfo;
    ULONG_PTR Win32ClientInfo[WIN32_CLIENT_INFO_LENGTH];

    PVOID glDispatchTable[233];
    ULONG_PTR glReserved1[29];
    PVOID glReserved2;
    PVOID glSectionInfo;
    PVOID glSection;
    PVOID glTable;
    PVOID glCurrentRC;
    PVOID glContext;

    NTSTATUS LastStatusValue;
    UNICODE_STRING StaticUnicodeString;
    WCHAR StaticUnicodeBuffer[STATIC_UNICODE_BUFFER_LENGTH];

    PVOID DeallocationStack;
    PVOID TlsSlots[TLS_MINIMUM_AVAILABLE];
    LIST_ENTRY TlsLinks;

    PVOID Vdm;
    PVOID ReservedForNtRpc;
    PVOID DbgSsReserved[2];

    ULONG HardErrorMode;
#ifdef _WIN64
    PVOID Instrumentation[11];
#else
    PVOID Instrumentation[9];
#endif
    GUID ActivityId;

    PVOID SubProcessTag;
    PVOID PerflibData;
    PVOID EtwTraceData;
    PVOID WinSockData;
    ULONG GdiBatchCount;

    union
    {
        PROCESSOR_NUMBER CurrentIdealProcessor;
        ULONG IdealProcessorValue;
        struct
        {
            UCHAR ReservedPad0;
            UCHAR ReservedPad1;
            UCHAR ReservedPad2;
            UCHAR IdealProcessor;
        };
    };

    ULONG GuaranteedStackBytes;
    PVOID ReservedForPerf;
    PVOID ReservedForOle; // tagSOleTlsData
    ULONG WaitingOnLoaderLock;
    PVOID SavedPriorityState;
    ULONG_PTR ReservedForCodeCoverage;
    PVOID ThreadPoolData;
    PVOID* TlsExpansionSlots;
#ifdef _WIN64
    PVOID DeallocationBStore;
    PVOID BStoreLimit;
#endif
    ULONG MuiGeneration;
    ULONG IsImpersonating;
    PVOID NlsCache;
    PVOID pShimData;
    ULONG HeapData;
    HANDLE CurrentTransactionHandle;
    PTEB_ACTIVE_FRAME ActiveFrame;
    PVOID FlsData;

    PVOID PreferredLanguages;
    PVOID UserPrefLanguages;
    PVOID MergedPrefLanguages;
    ULONG MuiImpersonation;

    union
    {
        USHORT CrossTebFlags;
        USHORT SpareCrossTebBits : 16;
    };
    union
    {
        USHORT SameTebFlags;
        struct
        {
            USHORT SafeThunkCall : 1;
            USHORT InDebugPrint : 1;
            USHORT HasFiberData : 1;
            USHORT SkipThreadAttach : 1;
            USHORT WerInShipAssertCode : 1;
            USHORT RanProcessInit : 1;
            USHORT ClonedThread : 1;
            USHORT SuppressDebugMsg : 1;
            USHORT DisableUserStackWalk : 1;
            USHORT RtlExceptionAttached : 1;
            USHORT InitialThread : 1;
            USHORT SessionAware : 1;
            USHORT LoadOwner : 1;
            USHORT LoaderWorker : 1;
            USHORT SkipLoaderInit : 1;
            USHORT SkipFileAPIBrokering : 1;
        };
    };

    PVOID TxnScopeEnterCallback;
    PVOID TxnScopeExitCallback;
    PVOID TxnScopeContext;
    ULONG LockCount;
    LONG WowTebOffset;
    PVOID ResourceRetValue;
    PVOID ReservedForWdf;
    ULONGLONG ReservedForCrt;
    GUID EffectiveContainerId;
    ULONGLONG LastSleepCounter; // Win11
    ULONG SpinCallCount;
    ULONGLONG ExtendedFeatureDisableMask;
} TEB, * PTEB;

#endif // HELPER_HPP