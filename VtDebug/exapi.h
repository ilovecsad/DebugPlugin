#pragma once
#include <ntifs.h>

EXTERN_C{

typedef struct _SYSTEM_THREAD_INFO
{
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG ContextSwitches;
	ULONG ThreadState;
	KWAIT_REASON WaitReason;
}SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFO
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize;
	ULONG HardFaultCount;
	ULONG NumberOfThreadsHighWatermark;
	ULONGLONG CycleTime;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	ULONG BasePriority;
	HANDLE ProcessId;
	HANDLE InheritedFromProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey;
	ULONG_PTR PeakVirtualSize;
	ULONG_PTR VirtualSize;
	ULONG PageFaultCount;
	ULONG_PTR PeakWorkingSetSize;
	ULONG_PTR WorkingSetSize;
	ULONG_PTR QuotaPeakPagedPoolUsage;
	ULONG_PTR QuotaPagedPoolUsage;
	ULONG_PTR QuotaPeakNonPagedPoolUsage;
	ULONG_PTR QuotaNonPagedPoolUsage;
	ULONG_PTR PagefileUsage;
	ULONG_PTR PeakPagefileUsage;
	ULONG_PTR PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
	SYSTEM_THREAD_INFORMATION Threads[1];
}SYSTEM_PROCESS_INFO,* PSYSTEM_PROCESS_INFO;
//https://cloud.tencent.com/developer/article/1600862
NTKERNELAPI NTSTATUS
KeUserModeCallback(
	IN ULONG ApiNumber,
	IN PVOID InputBuffer,
	IN ULONG InputLength,
	OUT PVOID* OutputBuffer,
	IN PULONG OutputLength
);


NTKERNELAPI NTSTATUS
MmMarkPhysicalMemoryAsBad(
  IN  PPHYSICAL_ADDRESS StartAddress,
  IN OUT PLARGE_INTEGER NumberOfBytes
  );
NTKERNELAPI
NTSTATUS
NTAPI
MmCopyVirtualMemory(
	IN PEPROCESS FromProcess,
	IN PVOID FromAddress,
	IN PEPROCESS ToProcess,
	OUT PVOID ToAddress,
	IN SIZE_T BufferSize,
	IN KPROCESSOR_MODE PreviousMode,
	OUT PSIZE_T NumberOfBytesCopied
);

NTKERNELAPI PVOID NTAPI PsGetProcessPeb(
	_In_ PEPROCESS Process
);
NTKERNELAPI NTSTATUS MmCreateSection(OUT PVOID* SectionObject,
	IN ACCESS_MASK         DesiredAccess,
	IN POBJECT_ATTRIBUTES  ObjectAttributes   OPTIONAL,
	IN PLARGE_INTEGER      MaximumSize,
	IN ULONG                 SectionPageProtection,
	IN ULONG                 AllocationAttributes,
	IN HANDLE               FileHandle   OPTIONAL,
	IN PFILE_OBJECT          File   OPTIONAL);

NTKERNELAPI PVOID NTAPI ObGetObjectType(IN PVOID pObject);

NTKERNELAPI //声明要使用此函数
NTSTATUS //返回类型
PsSuspendProcess(PEPROCESS Process);


NTKERNELAPI //声明要使用此函数
NTSTATUS //返回类型
PsResumeProcess(PEPROCESS Process);
//////////////////////////////////////
NTKERNELAPI NTSTATUS PsGetContextThread(
	__in PETHREAD Thread,
	__inout PCONTEXT ThreadContext,
	__in KPROCESSOR_MODE Mode
);

NTKERNELAPI NTSTATUS PsSetContextThread(
	__in PETHREAD Thread,
	__inout PCONTEXT ThreadContext,
	__in KPROCESSOR_MODE Mode
);






typedef
_Function_class_(KNORMAL_ROUTINE)
_IRQL_requires_max_(PASSIVE_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_
VOID
KNORMAL_ROUTINE(
	_In_opt_ PVOID NormalContext,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2
);
typedef KNORMAL_ROUTINE* PKNORMAL_ROUTINE;

typedef
_Function_class_(KKERNEL_ROUTINE)
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_min_(APC_LEVEL)
_IRQL_requires_(APC_LEVEL)
_IRQL_requires_same_
VOID
KKERNEL_ROUTINE(
	_In_ struct _KAPC* Apc,
	_Inout_ PKNORMAL_ROUTINE* NormalRoutine,
	_Inout_ PVOID* NormalContext,
	_Inout_ PVOID* SystemArgument1,
	_Inout_ PVOID* SystemArgument2
);
typedef KKERNEL_ROUTINE* PKKERNEL_ROUTINE;


typedef
_Function_class_(KRUNDOWN_ROUTINE)
_IRQL_requires_max_(PASSIVE_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_
VOID
KRUNDOWN_ROUTINE(
	_In_ struct _KAPC* Apc
);
typedef KRUNDOWN_ROUTINE* PKRUNDOWN_ROUTINE;


typedef
_IRQL_requires_same_
_Function_class_(KENUM_ROUTINE)
VOID
KENUM_ROUTINE(
	_In_reads_(_Inexpressible_(Length)) PVOID Data,
	_In_ ULONG Length,
	_In_ PVOID Context
);

typedef KENUM_ROUTINE* PKENUM_ROUTINE;

typedef enum _KAPC_ENVIRONMENT {
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
} KAPC_ENVIRONMENT;


NTKERNELAPI
_IRQL_requires_same_
_When_(Environment != OriginalApcEnvironment, __drv_reportError("Caution: "
	"Using an APC environment other than the original environment can lead to "
	"a system bugcheck if the target thread is attached to a process with APCs "
	"disabled. APC environments should be used with care."))
	VOID
	KeInitializeApc(
		_Out_ PRKAPC Apc,
		_In_ PRKTHREAD Thread,
		_In_ KAPC_ENVIRONMENT Environment,
		_In_ PKKERNEL_ROUTINE KernelRoutine,
		_In_opt_ PKRUNDOWN_ROUTINE RundownRoutine,
		_In_opt_ PKNORMAL_ROUTINE NormalRoutine,
		_In_opt_ KPROCESSOR_MODE ProcessorMode,
		_In_opt_ PVOID NormalContext
	);

NTKERNELAPI
_Must_inspect_result_
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
BOOLEAN
KeInsertQueueApc(
	_Inout_ PRKAPC Apc,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2,
	_In_ KPRIORITY Increment
);


typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,              // obsolete...delete  
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,                //系统进程信息  
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,     //系统模块  
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemMirrorMemoryInformation,
	SystemPerformanceTraceInformation,
	SystemObsolete0,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemVerifierAddDriverInformation,
	SystemVerifierRemoveDriverInformation,
	SystemProcessorIdleInformation,
	SystemLegacyDriverInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation,
	SystemTimeSlipNotification,
	SystemSessionCreate,
	SystemSessionDetach,
	SystemSessionInformation,
	SystemRangeStartInformation,
	SystemVerifierInformation,
	SystemVerifierThunkExtend,
	SystemSessionProcessInformation,
	SystemLoadGdiDriverInSystemSpace,
	SystemNumaProcessorMap,
	SystemPrefetcherInformation,
	SystemExtendedProcessInformation,
	SystemRecommendedSharedDataAlignment,
	SystemComPlusPackage,
	SystemNumaAvailableMemory,
	SystemProcessorPowerInformation,
	SystemEmulationBasicInformation,
	SystemEmulationProcessorInformation,
	SystemExtendedHandleInformation,
	SystemLostDelayedWriteInformation,
	SystemBigPoolInformation,
	SystemSessionPoolTagInformation,
	SystemSessionMappedViewInformation,
	SystemHotpatchInformation,
	SystemObjectSecurityMode,
	SystemWatchdogTimerHandler,
	SystemWatchdogTimerInformation,
	SystemLogicalProcessorInformation,
	SystemWow64SharedInformation,
	SystemRegisterFirmwareTableInformationHandler,
	SystemFirmwareTableInformation,
	SystemModuleInformationEx,
	SystemVerifierTriageInformation,
	SystemSuperfetchInformation,
	SystemMemoryListInformation,
	SystemFileCacheInformationEx,
	MaxSystemInfoClass   // MaxSystemInfoClass should always be the last enum  
} SYSTEM_INFORMATION_CLASS;
NTKERNELAPI NTSTATUS NTAPI ZwQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	ULONG* ReturnLength);

NTKERNELAPI PVOID NTAPI PsGetThreadWin32Thread(PETHREAD pEthread);
NTKERNELAPI PVOID NTAPI PsGetProcessWow64Process(PEPROCESS pProcess);

NTKERNELAPI PVOID NTAPI PsGetThreadTeb(PETHREAD pEthread);
NTKERNELAPI
PVOID
NTAPI
PsGetCurrentProcessWow64Process();
NTKERNELAPI
BOOLEAN
NTAPI
KeTestAlertThread(IN KPROCESSOR_MODE AlertMode);
NTKERNELAPI  CHAR* NTAPI PsGetProcessImageFileName(
	__in PEPROCESS Process
);

NTKERNELAPI NTSTATUS NTAPI ObDuplicateObject(
	IN PEPROCESS SourceProcess,
	IN HANDLE SourceHandle,
	IN PEPROCESS TargetProcess OPTIONAL,
	OUT PHANDLE TargetHandle OPTIONAL,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG HandleAttributes,
	IN ULONG Options,
	IN KPROCESSOR_MODE PreviousMode
);

NTKERNELAPI NTSTATUS NTAPI  MmMapViewOfSection(
	IN PVOID SectionToMap,
	IN PEPROCESS Process,
	IN OUT PVOID* CapturedBase,
	IN ULONG_PTR ZeroBits,
	IN SIZE_T CommitSize,
	IN OUT PLARGE_INTEGER SectionOffset,
	IN OUT PSIZE_T CapturedViewSize,
	IN SECTION_INHERIT InheritDisposition,
	IN ULONG AllocationType,
	IN ULONG Protect
	);
NTKERNELAPI NTSTATUS NTAPI MmUnmapViewOfSection(IN PEPROCESS Process, IN PVOID BaseAddress);


NTKERNELAPI
NTSTATUS
ObReferenceObjectByName(
	IN PUNICODE_STRING ObjectName,
	IN ULONG Attributes,
	IN PACCESS_STATE PassedAccessState OPTIONAL,
	IN ACCESS_MASK DesiredAccess OPTIONAL,
	IN POBJECT_TYPE ObjectType,
	IN KPROCESSOR_MODE AccessMode,
	IN OUT PVOID ParseContext OPTIONAL,
	OUT PVOID* Object
	);



NTKERNELAPI NTSTATUS NTAPI ZwQueryInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation,
	ULONG ThreadInformationLength, PULONG ReturnLength);


}