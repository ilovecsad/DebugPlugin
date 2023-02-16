#pragma once
#include <Windows.h>
#include <winternl.h>
#include <list>
#include <vector>
#include <TlHelp32.h>
#include <string>


#define STATUS_UNSUCCESSFUL              ((NTSTATUS)0xC0000001L)
#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L) 
#pragma pack(8)

typedef struct _RTL_BALANCED_NODE {
	union {
		struct _RTL_BALANCED_NODE* Children[2];
		struct {
			struct _RTL_BALANCED_NODE* Left;
			struct _RTL_BALANCED_NODE* Right;
		} DUMMYSTRUCTNAME;
	} DUMMYUNIONNAME;

#define RTL_BALANCED_NODE_RESERVED_PARENT_MASK 3

	union {
		UCHAR Red : 1;
		UCHAR Balance : 2;
		ULONG_PTR ParentValue;
	} DUMMYUNIONNAME2;
} RTL_BALANCED_NODE, * PRTL_BALANCED_NODE;



typedef enum _LDR_DLL_LOAD_REASON  // 10 elements, 0x4 bytes
{
	LoadReasonStaticDependency = 0 /*0x0*/,
	LoadReasonStaticForwarderDependency = 1 /*0x1*/,
	LoadReasonDynamicForwarderDependency = 2 /*0x2*/,
	LoadReasonDelayloadDependency = 3 /*0x3*/,
	LoadReasonDynamicLoad = 4 /*0x4*/,
	LoadReasonAsImageLoad = 5 /*0x5*/,
	LoadReasonAsDataLoad = 6 /*0x6*/,
	LoadReasonEnclavePrimary = 7 /*0x7*/,
	LoadReasonEnclaveDependency = 8 /*0x8*/,
	LoadReasonUnknown = -1 /*0xFF*/
}LDR_DLL_LOAD_REASON, * PLDR_DLL_LOAD_REASON;

typedef struct _LDR_DATA_TABLE_ENTRY64                         // 59 elements, 0x120 bytes (sizeof) 
{
	/*0x000*/     struct _LIST_ENTRY InLoadOrderLinks;                     // 2 elements, 0x10 bytes (sizeof)   
	/*0x010*/     struct _LIST_ENTRY InMemoryOrderLinks;                   // 2 elements, 0x10 bytes (sizeof)   
	/*0x020*/     struct _LIST_ENTRY InInitializationOrderLinks;           // 2 elements, 0x10 bytes (sizeof)   
	/*0x030*/     VOID* DllBase;
	/*0x038*/     VOID* EntryPoint;
	/*0x040*/     ULONG32      SizeOfImage;
	/*0x044*/     UINT8        _PADDING0_[0x4];
	/*0x048*/     struct _UNICODE_STRING FullDllName;                      // 3 elements, 0x10 bytes (sizeof)   
	/*0x058*/     struct _UNICODE_STRING BaseDllName;                      // 3 elements, 0x10 bytes (sizeof)   
	union                                                    // 3 elements, 0x4 bytes (sizeof)    
	{
		/*0x068*/         UINT8        FlagGroup[4];
		struct                                               // 28 elements, 0x4 bytes (sizeof)   
		{
			/*0x068*/             ULONG32      PackagedBinary : 1;                 // 0 BitPosition                     
			/*0x068*/             ULONG32      MarkedForRemoval : 1;               // 1 BitPosition                     
			/*0x068*/             ULONG32      ImageDll : 1;                       // 2 BitPosition                     
			/*0x068*/             ULONG32      LoadNotificationsSent : 1;          // 3 BitPosition                     
			/*0x068*/             ULONG32      TelemetryEntryProcessed : 1;        // 4 BitPosition                     
			/*0x068*/             ULONG32      ProcessStaticImport : 1;            // 5 BitPosition                     
			/*0x068*/             ULONG32      InLegacyLists : 1;                  // 6 BitPosition                     
			/*0x068*/             ULONG32      InIndexes : 1;                      // 7 BitPosition                     
			/*0x068*/             ULONG32      ShimDll : 1;                        // 8 BitPosition                     
			/*0x068*/             ULONG32      InExceptionTable : 1;               // 9 BitPosition                     
			/*0x068*/             ULONG32      ReservedFlags1 : 2;                 // 10 BitPosition                    
			/*0x068*/             ULONG32      LoadInProgress : 1;                 // 12 BitPosition                    
			/*0x068*/             ULONG32      LoadConfigProcessed : 1;            // 13 BitPosition                    
			/*0x068*/             ULONG32      EntryProcessed : 1;                 // 14 BitPosition                    
			/*0x068*/             ULONG32      ProtectDelayLoad : 1;               // 15 BitPosition                    
			/*0x068*/             ULONG32      ReservedFlags3 : 2;                 // 16 BitPosition                    
			/*0x068*/             ULONG32      DontCallForThreads : 1;             // 18 BitPosition                    
			/*0x068*/             ULONG32      ProcessAttachCalled : 1;            // 19 BitPosition                    
			/*0x068*/             ULONG32      ProcessAttachFailed : 1;            // 20 BitPosition                    
			/*0x068*/             ULONG32      CorDeferredValidate : 1;            // 21 BitPosition                    
			/*0x068*/             ULONG32      CorImage : 1;                       // 22 BitPosition                    
			/*0x068*/             ULONG32      DontRelocate : 1;                   // 23 BitPosition                    
			/*0x068*/             ULONG32      CorILOnly : 1;                      // 24 BitPosition                    
			/*0x068*/             ULONG32      ChpeImage : 1;                      // 25 BitPosition                    
			/*0x068*/             ULONG32      ReservedFlags5 : 2;                 // 26 BitPosition                    
			/*0x068*/             ULONG32      Redirected : 1;                     // 28 BitPosition                    
			/*0x068*/             ULONG32      ReservedFlags6 : 2;                 // 29 BitPosition                    
			/*0x068*/             ULONG32      CompatDatabaseProcessed : 1;        // 31 BitPosition                    
		}Flags;
	}u;
	/*0x06C*/     UINT16       ObsoleteLoadCount;
	/*0x06E*/     UINT16       TlsIndex;
	/*0x070*/     struct _LIST_ENTRY HashLinks;                            // 2 elements, 0x10 bytes (sizeof)   
	/*0x080*/     ULONG32      TimeDateStamp;
	/*0x084*/     UINT8        _PADDING1_[0x4];
	/*0x088*/     PVOID EntryPointActivationContext;
	/*0x090*/     VOID* Lock;
	/*0x098*/     PVOID DdagNode;
	/*0x0A0*/     struct _LIST_ENTRY NodeModuleLink;                       // 2 elements, 0x10 bytes (sizeof)   
	/*0x0B0*/     PVOID LoadContext;
	/*0x0B8*/     VOID* ParentDllBase;
	/*0x0C0*/     VOID* SwitchBackContext;
	/*0x0C8*/     struct _RTL_BALANCED_NODE BaseAddressIndexNode;          // 6 elements, 0x18 bytes (sizeof)   
	/*0x0E0*/     struct _RTL_BALANCED_NODE MappingInfoIndexNode;          // 6 elements, 0x18 bytes (sizeof)   
	/*0x0F8*/     UINT64       OriginalBase;
	/*0x100*/     union _LARGE_INTEGER LoadTime;                           // 4 elements, 0x8 bytes (sizeof)    
	/*0x108*/     ULONG32      BaseNameHashValue;
	/*0x10C*/     enum _LDR_DLL_LOAD_REASON LoadReason;
	/*0x110*/     ULONG32      ImplicitPathOptions;
	/*0x114*/     ULONG32      ReferenceCount;
	/*0x118*/     ULONG32      DependentLoadFlags;
	/*0x11C*/     UINT8        SigningLevel;
	/*0x11D*/     UINT8        _PADDING2_[0x3];
}LDR_DATA_TABLE_ENTRY64, * PLDR_DATA_TABLE_ENTRY64;
typedef struct _PEB_LDR_DATA64                            // 9 elements, 0x58 bytes (sizeof) 
{
	/*0x000*/     ULONG32      Length;
	/*0x004*/     UINT8        Initialized;
	/*0x005*/     UINT8        _PADDING0_[0x3];
	/*0x008*/     VOID* SsHandle;
	/*0x010*/     struct _LIST_ENTRY InLoadOrderModuleList;           // 2 elements, 0x10 bytes (sizeof) 
	/*0x020*/     struct _LIST_ENTRY InMemoryOrderModuleList;         // 2 elements, 0x10 bytes (sizeof) 
	/*0x030*/     struct _LIST_ENTRY InInitializationOrderModuleList; // 2 elements, 0x10 bytes (sizeof) 
	/*0x040*/     VOID* EntryInProgress;
	/*0x048*/     UINT8        ShutdownInProgress;
	/*0x049*/     UINT8        _PADDING1_[0x7];
	/*0x050*/     VOID* ShutdownThreadId;
}PEB_LDR_DATA64, * PPEB_LDR_DATA64;

typedef struct _PEB64                                      // 115 elements, 0x7C8 bytes (sizeof) 
{
	/*0x000*/     UINT8        InheritedAddressSpace;
	/*0x001*/     UINT8        ReadImageFileExecOptions;
	/*0x002*/     UINT8        BeingDebugged;
	union                                                  // 2 elements, 0x1 bytes (sizeof)     
	{
		/*0x003*/         UINT8        BitField;
		struct                                             // 8 elements, 0x1 bytes (sizeof)     
		{
			/*0x003*/             UINT8        ImageUsesLargePages : 1;          // 0 BitPosition                      
			/*0x003*/             UINT8        IsProtectedProcess : 1;           // 1 BitPosition                      
			/*0x003*/             UINT8        IsImageDynamicallyRelocated : 1;  // 2 BitPosition                      
			/*0x003*/             UINT8        SkipPatchingUser32Forwarders : 1; // 3 BitPosition                      
			/*0x003*/             UINT8        IsPackagedProcess : 1;            // 4 BitPosition                      
			/*0x003*/             UINT8        IsAppContainer : 1;               // 5 BitPosition                      
			/*0x003*/             UINT8        IsProtectedProcessLight : 1;      // 6 BitPosition                      
			/*0x003*/             UINT8        IsLongPathAwareProcess : 1;       // 7 BitPosition                      
		};
	};
	/*0x004*/     UINT8        Padding0[4];
	/*0x008*/     UINT64       Mutant;
	/*0x010*/     UINT64       ImageBaseAddress;
	/*0x018*/     UINT64       Ldr;
	/*0x020*/     UINT64       ProcessParameters;
	/*0x028*/     UINT64       SubSystemData;
	/*0x030*/     UINT64       ProcessHeap;
	/*0x038*/     UINT64       FastPebLock;
	/*0x040*/     UINT64       AtlThunkSListPtr;
	/*0x048*/     UINT64       IFEOKey;
	union                                                  // 2 elements, 0x4 bytes (sizeof)     
	{
		/*0x050*/         ULONG32      CrossProcessFlags;
		struct                                             // 9 elements, 0x4 bytes (sizeof)     
		{
			/*0x050*/             ULONG32      ProcessInJob : 1;                 // 0 BitPosition                      
			/*0x050*/             ULONG32      ProcessInitializing : 1;          // 1 BitPosition                      
			/*0x050*/             ULONG32      ProcessUsingVEH : 1;              // 2 BitPosition                      
			/*0x050*/             ULONG32      ProcessUsingVCH : 1;              // 3 BitPosition                      
			/*0x050*/             ULONG32      ProcessUsingFTH : 1;              // 4 BitPosition                      
			/*0x050*/             ULONG32      ProcessPreviouslyThrottled : 1;   // 5 BitPosition                      
			/*0x050*/             ULONG32      ProcessCurrentlyThrottled : 1;    // 6 BitPosition                      
			/*0x050*/             ULONG32      ProcessImagesHotPatched : 1;      // 7 BitPosition                      
			/*0x050*/             ULONG32      ReservedBits0 : 24;               // 8 BitPosition                      
		};
	};
	/*0x054*/     UINT8        Padding1[4];
	union                                                  // 2 elements, 0x8 bytes (sizeof)     
	{
		/*0x058*/         UINT64       KernelCallbackTable;
		/*0x058*/         UINT64       UserSharedInfoPtr;
	};
	/*0x060*/     ULONG32      SystemReserved;
	/*0x064*/     ULONG32      AtlThunkSListPtr32;
	/*0x068*/     UINT64       ApiSetMap;
	/*0x070*/     ULONG32      TlsExpansionCounter;
	/*0x074*/     UINT8        Padding2[4];
	/*0x078*/     UINT64       TlsBitmap;
	/*0x080*/     ULONG32      TlsBitmapBits[2];
	/*0x088*/     UINT64       ReadOnlySharedMemoryBase;
	/*0x090*/     UINT64       SharedData;
	/*0x098*/     UINT64       ReadOnlyStaticServerData;
	/*0x0A0*/     UINT64       AnsiCodePageData;
	/*0x0A8*/     UINT64       OemCodePageData;
	/*0x0B0*/     UINT64       UnicodeCaseTableData;
	/*0x0B8*/     ULONG32      NumberOfProcessors;
	/*0x0BC*/     ULONG32      NtGlobalFlag;
	/*0x0C0*/     union _LARGE_INTEGER CriticalSectionTimeout;           // 4 elements, 0x8 bytes (sizeof)     
	/*0x0C8*/     UINT64       HeapSegmentReserve;
	/*0x0D0*/     UINT64       HeapSegmentCommit;
	/*0x0D8*/     UINT64       HeapDeCommitTotalFreeThreshold;
	/*0x0E0*/     UINT64       HeapDeCommitFreeBlockThreshold;
	/*0x0E8*/     ULONG32      NumberOfHeaps;
	/*0x0EC*/     ULONG32      MaximumNumberOfHeaps;
	/*0x0F0*/     UINT64       ProcessHeaps;
	/*0x0F8*/     UINT64       GdiSharedHandleTable;
	/*0x100*/     UINT64       ProcessStarterHelper;
	/*0x108*/     ULONG32      GdiDCAttributeList;
	/*0x10C*/     UINT8        Padding3[4];
	/*0x110*/     UINT64       LoaderLock;
	/*0x118*/     ULONG32      OSMajorVersion;
	/*0x11C*/     ULONG32      OSMinorVersion;
	/*0x120*/     UINT16       OSBuildNumber;
	/*0x122*/     UINT16       OSCSDVersion;
	/*0x124*/     ULONG32      OSPlatformId;
	/*0x128*/     ULONG32      ImageSubsystem;
	/*0x12C*/     ULONG32      ImageSubsystemMajorVersion;
	/*0x130*/     ULONG32      ImageSubsystemMinorVersion;
	/*0x134*/     UINT8        Padding4[4];
	/*0x138*/     UINT64       ActiveProcessAffinityMask;
	/*0x140*/     ULONG32      GdiHandleBuffer[60];
	/*0x230*/     UINT64       PostProcessInitRoutine;
	/*0x238*/     UINT64       TlsExpansionBitmap;
	/*0x240*/     ULONG32      TlsExpansionBitmapBits[32];
	/*0x2C0*/     ULONG32      SessionId;
	/*0x2C4*/     UINT8        Padding5[4];
	/*0x2C8*/     union _ULARGE_INTEGER AppCompatFlags;                  // 4 elements, 0x8 bytes (sizeof)     
	/*0x2D0*/     union _ULARGE_INTEGER AppCompatFlagsUser;              // 4 elements, 0x8 bytes (sizeof)     
	/*0x2D8*/     UINT64       pShimData;
	/*0x2E0*/     UINT64       AppCompatInfo;
	/*0x2E8*/     struct _STRING CSDVersion;                           // 3 elements, 0x10 bytes (sizeof)    
	/*0x2F8*/     UINT64       ActivationContextData;
	/*0x300*/     UINT64       ProcessAssemblyStorageMap;
	/*0x308*/     UINT64       SystemDefaultActivationContextData;
	/*0x310*/     UINT64       SystemAssemblyStorageMap;
	/*0x318*/     UINT64       MinimumStackCommit;
	/*0x320*/     UINT64       SparePointers[4];
	/*0x340*/     ULONG32      SpareUlongs[5];
	/*0x354*/     UINT8        _PADDING0_[0x4];
	/*0x358*/     UINT64       WerRegistrationData;
	/*0x360*/     UINT64       WerShipAssertPtr;
	/*0x368*/     UINT64       pUnused;
	/*0x370*/     UINT64       pImageHeaderHash;
	union                                                  // 2 elements, 0x4 bytes (sizeof)     
	{
		/*0x378*/         ULONG32      TracingFlags;
		struct                                             // 4 elements, 0x4 bytes (sizeof)     
		{
			/*0x378*/             ULONG32      HeapTracingEnabled : 1;           // 0 BitPosition                      
			/*0x378*/             ULONG32      CritSecTracingEnabled : 1;        // 1 BitPosition                      
			/*0x378*/             ULONG32      LibLoaderTracingEnabled : 1;      // 2 BitPosition                      
			/*0x378*/             ULONG32      SpareTracingBits : 29;            // 3 BitPosition                      
		};
	};
	/*0x37C*/     UINT8        Padding6[4];
	/*0x380*/     UINT64       CsrServerReadOnlySharedMemoryBase;
	/*0x388*/     UINT64       TppWorkerpListLock;
	/*0x390*/     struct _LIST_ENTRY TppWorkerpList;                   // 2 elements, 0x10 bytes (sizeof)    
	/*0x3A0*/     UINT64       WaitOnAddressHashTable[128];
	/*0x7A0*/     UINT64       TelemetryCoverageHeader;
	/*0x7A8*/     ULONG32      CloudFileFlags;
	/*0x7AC*/     ULONG32      CloudFileDiagFlags;
	/*0x7B0*/     CHAR         PlaceholderCompatibilityMode;
	/*0x7B1*/     CHAR         PlaceholderCompatibilityModeReserved[7];
	/*0x7B8*/     UINT64       LeapSecondData;
	union                                                  // 2 elements, 0x4 bytes (sizeof)     
	{
		/*0x7C0*/         ULONG32      LeapSecondFlags;
		struct                                             // 2 elements, 0x4 bytes (sizeof)     
		{
			/*0x7C0*/             ULONG32      SixtySecondEnabled : 1;           // 0 BitPosition                      
			/*0x7C0*/             ULONG32      Reserved : 31;                    // 1 BitPosition                      
		};
	};
	/*0x7C4*/     ULONG32      NtGlobalFlag2;
}PEB64, * PPEB64;




typedef struct _GDI_TEB_BATCH64               // 4 elements, 0x4E8 bytes (sizeof) 
{
	struct                                    // 2 elements, 0x4 bytes (sizeof)   
	{
		/*0x000*/         ULONG32      Offset : 31;             // 0 BitPosition                    
		/*0x000*/         ULONG32      HasRenderingCommand : 1; // 31 BitPosition                   
	};
	/*0x008*/     UINT64       HDC;
	/*0x010*/     ULONG32      Buffer[310];
}GDI_TEB_BATCH64, * PGDI_TEB_BATCH64;
typedef struct _ACTIVATION_CONTEXT_STACK64 // 5 elements, 0x28 bytes (sizeof) 
{
	/*0x000*/     UINT64       ActiveFrame;
	/*0x008*/     struct _LIST_ENTRY FrameListCache;   // 2 elements, 0x10 bytes (sizeof) 
	/*0x018*/     ULONG32      Flags;
	/*0x01C*/     ULONG32      NextCookieSequenceNumber;
	/*0x020*/     ULONG32      StackId;
	/*0x024*/     UINT8        _PADDING0_[0x4];
}ACTIVATION_CONTEXT_STACK64, * PACTIVATION_CONTEXT_STACK64;
typedef struct _TEB64                                    // 127 elements, 0x1838 bytes (sizeof) 
{
	/*0x000*/      struct _NT_TIB64 NtTib;                              // 8 elements, 0x38 bytes (sizeof)     
	/*0x038*/      UINT64       EnvironmentPointer;
	/*0x040*/      struct _CLIENT_ID ClientId;                        // 2 elements, 0x10 bytes (sizeof)     
	/*0x050*/      UINT64       ActiveRpcHandle;
	/*0x058*/      UINT64       ThreadLocalStoragePointer;
	/*0x060*/      UINT64       ProcessEnvironmentBlock;
	/*0x068*/      ULONG32      LastErrorValue;
	/*0x06C*/      ULONG32      CountOfOwnedCriticalSections;
	/*0x070*/      UINT64       CsrClientThread;
	/*0x078*/      UINT64       Win32ThreadInfo;
	/*0x080*/      ULONG32      User32Reserved[26];
	/*0x0E8*/      ULONG32      UserReserved[5];
	/*0x0FC*/      UINT8        _PADDING0_[0x4];
	/*0x100*/      UINT64       WOW32Reserved;
	/*0x108*/      ULONG32      CurrentLocale;
	/*0x10C*/      ULONG32      FpSoftwareStatusRegister;
	/*0x110*/      UINT64       ReservedForDebuggerInstrumentation[16];
	/*0x190*/      UINT64       SystemReserved1[30];
	/*0x280*/      CHAR         PlaceholderCompatibilityMode;
	/*0x281*/      UINT8        PlaceholderHydrationAlwaysExplicit;
	/*0x282*/      CHAR         PlaceholderReserved[10];
	/*0x28C*/      ULONG32      ProxiedProcessId;
	/*0x290*/      struct _ACTIVATION_CONTEXT_STACK64 _ActivationStack; // 5 elements, 0x28 bytes (sizeof)     
	/*0x2B8*/      UINT8        WorkingOnBehalfTicket[8];
	/*0x2C0*/      LONG32       ExceptionCode;
	/*0x2C4*/      UINT8        Padding0[4];
	/*0x2C8*/      UINT64       ActivationContextStackPointer;
	/*0x2D0*/      UINT64       InstrumentationCallbackSp;
	/*0x2D8*/      UINT64       InstrumentationCallbackPreviousPc;
	/*0x2E0*/      UINT64       InstrumentationCallbackPreviousSp;
	/*0x2E8*/      ULONG32      TxFsContext;
	/*0x2EC*/      UINT8        InstrumentationCallbackDisabled;
	/*0x2ED*/      UINT8        UnalignedLoadStoreExceptions;
	/*0x2EE*/      UINT8        Padding1[2];
	/*0x2F0*/      struct _GDI_TEB_BATCH64 GdiTebBatch;                 // 4 elements, 0x4E8 bytes (sizeof)    
	/*0x7D8*/      struct _CLIENT_ID RealClientId;                    // 2 elements, 0x10 bytes (sizeof)     
	/*0x7E8*/      UINT64       GdiCachedProcessHandle;
	/*0x7F0*/      ULONG32      GdiClientPID;
	/*0x7F4*/      ULONG32      GdiClientTID;
	/*0x7F8*/      UINT64       GdiThreadLocalInfo;
	/*0x800*/      UINT64       Win32ClientInfo[62];
	/*0x9F0*/      UINT64       glDispatchTable[233];
	/*0x1138*/     UINT64       glReserved1[29];
	/*0x1220*/     UINT64       glReserved2;
	/*0x1228*/     UINT64       glSectionInfo;
	/*0x1230*/     UINT64       glSection;
	/*0x1238*/     UINT64       glTable;
	/*0x1240*/     UINT64       glCurrentRC;
	/*0x1248*/     UINT64       glContext;
	/*0x1250*/     ULONG32      LastStatusValue;
	/*0x1254*/     UINT8        Padding2[4];
	/*0x1258*/     struct _STRING StaticUnicodeString;                // 3 elements, 0x10 bytes (sizeof)     
	/*0x1268*/     WCHAR        StaticUnicodeBuffer[261];
	/*0x1472*/     UINT8        Padding3[6];
	/*0x1478*/     UINT64       DeallocationStack;
	/*0x1480*/     UINT64       TlsSlots[64];
	/*0x1680*/     struct _LIST_ENTRY TlsLinks;                       // 2 elements, 0x10 bytes (sizeof)     
	/*0x1690*/     UINT64       Vdm;
	/*0x1698*/     UINT64       ReservedForNtRpc;
	/*0x16A0*/     UINT64       DbgSsReserved[2];
	/*0x16B0*/     ULONG32      HardErrorMode;
	/*0x16B4*/     UINT8        Padding4[4];
	/*0x16B8*/     UINT64       Instrumentation[11];
	/*0x1710*/     struct _GUID ActivityId;                             // 4 elements, 0x10 bytes (sizeof)     
	/*0x1720*/     UINT64       SubProcessTag;
	/*0x1728*/     UINT64       PerflibData;
	/*0x1730*/     UINT64       EtwTraceData;
	/*0x1738*/     UINT64       WinSockData;
	/*0x1740*/     ULONG32      GdiBatchCount;
	union                                                // 3 elements, 0x4 bytes (sizeof)      
	{
		/*0x1744*/         struct _PROCESSOR_NUMBER CurrentIdealProcessor;  // 3 elements, 0x4 bytes (sizeof)      
		/*0x1744*/         ULONG32      IdealProcessorValue;
		struct                                           // 4 elements, 0x4 bytes (sizeof)      
		{
			/*0x1744*/             UINT8        ReservedPad0;
			/*0x1745*/             UINT8        ReservedPad1;
			/*0x1746*/             UINT8        ReservedPad2;
			/*0x1747*/             UINT8        IdealProcessor;
		};
	};
	/*0x1748*/     ULONG32      GuaranteedStackBytes;
	/*0x174C*/     UINT8        Padding5[4];
	/*0x1750*/     UINT64       ReservedForPerf;
	/*0x1758*/     UINT64       ReservedForOle;
	/*0x1760*/     ULONG32      WaitingOnLoaderLock;
	/*0x1764*/     UINT8        Padding6[4];
	/*0x1768*/     UINT64       SavedPriorityState;
	/*0x1770*/     UINT64       ReservedForCodeCoverage;
	/*0x1778*/     UINT64       ThreadPoolData;
	/*0x1780*/     UINT64       TlsExpansionSlots;
	/*0x1788*/     UINT64       DeallocationBStore;
	/*0x1790*/     UINT64       BStoreLimit;
	/*0x1798*/     ULONG32      MuiGeneration;
	/*0x179C*/     ULONG32      IsImpersonating;
	/*0x17A0*/     UINT64       NlsCache;
	/*0x17A8*/     UINT64       pShimData;
	/*0x17B0*/     ULONG32      HeapData;
	/*0x17B4*/     UINT8        Padding7[4];
	/*0x17B8*/     UINT64       CurrentTransactionHandle;
	/*0x17C0*/     UINT64       ActiveFrame;
	/*0x17C8*/     UINT64       FlsData;
	/*0x17D0*/     UINT64       PreferredLanguages;
	/*0x17D8*/     UINT64       UserPrefLanguages;
	/*0x17E0*/     UINT64       MergedPrefLanguages;
	/*0x17E8*/     ULONG32      MuiImpersonation;
	union                                                // 2 elements, 0x2 bytes (sizeof)      
	{
		/*0x17EC*/         UINT16       CrossTebFlags;
		/*0x17EC*/         UINT16       SpareCrossTebBits : 16;             // 0 BitPosition                       
	};
	union                                                // 2 elements, 0x2 bytes (sizeof)      
	{
		/*0x17EE*/         UINT16       SameTebFlags;
		struct                                           // 16 elements, 0x2 bytes (sizeof)     
		{
			/*0x17EE*/             UINT16       SafeThunkCall : 1;              // 0 BitPosition                       
			/*0x17EE*/             UINT16       InDebugPrint : 1;               // 1 BitPosition                       
			/*0x17EE*/             UINT16       HasFiberData : 1;               // 2 BitPosition                       
			/*0x17EE*/             UINT16       SkipThreadAttach : 1;           // 3 BitPosition                       
			/*0x17EE*/             UINT16       WerInShipAssertCode : 1;        // 4 BitPosition                       
			/*0x17EE*/             UINT16       RanProcessInit : 1;             // 5 BitPosition                       
			/*0x17EE*/             UINT16       ClonedThread : 1;               // 6 BitPosition                       
			/*0x17EE*/             UINT16       SuppressDebugMsg : 1;           // 7 BitPosition                       
			/*0x17EE*/             UINT16       DisableUserStackWalk : 1;       // 8 BitPosition                       
			/*0x17EE*/             UINT16       RtlExceptionAttached : 1;       // 9 BitPosition                       
			/*0x17EE*/             UINT16       InitialThread : 1;              // 10 BitPosition                      
			/*0x17EE*/             UINT16       SessionAware : 1;               // 11 BitPosition                      
			/*0x17EE*/             UINT16       LoadOwner : 1;                  // 12 BitPosition                      
			/*0x17EE*/             UINT16       LoaderWorker : 1;               // 13 BitPosition                      
			/*0x17EE*/             UINT16       SkipLoaderInit : 1;             // 14 BitPosition                      
			/*0x17EE*/             UINT16       SpareSameTebBits : 1;           // 15 BitPosition                      
		};
	};
	/*0x17F0*/     UINT64       TxnScopeEnterCallback;
	/*0x17F8*/     UINT64       TxnScopeExitCallback;
	/*0x1800*/     UINT64       TxnScopeContext;
	/*0x1808*/     ULONG32      LockCount;
	/*0x180C*/     LONG32       WowTebOffset;
	/*0x1810*/     UINT64       ResourceRetValue;
	/*0x1818*/     UINT64       ReservedForWdf;
	/*0x1820*/     UINT64       ReservedForCrt;
	/*0x1828*/     struct _GUID EffectiveContainerId;                   // 4 elements, 0x10 bytes (sizeof)     
}TEB64, * PTEB64;
#pragma pack()


#pragma pack(4)
typedef struct _STRING32        // 3 elements, 0x8 bytes (sizeof) 
{
	/*0x000*/     UINT16       Length;
	/*0x002*/     UINT16       MaximumLength;
	/*0x004*/     ULONG32      Buffer;
}STRING32, * PSTRING32;
typedef struct _LDR_DATA_TABLE_ENTRY32
{
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
	ULONG DllBase;
	ULONG EntryPoint;
	ULONG SizeOfImage;
	STRING32 FullDllName;
	STRING32 BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union
	{
		LIST_ENTRY32 HashLinks;
		ULONG SectionPointer;
	}u1;
	ULONG CheckSum;
	union
	{
		ULONG TimeDateStamp;
		ULONG LoadedImports;
	}u2;
	ULONG EntryPointActivationContext;
	ULONG PatchInformation;
} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;

typedef struct _PEB_LDR_DATA32
{
	ULONG Length;
	BOOLEAN Initialized;
	ULONG SsHandle;
	LIST_ENTRY32 InLoadOrderModuleList;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
	ULONG EntryInProgress;
} PEB_LDR_DATA32, * PPEB_LDR_DATA32;

typedef struct _GDI_TEB_BATCH32               // 4 elements, 0x4E0 bytes (sizeof) 
{
	struct                                    // 2 elements, 0x4 bytes (sizeof)   
	{
		/*0x000*/         ULONG32      Offset : 31;             // 0 BitPosition                    
		/*0x000*/         ULONG32      HasRenderingCommand : 1; // 31 BitPosition                   
	};
	/*0x004*/     ULONG32      HDC;
	/*0x008*/     ULONG32      Buffer[310];
}GDI_TEB_BATCH32, * PGDI_TEB_BATCH32;

typedef struct _ACTIVATION_CONTEXT_STACK32 // 5 elements, 0x18 bytes (sizeof) 
{
	/*0x000*/     ULONG32      ActiveFrame;
	/*0x004*/     struct LIST_ENTRY32 FrameListCache;   // 2 elements, 0x8 bytes (sizeof)  
	/*0x00C*/     ULONG32      Flags;
	/*0x010*/     ULONG32      NextCookieSequenceNumber;
	/*0x014*/     ULONG32      StackId;
}ACTIVATION_CONTEXT_STACK32, * PACTIVATION_CONTEXT_STACK32;
typedef struct _CLIENT_ID32     // 2 elements, 0x8 bytes (sizeof) 
{
	/*0x000*/     ULONG32      UniqueProcess;
	/*0x004*/     ULONG32      UniqueThread;
}CLIENT_ID32, * PCLIENT_ID32;
typedef struct _TEB32                                    // 117 elements, 0x1000 bytes (sizeof) 
{
	/*0x000*/     struct _NT_TIB32 NtTib;                              // 8 elements, 0x1C bytes (sizeof)     
	/*0x01C*/     ULONG32      EnvironmentPointer;
	/*0x020*/     struct _CLIENT_ID32 ClientId;                        // 2 elements, 0x8 bytes (sizeof)      
	/*0x028*/     ULONG32      ActiveRpcHandle;
	/*0x02C*/     ULONG32      ThreadLocalStoragePointer;
	/*0x030*/     ULONG32      ProcessEnvironmentBlock;
	/*0x034*/     ULONG32      LastErrorValue;
	/*0x038*/     ULONG32      CountOfOwnedCriticalSections;
	/*0x03C*/     ULONG32      CsrClientThread;
	/*0x040*/     ULONG32      Win32ThreadInfo;
	/*0x044*/     ULONG32      User32Reserved[26];
	/*0x0AC*/     ULONG32      UserReserved[5];
	/*0x0C0*/     ULONG32      WOW32Reserved;
	/*0x0C4*/     ULONG32      CurrentLocale;
	/*0x0C8*/     ULONG32      FpSoftwareStatusRegister;
	/*0x0CC*/     ULONG32      ReservedForDebuggerInstrumentation[16];
	/*0x10C*/     ULONG32      SystemReserved1[26];
	/*0x174*/     CHAR         PlaceholderCompatibilityMode;
	/*0x175*/     UINT8        PlaceholderHydrationAlwaysExplicit;
	/*0x176*/     CHAR         PlaceholderReserved[10];
	/*0x180*/     ULONG32      ProxiedProcessId;
	/*0x184*/     struct _ACTIVATION_CONTEXT_STACK32 _ActivationStack; // 5 elements, 0x18 bytes (sizeof)     
	/*0x19C*/     UINT8        WorkingOnBehalfTicket[8];
	/*0x1A4*/     LONG32       ExceptionCode;
	/*0x1A8*/     ULONG32      ActivationContextStackPointer;
	/*0x1AC*/     ULONG32      InstrumentationCallbackSp;
	/*0x1B0*/     ULONG32      InstrumentationCallbackPreviousPc;
	/*0x1B4*/     ULONG32      InstrumentationCallbackPreviousSp;
	/*0x1B8*/     UINT8        InstrumentationCallbackDisabled;
	/*0x1B9*/     UINT8        SpareBytes[23];
	/*0x1D0*/     ULONG32      TxFsContext;
	/*0x1D4*/     struct _GDI_TEB_BATCH32 GdiTebBatch;                 // 4 elements, 0x4E0 bytes (sizeof)    
	/*0x6B4*/     struct _CLIENT_ID32 RealClientId;                    // 2 elements, 0x8 bytes (sizeof)      
	/*0x6BC*/     ULONG32      GdiCachedProcessHandle;
	/*0x6C0*/     ULONG32      GdiClientPID;
	/*0x6C4*/     ULONG32      GdiClientTID;
	/*0x6C8*/     ULONG32      GdiThreadLocalInfo;
	/*0x6CC*/     ULONG32      Win32ClientInfo[62];
	/*0x7C4*/     ULONG32      glDispatchTable[233];
	/*0xB68*/     ULONG32      glReserved1[29];
	/*0xBDC*/     ULONG32      glReserved2;
	/*0xBE0*/     ULONG32      glSectionInfo;
	/*0xBE4*/     ULONG32      glSection;
	/*0xBE8*/     ULONG32      glTable;
	/*0xBEC*/     ULONG32      glCurrentRC;
	/*0xBF0*/     ULONG32      glContext;
	/*0xBF4*/     ULONG32      LastStatusValue;
	/*0xBF8*/     struct _STRING32 StaticUnicodeString;                // 3 elements, 0x8 bytes (sizeof)      
	/*0xC00*/     WCHAR        StaticUnicodeBuffer[261];
	/*0xE0A*/     UINT8        _PADDING0_[0x2];
	/*0xE0C*/     ULONG32      DeallocationStack;
	/*0xE10*/     ULONG32      TlsSlots[64];
	/*0xF10*/     struct LIST_ENTRY32 TlsLinks;                       // 2 elements, 0x8 bytes (sizeof)      
	/*0xF18*/     ULONG32      Vdm;
	/*0xF1C*/     ULONG32      ReservedForNtRpc;
	/*0xF20*/     ULONG32      DbgSsReserved[2];
	/*0xF28*/     ULONG32      HardErrorMode;
	/*0xF2C*/     ULONG32      Instrumentation[9];
	/*0xF50*/     struct _GUID ActivityId;                             // 4 elements, 0x10 bytes (sizeof)     
	/*0xF60*/     ULONG32      SubProcessTag;
	/*0xF64*/     ULONG32      PerflibData;
	/*0xF68*/     ULONG32      EtwTraceData;
	/*0xF6C*/     ULONG32      WinSockData;
	/*0xF70*/     ULONG32      GdiBatchCount;
	union                                                // 3 elements, 0x4 bytes (sizeof)      
	{
		/*0xF74*/         struct _PROCESSOR_NUMBER CurrentIdealProcessor;  // 3 elements, 0x4 bytes (sizeof)      
		/*0xF74*/         ULONG32      IdealProcessorValue;
		struct                                           // 4 elements, 0x4 bytes (sizeof)      
		{
			/*0xF74*/             UINT8        ReservedPad0;
			/*0xF75*/             UINT8        ReservedPad1;
			/*0xF76*/             UINT8        ReservedPad2;
			/*0xF77*/             UINT8        IdealProcessor;
		};
	};
	/*0xF78*/     ULONG32      GuaranteedStackBytes;
	/*0xF7C*/     ULONG32      ReservedForPerf;
	/*0xF80*/     ULONG32      ReservedForOle;
	/*0xF84*/     ULONG32      WaitingOnLoaderLock;
	/*0xF88*/     ULONG32      SavedPriorityState;
	/*0xF8C*/     ULONG32      ReservedForCodeCoverage;
	/*0xF90*/     ULONG32      ThreadPoolData;
	/*0xF94*/     ULONG32      TlsExpansionSlots;
	/*0xF98*/     ULONG32      MuiGeneration;
	/*0xF9C*/     ULONG32      IsImpersonating;
	/*0xFA0*/     ULONG32      NlsCache;
	/*0xFA4*/     ULONG32      pShimData;
	/*0xFA8*/     ULONG32      HeapData;
	/*0xFAC*/     ULONG32      CurrentTransactionHandle;
	/*0xFB0*/     ULONG32      ActiveFrame;
	/*0xFB4*/     ULONG32      FlsData;
	/*0xFB8*/     ULONG32      PreferredLanguages;
	/*0xFBC*/     ULONG32      UserPrefLanguages;
	/*0xFC0*/     ULONG32      MergedPrefLanguages;
	/*0xFC4*/     ULONG32      MuiImpersonation;
	union                                                // 2 elements, 0x2 bytes (sizeof)      
	{
		/*0xFC8*/         UINT16       CrossTebFlags;
		/*0xFC8*/         UINT16       SpareCrossTebBits : 16;             // 0 BitPosition                       
	};
	union                                                // 2 elements, 0x2 bytes (sizeof)      
	{
		/*0xFCA*/         UINT16       SameTebFlags;
		struct                                           // 16 elements, 0x2 bytes (sizeof)     
		{
			/*0xFCA*/             UINT16       SafeThunkCall : 1;              // 0 BitPosition                       
			/*0xFCA*/             UINT16       InDebugPrint : 1;               // 1 BitPosition                       
			/*0xFCA*/             UINT16       HasFiberData : 1;               // 2 BitPosition                       
			/*0xFCA*/             UINT16       SkipThreadAttach : 1;           // 3 BitPosition                       
			/*0xFCA*/             UINT16       WerInShipAssertCode : 1;        // 4 BitPosition                       
			/*0xFCA*/             UINT16       RanProcessInit : 1;             // 5 BitPosition                       
			/*0xFCA*/             UINT16       ClonedThread : 1;               // 6 BitPosition                       
			/*0xFCA*/             UINT16       SuppressDebugMsg : 1;           // 7 BitPosition                       
			/*0xFCA*/             UINT16       DisableUserStackWalk : 1;       // 8 BitPosition                       
			/*0xFCA*/             UINT16       RtlExceptionAttached : 1;       // 9 BitPosition                       
			/*0xFCA*/             UINT16       InitialThread : 1;              // 10 BitPosition                      
			/*0xFCA*/             UINT16       SessionAware : 1;               // 11 BitPosition                      
			/*0xFCA*/             UINT16       LoadOwner : 1;                  // 12 BitPosition                      
			/*0xFCA*/             UINT16       LoaderWorker : 1;               // 13 BitPosition                      
			/*0xFCA*/             UINT16       SkipLoaderInit : 1;             // 14 BitPosition                      
			/*0xFCA*/             UINT16       SpareSameTebBits : 1;           // 15 BitPosition                      
		};
	};
	/*0xFCC*/     ULONG32      TxnScopeEnterCallback;
	/*0xFD0*/     ULONG32      TxnScopeExitCallback;
	/*0xFD4*/     ULONG32      TxnScopeContext;
	/*0xFD8*/     ULONG32      LockCount;
	/*0xFDC*/     LONG32       WowTebOffset;
	/*0xFE0*/     ULONG32      ResourceRetValue;
	/*0xFE4*/     ULONG32      ReservedForWdf;
	/*0xFE8*/     UINT64       ReservedForCrt;
	/*0xFF0*/     struct _GUID EffectiveContainerId;                   // 4 elements, 0x10 bytes (sizeof)     
}TEB32, * PTEB32;



typedef struct _PEB32                                      // 108 elements, 0x480 bytes (sizeof) 
{
	/*0x000*/     UINT8        InheritedAddressSpace;
	/*0x001*/     UINT8        ReadImageFileExecOptions;
	/*0x002*/     UINT8        BeingDebugged;
	union                                                  // 2 elements, 0x1 bytes (sizeof)     
	{
		/*0x003*/         UINT8        BitField;
		struct                                             // 8 elements, 0x1 bytes (sizeof)     
		{
			/*0x003*/             UINT8        ImageUsesLargePages : 1;          // 0 BitPosition                      
			/*0x003*/             UINT8        IsProtectedProcess : 1;           // 1 BitPosition                      
			/*0x003*/             UINT8        IsImageDynamicallyRelocated : 1;  // 2 BitPosition                      
			/*0x003*/             UINT8        SkipPatchingUser32Forwarders : 1; // 3 BitPosition                      
			/*0x003*/             UINT8        IsPackagedProcess : 1;            // 4 BitPosition                      
			/*0x003*/             UINT8        IsAppContainer : 1;               // 5 BitPosition                      
			/*0x003*/             UINT8        IsProtectedProcessLight : 1;      // 6 BitPosition                      
			/*0x003*/             UINT8        IsLongPathAwareProcess : 1;       // 7 BitPosition                      
		};
	};
	/*0x004*/     ULONG32      Mutant;
	/*0x008*/     ULONG32      ImageBaseAddress;
	/*0x00C*/     ULONG32      Ldr;
	/*0x010*/     ULONG32      ProcessParameters;
	/*0x014*/     ULONG32      SubSystemData;
	/*0x018*/     ULONG32      ProcessHeap;
	/*0x01C*/     ULONG32      FastPebLock;
	/*0x020*/     ULONG32      AtlThunkSListPtr;
	/*0x024*/     ULONG32      IFEOKey;
	union                                                  // 2 elements, 0x4 bytes (sizeof)     
	{
		/*0x028*/         ULONG32      CrossProcessFlags;
		struct                                             // 9 elements, 0x4 bytes (sizeof)     
		{
			/*0x028*/             ULONG32      ProcessInJob : 1;                 // 0 BitPosition                      
			/*0x028*/             ULONG32      ProcessInitializing : 1;          // 1 BitPosition                      
			/*0x028*/             ULONG32      ProcessUsingVEH : 1;              // 2 BitPosition                      
			/*0x028*/             ULONG32      ProcessUsingVCH : 1;              // 3 BitPosition                      
			/*0x028*/             ULONG32      ProcessUsingFTH : 1;              // 4 BitPosition                      
			/*0x028*/             ULONG32      ProcessPreviouslyThrottled : 1;   // 5 BitPosition                      
			/*0x028*/             ULONG32      ProcessCurrentlyThrottled : 1;    // 6 BitPosition                      
			/*0x028*/             ULONG32      ProcessImagesHotPatched : 1;      // 7 BitPosition                      
			/*0x028*/             ULONG32      ReservedBits0 : 24;               // 8 BitPosition                      
		};
	};
	union                                                  // 2 elements, 0x4 bytes (sizeof)     
	{
		/*0x02C*/         ULONG32      KernelCallbackTable;
		/*0x02C*/         ULONG32      UserSharedInfoPtr;
	};
	/*0x030*/     ULONG32      SystemReserved;
	/*0x034*/     ULONG32      AtlThunkSListPtr32;
	/*0x038*/     ULONG32      ApiSetMap;
	/*0x03C*/     ULONG32      TlsExpansionCounter;
	/*0x040*/     ULONG32      TlsBitmap;
	/*0x044*/     ULONG32      TlsBitmapBits[2];
	/*0x04C*/     ULONG32      ReadOnlySharedMemoryBase;
	/*0x050*/     ULONG32      SharedData;
	/*0x054*/     ULONG32      ReadOnlyStaticServerData;
	/*0x058*/     ULONG32      AnsiCodePageData;
	/*0x05C*/     ULONG32      OemCodePageData;
	/*0x060*/     ULONG32      UnicodeCaseTableData;
	/*0x064*/     ULONG32      NumberOfProcessors;
	/*0x068*/     ULONG32      NtGlobalFlag;
	/*0x06C*/     UINT8        _PADDING0_[0x4];
	/*0x070*/     union _LARGE_INTEGER CriticalSectionTimeout;           // 4 elements, 0x8 bytes (sizeof)     
	/*0x078*/     ULONG32      HeapSegmentReserve;
	/*0x07C*/     ULONG32      HeapSegmentCommit;
	/*0x080*/     ULONG32      HeapDeCommitTotalFreeThreshold;
	/*0x084*/     ULONG32      HeapDeCommitFreeBlockThreshold;
	/*0x088*/     ULONG32      NumberOfHeaps;
	/*0x08C*/     ULONG32      MaximumNumberOfHeaps;
	/*0x090*/     ULONG32      ProcessHeaps;
	/*0x094*/     ULONG32      GdiSharedHandleTable;
	/*0x098*/     ULONG32      ProcessStarterHelper;
	/*0x09C*/     ULONG32      GdiDCAttributeList;
	/*0x0A0*/     ULONG32      LoaderLock;
	/*0x0A4*/     ULONG32      OSMajorVersion;
	/*0x0A8*/     ULONG32      OSMinorVersion;
	/*0x0AC*/     UINT16       OSBuildNumber;
	/*0x0AE*/     UINT16       OSCSDVersion;
	/*0x0B0*/     ULONG32      OSPlatformId;
	/*0x0B4*/     ULONG32      ImageSubsystem;
	/*0x0B8*/     ULONG32      ImageSubsystemMajorVersion;
	/*0x0BC*/     ULONG32      ImageSubsystemMinorVersion;
	/*0x0C0*/     ULONG32      ActiveProcessAffinityMask;
	/*0x0C4*/     ULONG32      GdiHandleBuffer[34];
	/*0x14C*/     ULONG32      PostProcessInitRoutine;
	/*0x150*/     ULONG32      TlsExpansionBitmap;
	/*0x154*/     ULONG32      TlsExpansionBitmapBits[32];
	/*0x1D4*/     ULONG32      SessionId;
	/*0x1D8*/     union _ULARGE_INTEGER AppCompatFlags;                  // 4 elements, 0x8 bytes (sizeof)     
	/*0x1E0*/     union _ULARGE_INTEGER AppCompatFlagsUser;              // 4 elements, 0x8 bytes (sizeof)     
	/*0x1E8*/     ULONG32      pShimData;
	/*0x1EC*/     ULONG32      AppCompatInfo;
	/*0x1F0*/     struct _STRING32 CSDVersion;                           // 3 elements, 0x8 bytes (sizeof)     
	/*0x1F8*/     ULONG32      ActivationContextData;
	/*0x1FC*/     ULONG32      ProcessAssemblyStorageMap;
	/*0x200*/     ULONG32      SystemDefaultActivationContextData;
	/*0x204*/     ULONG32      SystemAssemblyStorageMap;
	/*0x208*/     ULONG32      MinimumStackCommit;
	/*0x20C*/     ULONG32      SparePointers[4];
	/*0x21C*/     ULONG32      SpareUlongs[5];
	/*0x230*/     ULONG32      WerRegistrationData;
	/*0x234*/     ULONG32      WerShipAssertPtr;
	/*0x238*/     ULONG32      pUnused;
	/*0x23C*/     ULONG32      pImageHeaderHash;
	union                                                  // 2 elements, 0x4 bytes (sizeof)     
	{
		/*0x240*/         ULONG32      TracingFlags;
		struct                                             // 4 elements, 0x4 bytes (sizeof)     
		{
			/*0x240*/             ULONG32      HeapTracingEnabled : 1;           // 0 BitPosition                      
			/*0x240*/             ULONG32      CritSecTracingEnabled : 1;        // 1 BitPosition                      
			/*0x240*/             ULONG32      LibLoaderTracingEnabled : 1;      // 2 BitPosition                      
			/*0x240*/             ULONG32      SpareTracingBits : 29;            // 3 BitPosition                      
		};
	};
	/*0x248*/     UINT64       CsrServerReadOnlySharedMemoryBase;
	/*0x250*/     ULONG32      TppWorkerpListLock;
	/*0x254*/     struct LIST_ENTRY32 TppWorkerpList;                   // 2 elements, 0x8 bytes (sizeof)     
	/*0x25C*/     ULONG32      WaitOnAddressHashTable[128];
	/*0x45C*/     ULONG32      TelemetryCoverageHeader;
	/*0x460*/     ULONG32      CloudFileFlags;
	/*0x464*/     ULONG32      CloudFileDiagFlags;
	/*0x468*/     CHAR         PlaceholderCompatibilityMode;
	/*0x469*/     CHAR         PlaceholderCompatibilityModeReserved[7];
	/*0x470*/     ULONG32      LeapSecondData;
	union                                                  // 2 elements, 0x4 bytes (sizeof)     
	{
		/*0x474*/         ULONG32      LeapSecondFlags;
		struct                                             // 2 elements, 0x4 bytes (sizeof)     
		{
			/*0x474*/             ULONG32      SixtySecondEnabled : 1;           // 0 BitPosition                      
			/*0x474*/             ULONG32      Reserved : 31;                    // 1 BitPosition                      
		};
	};
	/*0x478*/     ULONG32      NtGlobalFlag2;
	/*0x47C*/     UINT8        _PADDING1_[0x4];
}PEB32, * PPEB32;

#pragma pack()

#define  DWORDX ULONG_PTR

typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS                ExitStatus;
    PVOID                   TebBaseAddress;
    CLIENT_ID               ClientId;
    KAFFINITY               AffinityMask;
    LONG               Priority;
    LONG               BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;
DWORD HandleToPid(HANDLE hProcess);
PVOID GetThreadStartAddress(HANDLE hThread);
CLIENT_ID ThreadHandleToPid(HANDLE hThread);

DWORD GetProcessPid(const WCHAR* szProcessName);

std::string wstringToString(const std::wstring& wstr);
std::wstring stringToWstring(const std::string& str);

PVOID file_to_image_buffer(LPCWSTR szFullPath, DWORD& pImageSize);
BOOL ImageFile(PVOID FileBuffer, PVOID* ImageModuleBase, DWORD& ImageSize);
BOOL fixed_image_buffer(PVOID pImageBufer, ULONG_PTR pTargetAddress);
BOOL FixImportTable(PVOID pPEBuffer, ULONG_PTR dwLoadMemoryAddress);
UINT AlignSize(UINT nSize, UINT nAlign);
BOOL FixBaseRelocTable(PVOID pPEBuffer, ULONG_PTR dwLoadMemoryAddress);

//DOS路径转换NT路径    C:\\WINDOWS\\system32\\drivers    -- \\??\\C:\\WINDOWS\\system32\\drivers
NTSTATUS DosPathToNtPath(wchar_t* pDosPath, PUNICODE_STRING pNtPath);

//\\Device\\HarddiskVolume1\x86.sys    c:\x86.sys    
BOOL DeviceDosPathToNtPath(wchar_t* pszDosPath, wchar_t* pszNtPath);

//NT路径转换DOS路径    \\??\\C:\\WINDOWS\\system32\\drivers    -- C:\\WINDOWS\\system32\\drivers
NTSTATUS NtPathToDosPath(PUNICODE_STRING pNtPath, wchar_t* pszDosPath);

HWND CheackProcessHaveWnd(ULONG nPid);
bool RemoteExec(HANDLE process, ULONG nPid, LPVOID address);



extern UCHAR mapInjectShellcode64[120];