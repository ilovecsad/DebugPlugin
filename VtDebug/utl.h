#pragma once
#include "stl.h"



struct LdrDataTableEntry {
	LIST_ENTRY in_load_order_links;
	LIST_ENTRY in_memory_order_links;
	LIST_ENTRY in_initialization_order_links;
	void* dll_base;
	void* entry_point;
	ULONG size_of_image;
	UNICODE_STRING full_dll_name;
	// ...
};
/// Represents ranges of addresses
struct PhysicalMemoryRun {
	ULONG_PTR base_page;   //!< A base address / PAGE_SIZE (ie, 0x1 for 0x1000)
	ULONG_PTR page_count;  //!< A number of pages
};
#if defined(_AMD64_)
static_assert(sizeof(PhysicalMemoryRun) == 0x10, "Size check");
#else
static_assert(sizeof(PhysicalMemoryRun) == 0x8, "Size check");
#endif

/// Represents a physical memory ranges of the system
struct PhysicalMemoryDescriptor {
	PFN_COUNT number_of_runs;    //!< A number of PhysicalMemoryDescriptor::run
	PFN_NUMBER number_of_pages;  //!< A physical memory size in pages
	PhysicalMemoryRun run[1];    //!< ranges of addresses
};
#if defined(_AMD64_)
static_assert(sizeof(PhysicalMemoryDescriptor) == 0x20, "Size check");
#else
static_assert(sizeof(PhysicalMemoryDescriptor) == 0x10, "Size check");
#endif

/// Indicates a result of VMX-instructions
///
/// This convention was taken from the VMX-intrinsic functions by Microsoft.
enum class VmxStatus : unsigned __int8 {
	kOk = 0,                  //!< Operation succeeded
	kErrorWithStatus = 1,     //!< Operation failed with extended status available
	kErrorWithoutStatus = 2,  //!< Operation failed without status available
};

/// Provides |= operator for VmxStatus
constexpr VmxStatus operator|=(_In_ VmxStatus lhs, _In_ VmxStatus rhs) {
	return static_cast<VmxStatus>(static_cast<unsigned __int8>(lhs) |
		static_cast<unsigned __int8>(rhs));
}

/// Available command numbers for VMCALL
enum class HypercallNumber : unsigned __int32 {
	kTerminateVmm,            //!< Terminates VMM
	kPingVmm,                 //!< Sends ping to the VMM
	kGetSharedProcessorData,  //!< Terminates VMM
	kShEnablePageShadowing,   //!< Calls ShEnablePageShadowing()
	kShDisablePageShadowing,  //!< Calls ShVmCallDisablePageShadowing()
};

////////////////////////////////////////////////////////////////////////////////



namespace Uti
{
	EXTERN_C
	{
	   _IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS UtilInitialization(PDRIVER_OBJECT driver_object);
	   
	   /// <summary>
	   /// 检测这个地址 是否是在内核模块中 请注意这个函数的实现方式 
	   /// </summary>
	   void* UtilPcToFileHeader(_In_ void* address);
	   /// VA -> PA
	   /// @param va   A virtual address to get its physical address
	   /// @return A physical address of \a va, or nullptr
	   ///
	   /// @warning
	   /// It cannot be used for a virtual address managed by a prototype PTE.
	   ULONG64 UtilPaFromVa(_In_ void* va);

	   /// VA -> PFN
	   /// @param va   A virtual address to get its physical address
	   /// @return A page frame number of \a va, or 0
	   ///
	   /// @warning
	   /// It cannot be used for a virtual address managed by a prototype PTE.
	   PFN_NUMBER UtilPfnFromVa(_In_ void* va);

	   /// PA -> PFN
	   /// @param pa   A physical address to get its page frame number
	   /// @return A page frame number of \a pa, or 0
	   PFN_NUMBER UtilPfnFromPa(_In_ ULONG64 pa);

	   /// PA -> VA
	   /// @param pa   A physical address to get its virtual address
	   /// @return A virtual address \a pa, or 0
	   void* UtilVaFromPa(_In_ ULONG64 pa);

	   /// PNF -> PA
	   /// @param pfn   A page frame number to get its physical address
	   /// @return A physical address of \a pfn
	   ULONG64 UtilPaFromPfn(_In_ PFN_NUMBER pfn);

	   /// PNF -> VA
	   /// @param pfn   A page frame number to get its virtual address
	   /// @return A virtual address of \a pfn
	   void* UtilVaFromPfn(_In_ PFN_NUMBER pfn);

	   ULONG64 UtilReadMsr64(Msr msr);

	   /// Writes 64bit-width MSR
       /// @param msr  MSR to write
       /// @param value  A value to write
	   void UtilWriteMsr64(_In_ Msr msr, _In_ ULONG64 value);

	   ULONG_PTR UtilReadMsr(Msr msr);

	   // Execute a given callback routine on all processors in PASSIVE_LEVEL. Returns
       // STATUS_SUCCESS when all callback returned STATUS_SUCCESS as well. When
       // one of callbacks returns anything but STATUS_SUCCESS, this function stops
       // to call remaining callbacks and returns the value.
	   _Use_decl_annotations_ NTSTATUS UtilForEachProcessor(NTSTATUS(*callback_routine)(void*), void* context);

	   void UtilTermination();

	   PhysicalMemoryDescriptor* UtilGetPhysicalMemoryRanges();

	   /// Allocates continuous physical memory
       /// @param number_of_bytes  A size to allocate
       /// @return A base address of an allocated memory or nullptr
       ///
       /// A returned value must be freed with UtilFreeContiguousMemory().
	   _Must_inspect_result_ _IRQL_requires_max_(DISPATCH_LEVEL) void
		   * UtilAllocateContiguousMemory(_In_ SIZE_T number_of_bytes);

	   /// Frees an address allocated by UtilAllocateContiguousMemory()
	   /// @param base_address A return value of UtilAllocateContiguousMemory() to free
	   _IRQL_requires_max_(DISPATCH_LEVEL) void UtilFreeContiguousMemory(
		   _In_ void* base_address);

	   /// Executes the INVEPT instruction and invalidates EPT entry cache
       /// @return A result of the INVEPT instruction
	   VmxStatus UtilInveptGlobal();

	   /// Executes the INVVPID instruction (type 2)
       /// @return A result of the INVVPID instruction
	   VmxStatus UtilInvvpidAllContext();

	   /// Reads natural-width VMCS
       /// @param field  VMCS-field to read
       /// @return read value
	   ULONG_PTR UtilVmRead(_In_ VmcsField field);

	   /// Checks if the system is a PAE-enabled x86 system
       /// @return true if the system is a PAE-enabled x86 system
	   bool UtilIsX86Pae();

	   /// Writes natural-width VMCS
       /// @param field  VMCS-field to write
       /// @param field_value  A value to write
       /// @return A result of the VMWRITE instruction
	   VmxStatus UtilVmWrite(_In_ VmcsField field, _In_ ULONG_PTR field_value);

	   /// Writes 64bit-width VMCS
       /// @param field  VMCS-field to write
       /// @param field_value  A value to write
       /// @return A result of the VMWRITE instruction
	   VmxStatus UtilVmWrite64(_In_ VmcsField field, _In_ ULONG64 field_value);

	   /// Loads the PDPTE registers from CR3 to VMCS
       /// @param cr3_value  CR3 value to retrieve PDPTEs
	   void UtilLoadPdptes(_In_ ULONG_PTR cr3_value);

	   /// Executes VMCALL
       /// @param hypercall_number   A command number
       /// @param context  An arbitrary parameter
       /// @return STATUS_SUCCESS if VMXON instruction succeeded
	   NTSTATUS UtilVmCall(_In_ HypercallNumber hypercall_number,_In_opt_ void* context,ULONG nMark);

	   /// Reads 64bit-width VMCS
       /// @param field  VMCS-field to read
       /// @return read value
	   ULONG64 UtilVmRead64(_In_ VmcsField field);

	   /// Executes the INVVPID instruction (type 3)
       /// @return A result of the INVVPID instruction
	   VmxStatus UtilInvvpidSingleContextExceptGlobal(_In_ USHORT vpid);

	   VmxStatus UtilInvvpidIndividualAddress(USHORT vpid, void* address);

	   void Sleep(LONG msec);
	   HANDLE GetProcessByName(const WCHAR* ProcessName);
	   BOOLEAN ProcessHasExited(PEPROCESS process);
	   PVOID GetKernelBase(PULONG pImageSize);
	}
	
}



/// Tests if \a value is in between \a min and \a max
/// @param value  A value to test
/// @param min  A minimum acceptable value
/// @param max  A maximum acceptable value
/// @return true if \a value is in between \a min and \a max
template <typename T>
constexpr bool UtilIsInBounds(_In_ const T& value, _In_ const T& min,
	_In_ const T& max) {
	return (min <= value) && (value <= max);
}