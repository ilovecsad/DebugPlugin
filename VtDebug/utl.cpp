#include "utl.h"
#include "util_page_constants.h"
#include "asm.h"
#include "exapi.h"
using MmAllocateContiguousNodeMemoryType =
decltype(MmAllocateContiguousNodeMemory);
static MmAllocateContiguousNodeMemoryType
* g_utilp_MmAllocateContiguousNodeMemory;

namespace Uti
{

    EXTERN_C
    {

        static PhysicalMemoryDescriptor* g_utilp_physical_memory_ranges;
        NTKERNELAPI PVOID NTAPI RtlPcToFileHeader(_In_ PVOID PcValue,
        _Out_ PVOID* BaseOfImage);
        using RtlPcToFileHeaderType = decltype(RtlPcToFileHeader);
        static const auto kUtilpUseRtlPcToFileHeader = false;
        static RtlPcToFileHeaderType* g_utilp_RtlPcToFileHeader;
        static LIST_ENTRY* g_utilp_PsLoadedModuleList;
        /// <summary>
        /// 初始化 页表信息
        /// </summary>
        _IRQL_requires_max_(PASSIVE_LEVEL) static NTSTATUS UtilpInitializePageTableVariables();
        bool UtilIsX86Pae();
        BOOLEAN InitializePageTableBase();

        NTSTATUS UtilpInitializeRtlPcToFileHeader(PDRIVER_OBJECT driver_object);
        // A fake RtlPcToFileHeader without acquiring PsLoadedModuleSpinLock. Thus, it
        // is unsafe and should be updated if we can locate PsLoadedModuleSpinLock.
        //不要再实战使用这个函数
        static PVOID NTAPI UtilpUnsafePcToFileHeader(PVOID pc_value, PVOID* base_of_image);
        _IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS UtilpInitializePhysicalMemoryRanges();
        _IRQL_requires_max_(PASSIVE_LEVEL) static PhysicalMemoryDescriptor* UtilpBuildPhysicalMemoryRanges();

        ULONG64 PTE_BASE = 0;
        ULONG64 PDE_BASE = 0;
        ULONG64 PPE_BASE = 0;
        ULONG64 PXE_BASE = 0;
        static ULONG_PTR g_utilp_pxe_base = 0;
        static ULONG_PTR g_utilp_ppe_base = 0;
        static ULONG_PTR g_utilp_pde_base = 0;
        static ULONG_PTR g_utilp_pte_base = 0;

        static ULONG_PTR g_utilp_pxi_shift = 0;
        static ULONG_PTR g_utilp_ppi_shift = 0;
        static ULONG_PTR g_utilp_pdi_shift = 0;
        static ULONG_PTR g_utilp_pti_shift = 0;

        static ULONG_PTR g_utilp_pxi_mask = 0;
        static ULONG_PTR g_utilp_ppi_mask = 0;
        static ULONG_PTR g_utilp_pdi_mask = 0;
        static ULONG_PTR g_utilp_pti_mask = 0;

        _Use_decl_annotations_ NTSTATUS UtilInitialization(PDRIVER_OBJECT driver_object)
        {
            auto status = STATUS_UNSUCCESSFUL;

            status = UtilpInitializePageTableVariables();
            if (!NT_SUCCESS(status)) {
                Log("[hzw]:UtilpInitializePageTableVariables failed\n");
                return status;
            }
            Log("[hzw]:PXE at %016Ix, PPE at %016Ix, PDE at %016Ix, PTE at %016Ix \n", g_utilp_pxe_base, g_utilp_ppe_base, g_utilp_pde_base, g_utilp_pte_base);
            status = UtilpInitializeRtlPcToFileHeader(driver_object);
            if (!NT_SUCCESS(status)) {
                Log("[hzw]:Init UtilpInitializeRtlPcToFileHeader failed\n");
                return status;
            }
            status = UtilpInitializePhysicalMemoryRanges();
            if (!NT_SUCCESS(status)) {

                Log("[hzw]:UtilpInitializePhysicalMemoryRanges failed\n");
                return status;
            }


            return status;
        }


        NTSTATUS UtilpInitializePhysicalMemoryRanges()
        {
           
            const auto ranges  = UtilpBuildPhysicalMemoryRanges();
            if (!ranges) {
                return STATUS_UNSUCCESSFUL;
            }

            g_utilp_physical_memory_ranges = ranges;

            Log("[hzw]打印系统所有的物理页信息\n");
            for (auto i = 0ul; i < ranges->number_of_runs; ++i) {
                const auto base_addr =
                    static_cast<ULONG64>(ranges->run[i].base_page) * PAGE_SIZE;
                Log("[hzw]Physical Memory Range: %016llx - %016llx \n",
                    base_addr,
                    base_addr + ranges->run[i].page_count * PAGE_SIZE);
            }

            const auto pm_size =
                static_cast<ULONG64>(ranges->number_of_pages) * PAGE_SIZE;
            Log("[hzw]Physical Memory Total: %llu KB \n", pm_size / 1024);

            return STATUS_SUCCESS;
        }

        _Use_decl_annotations_ NTSTATUS UtilpInitializePageTableVariables()
        {
            // Check OS version to know if page table base addresses need to be relocated
            RTL_OSVERSIONINFOW os_version = { sizeof(os_version) };
            auto status = RtlGetVersion(&os_version);
            if (!NT_SUCCESS(status)) {
                return status;
            }

            if (!IsX64() || os_version.dwMajorVersion < 10 ||
                os_version.dwBuildNumber < 14316) {
                if constexpr (IsX64()) {
                    g_utilp_pxe_base = kUtilpPxeBase;
                    g_utilp_ppe_base = kUtilpPpeBase;
                    g_utilp_pxi_shift = kUtilpPxiShift;
                    g_utilp_ppi_shift = kUtilpPpiShift;
                    g_utilp_pxi_mask = kUtilpPxiMask;
                    g_utilp_ppi_mask = kUtilpPpiMask;
                }
                if (UtilIsX86Pae()) {
                    g_utilp_pde_base = kUtilpPdeBasePae;
                    g_utilp_pte_base = kUtilpPteBasePae;
                    g_utilp_pdi_shift = kUtilpPdiShiftPae;
                    g_utilp_pti_shift = kUtilpPtiShiftPae;
                    g_utilp_pdi_mask = kUtilpPdiMaskPae;
                    g_utilp_pti_mask = kUtilpPtiMaskPae;
                }
                else {
                    g_utilp_pde_base = kUtilpPdeBase;
                    g_utilp_pte_base = kUtilpPteBase;
                    g_utilp_pdi_shift = kUtilpPdiShift;
                    g_utilp_pti_shift = kUtilpPtiShift;
                    g_utilp_pdi_mask = kUtilpPdiMask;
                    g_utilp_pti_mask = kUtilpPtiMask;
                }
                return status;
            }

            if (!InitializePageTableBase()) {
                return STATUS_NOT_SUPPORTED;
            }

            g_utilp_pxe_base = static_cast<ULONG_PTR>(PXE_BASE);
            g_utilp_ppe_base = static_cast<ULONG_PTR>(PPE_BASE);
            g_utilp_pde_base = static_cast<ULONG_PTR>(PDE_BASE);
            g_utilp_pte_base = static_cast<ULONG_PTR>(PTE_BASE);

            g_utilp_pxi_shift = kUtilpPxiShift;
            g_utilp_ppi_shift = kUtilpPpiShift;
            g_utilp_pdi_shift = kUtilpPdiShift;
            g_utilp_pti_shift = kUtilpPtiShift;

            g_utilp_pxi_mask = kUtilpPxiMask;
            g_utilp_ppi_mask = kUtilpPpiMask;
            g_utilp_pdi_mask = kUtilpPdiMask;
            g_utilp_pti_mask = kUtilpPtiMask;


            return status;
        }


        // Returns true when a system is on the x86 PAE mode
        /*_Use_decl_annotations_*/ bool UtilIsX86Pae() {
            return (!IsX64() && Cr4 { __readcr4() }.fields.pae);
        }


        BOOLEAN InitializePageTableBase()
        {
            //众所周知windows 10 14316开始实现了页表随机化，之前WRK里给出的#define PTE_BASE 0xFFFFF68000000000h

            int PTESize;
            UINT_PTR PAGE_SIZE_LARGE;
            BOOLEAN bRet = FALSE;

    #ifndef AMD64

    #else
            PTESize = 8; //pae
            PAGE_SIZE_LARGE = 0x200000;
    #endif


            ULONG_PTR PTEBase = 0;
            ULONG_PTR PXEPA = __readcr3() & 0xFFFFFFFFF000;
            PHYSICAL_ADDRESS PXEPAParam;
            PXEPAParam.QuadPart = (LONGLONG)PXEPA;
            ULONG_PTR PXEVA = (ULONG_PTR)MmGetVirtualForPhysical(PXEPAParam); // _MMPTE_HARDWARE 0xffffaed7`6bb5d000
            ULONG_PTR PXEOffset = 0;
            ULONG_PTR slot = 0;
            if (PXEVA)
            {

                do
                {
                    if ((*(PULONGLONG)(PXEVA + PXEOffset) & 0xFFFFFFFFF000) == PXEPA)
                    {
                        PTEBase = (PXEOffset + 0xFFFF000) << 36;
                        break;
                    }
                    PXEOffset += 8;
                    slot++;
                } while (PXEOffset < PAGE_SIZE);
            }


            if (PTEBase) {
                PTE_BASE = PTEBase;
                PDE_BASE = (ULONG_PTR)PTE_BASE + ((__int64)slot << 30);
                PPE_BASE = (ULONG_PTR)PTE_BASE + ((__int64)slot << 30) + ((__int64)slot << 21);
                PXE_BASE = ((ULONG_PTR)PPE_BASE + ((__int64)slot << 12));

                if (PTE_BASE && PDE_BASE && PPE_BASE && PXE_BASE) {
                    bRet = TRUE;
                }

            }

            return bRet;
        }

        NTSTATUS UtilpInitializeRtlPcToFileHeader(PDRIVER_OBJECT driver_object)
        {
            if (kUtilpUseRtlPcToFileHeader) 
            {

                UNICODE_STRING us = RTL_CONSTANT_STRING(L"RtlPcToFileHeader");
               const auto p_RtlPcToFileHeader = MmGetSystemRoutineAddress(&us);
                if (p_RtlPcToFileHeader) {
                    g_utilp_RtlPcToFileHeader =
                        reinterpret_cast<RtlPcToFileHeaderType*>(p_RtlPcToFileHeader);
                    return STATUS_SUCCESS;
                }
            }

    #pragma warning(push)
    #pragma warning(disable : 28175)
            auto module =
                reinterpret_cast<LdrDataTableEntry*>(driver_object->DriverSection);
    #pragma warning(pop)

            g_utilp_PsLoadedModuleList = module->in_load_order_links.Flink;
            g_utilp_RtlPcToFileHeader = UtilpUnsafePcToFileHeader;
            return STATUS_SUCCESS;
        }


        // A fake RtlPcToFileHeader without acquiring PsLoadedModuleSpinLock. Thus, it
       // is unsafe and should be updated if we can locate PsLoadedModuleSpinLock.  很大几率蓝屏
           _Use_decl_annotations_ static PVOID NTAPI UtilpUnsafePcToFileHeader(PVOID pc_value, PVOID* base_of_image)
           {
               if (pc_value < MmSystemRangeStart) {
                   return nullptr;
               }

               const auto head = g_utilp_PsLoadedModuleList;
               for (auto current = head->Flink; current != head; current = current->Flink) {
                   const auto module =
                       CONTAINING_RECORD(current, LdrDataTableEntry, in_load_order_links);
                   const auto driver_end = reinterpret_cast<void*>(
                       reinterpret_cast<ULONG_PTR>(module->dll_base) + module->size_of_image);
                   if (UtilIsInBounds(pc_value, module->dll_base, driver_end)) {
                       *base_of_image = module->dll_base;
                       return module->dll_base;
                   }
               }
               return nullptr;
           }

           // A wrapper of RtlPcToFileHeader
           _Use_decl_annotations_ void* UtilPcToFileHeader(void* pc_value) {
               void* base = nullptr;
               return g_utilp_RtlPcToFileHeader(pc_value, &base);
           }

           static PhysicalMemoryDescriptor* UtilpBuildPhysicalMemoryRanges()
           {
               PAGED_CODE();
               const auto pm_ranges = MmGetPhysicalMemoryRanges();
               if (!pm_ranges) {
                   return nullptr;
               }

               PFN_COUNT number_of_runs = 0;
               PFN_NUMBER number_of_pages = 0;
               for (/**/; /**/; ++number_of_runs) {
                   const auto range = &pm_ranges[number_of_runs];
                   if (!range->BaseAddress.QuadPart && !range->NumberOfBytes.QuadPart) {
                       break;
                   }
                   number_of_pages +=
                       static_cast<PFN_NUMBER>(BYTES_TO_PAGES(range->NumberOfBytes.QuadPart));
               }
               if (number_of_runs == 0) {
                   ExFreePoolWithTag(pm_ranges, 'hPmM');
                   return nullptr;
               }

               const auto memory_block_size =
                   sizeof(PhysicalMemoryDescriptor) +
                   sizeof(PhysicalMemoryRun) * (number_of_runs - 1);
               const auto pm_block =
                   reinterpret_cast<PhysicalMemoryDescriptor*>(ExAllocatePoolWithTag(
                       NonPagedPool, memory_block_size, kHyperPlatformCommonPoolTag));
               if (!pm_block) {
                   ExFreePoolWithTag(pm_ranges, 'hPmM');
                   return nullptr;
               }
               RtlZeroMemory(pm_block, memory_block_size);

               pm_block->number_of_runs = number_of_runs;
               pm_block->number_of_pages = number_of_pages;

               for (auto run_index = 0ul; run_index < number_of_runs; run_index++) {
                   auto current_run = &pm_block->run[run_index];
                   auto current_block = &pm_ranges[run_index];
                   current_run->base_page = static_cast<ULONG_PTR>(
                       UtilPfnFromPa(current_block->BaseAddress.QuadPart));
                   current_run->page_count = static_cast<ULONG_PTR>(
                       BYTES_TO_PAGES(current_block->NumberOfBytes.QuadPart));
               }

               ExFreePoolWithTag(pm_ranges, 'hPmM');
               return pm_block;
           }


           // PA -> PFN
           _Use_decl_annotations_ PFN_NUMBER UtilPfnFromPa(ULONG64 pa) {
               return static_cast<PFN_NUMBER>(pa >> PAGE_SHIFT);
           }
           // VA -> PA
           _Use_decl_annotations_ ULONG64 UtilPaFromVa(_In_ void* va)
           {
               const auto pa = MmGetPhysicalAddress(va);
               return pa.QuadPart;
           }
           // VA -> PFN
           _Use_decl_annotations_ PFN_NUMBER UtilPfnFromVa(void* va) {
               return UtilPfnFromPa(UtilPaFromVa(va));
           }

           // PA -> VA
           _Use_decl_annotations_ void* UtilVaFromPa(ULONG64 pa) {
               PHYSICAL_ADDRESS pa2 = {};
               pa2.QuadPart = pa;
               return MmGetVirtualForPhysical(pa2);
           }

           // PNF -> PA
           _Use_decl_annotations_ ULONG64 UtilPaFromPfn(PFN_NUMBER pfn) {
               return static_cast<ULONG64>(pfn) << PAGE_SHIFT;
           }
           // PFN -> VA
           _Use_decl_annotations_ void* UtilVaFromPfn(PFN_NUMBER pfn) {
               return UtilVaFromPa(UtilPaFromPfn(pfn));
           }


           // Reads 64bit-width MSR
           _Use_decl_annotations_ ULONG64 UtilReadMsr64(Msr msr) {
               return __readmsr(static_cast<unsigned long>(msr));
           }

           // Writes 64bit-width MSR
           _Use_decl_annotations_ void UtilWriteMsr64(Msr msr, ULONG64 value) {
               __writemsr(static_cast<unsigned long>(msr), value);
           }
           // Reads natural-width MSR
           _Use_decl_annotations_ ULONG_PTR UtilReadMsr(Msr msr) {
               return static_cast<ULONG_PTR>(__readmsr(static_cast<unsigned long>(msr)));
           }


           NTSTATUS UtilForEachProcessor(NTSTATUS(*callback_routine)(void*), void* context)
           {
               PAGED_CODE();
               const auto number_of_processors =
                   KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
               for (ULONG processor_index = 0; processor_index < number_of_processors;
                   processor_index++) {
                   PROCESSOR_NUMBER processor_number = {};
                   auto status =
                       KeGetProcessorNumberFromIndex(processor_index, &processor_number);
                   if (!NT_SUCCESS(status)) {
                       return status;
                   }

                   // Switch the current processor
                   GROUP_AFFINITY affinity = {};
                   affinity.Group = processor_number.Group;
                   affinity.Mask = 1ull << processor_number.Number;
                   GROUP_AFFINITY previous_affinity = {};
                   KeSetSystemGroupAffinityThread(&affinity, &previous_affinity);

                   // Execute callback
                   status = callback_routine(context);

                   KeRevertToUserGroupAffinityThread(&previous_affinity);
                   if (!NT_SUCCESS(status)) {
                       return status;
                   }
               }
               return STATUS_SUCCESS;
           }


           // Returns the physical memory ranges
           PhysicalMemoryDescriptor*UtilGetPhysicalMemoryRanges() 
           {
               return g_utilp_physical_memory_ranges;
           }


           // Frees an address allocated by UtilAllocateContiguousMemory()
           _Use_decl_annotations_ void UtilFreeContiguousMemory(void* base_address) {
               MmFreeContiguousMemory(base_address);
           }

           // Allocates continuous physical memory
           _Use_decl_annotations_ void* UtilAllocateContiguousMemory(
               SIZE_T number_of_bytes) {
               PHYSICAL_ADDRESS highest_acceptable_address = {};
               highest_acceptable_address.QuadPart = -1;
               if (g_utilp_MmAllocateContiguousNodeMemory) {
                   // Allocate NX physical memory
                   PHYSICAL_ADDRESS lowest_acceptable_address = {};
                   PHYSICAL_ADDRESS boundary_address_multiple = {};
                   return g_utilp_MmAllocateContiguousNodeMemory(
                       number_of_bytes, lowest_acceptable_address, highest_acceptable_address,
                       boundary_address_multiple, PAGE_READWRITE, MM_ANY_NODE_OK);
               }
               else {
#pragma warning(push)
#pragma warning(disable : 30029)
                   return MmAllocateContiguousMemory(number_of_bytes,
                       highest_acceptable_address);
#pragma warning(pop)
               }
           }



           // Executes the INVEPT instruction and invalidates EPT entry cache
           /*_Use_decl_annotations_*/ VmxStatus UtilInveptGlobal() {
               InvEptDescriptor desc = {};
               return static_cast<VmxStatus>(
                   AsmInvept(InvEptType::kGlobalInvalidation, &desc));
           }

           // Executes the INVVPID instruction (type 2)
           /*_Use_decl_annotations_*/ VmxStatus UtilInvvpidAllContext() {
               InvVpidDescriptor desc = {};
               return static_cast<VmxStatus>(
                   AsmInvvpid(InvVpidType::kAllContextInvalidation, &desc));
           }

           // Reads natural-width VMCS
           ULONG_PTR UtilVmRead(VmcsField field) {
               size_t field_value = 0;
               const auto vmx_status = static_cast<VmxStatus>(
                   __vmx_vmread(static_cast<size_t>(field), &field_value));
               if (vmx_status != VmxStatus::kOk) {
                   HYPERPLATFORM_COMMON_BUG_CHECK( HyperPlatformBugCheck::kCriticalVmxInstructionFailure,static_cast<ULONG_PTR>(vmx_status), static_cast<ULONG_PTR>(field), 0);
               }
               return field_value;
           }


           // Writes natural-width VMCS
           _Use_decl_annotations_ VmxStatus UtilVmWrite(VmcsField field,
               ULONG_PTR field_value) {
               return static_cast<VmxStatus>(
                   __vmx_vmwrite(static_cast<size_t>(field), field_value));
           }

           // Writes 64bit-width VMCS
           _Use_decl_annotations_ VmxStatus UtilVmWrite64(VmcsField field,
               ULONG64 field_value) {
#if defined(_AMD64_)
               return UtilVmWrite(field, field_value);
#else
               // Only 64bit fields should be given on x86 because it access field + 1 too.
               // Also, the field must be even number.
               NT_ASSERT(UtilIsInBounds(field, VmcsField::kIoBitmapA,
                   VmcsField::kHostIa32PerfGlobalCtrlHigh));
               NT_ASSERT((static_cast<ULONG>(field) % 2) == 0);

               ULARGE_INTEGER value64 = {};
               value64.QuadPart = field_value;
               const auto vmx_status = UtilVmWrite(field, value64.LowPart);
               if (vmx_status != VmxStatus::kOk) {
                   return vmx_status;
               }
               return UtilVmWrite(static_cast<VmcsField>(static_cast<ULONG>(field) + 1),
                   value64.HighPart);
#endif
           }

           // Loads the PDPTE registers from CR3 to VMCS
           _Use_decl_annotations_ void UtilLoadPdptes(ULONG_PTR cr3_value) {
               const auto current_cr3 = __readcr3();

               // Have to load cr3 to make UtilPfnFromVa() work properly.
               __writecr3(cr3_value);

               // Gets PDPTEs form CR3
               PdptrRegister pd_pointers[4] = {};
               for (auto i = 0ul; i < 4; ++i) {
                   const auto pd_addr = g_utilp_pde_base + i * PAGE_SIZE;
                   pd_pointers[i].fields.present = true;
                   pd_pointers[i].fields.page_directory_pa =
                       UtilPfnFromVa(reinterpret_cast<void*>(pd_addr));
               }

               __writecr3(current_cr3);
               UtilVmWrite64(VmcsField::kGuestPdptr0, pd_pointers[0].all);
               UtilVmWrite64(VmcsField::kGuestPdptr1, pd_pointers[1].all);
               UtilVmWrite64(VmcsField::kGuestPdptr2, pd_pointers[2].all);
               UtilVmWrite64(VmcsField::kGuestPdptr3, pd_pointers[3].all);
           }

           // Executes VMCALL
           _Use_decl_annotations_ NTSTATUS UtilVmCall(HypercallNumber hypercall_number,void* context,ULONG nMark) 
           {
               __try {
                   const auto vmx_status = static_cast<VmxStatus>(
                       AsmVmxCall(static_cast<ULONG>(hypercall_number), context, nMark));
                   return (vmx_status == VmxStatus::kOk) ? STATUS_SUCCESS
                       : STATUS_UNSUCCESSFUL;

#pragma prefast(suppress : __WARNING_EXCEPTIONEXECUTEHANDLER, "Catch all.");
               }
               __except (EXCEPTION_EXECUTE_HANDLER) {
                   const auto status = GetExceptionCode();
                   HYPERPLATFORM_COMMON_DBG_BREAK();
                   Log("Exception thrown (code %08x)", status);
                   return status;
               }
           }

           // Reads 64bit-width VMCS
           _Use_decl_annotations_ ULONG64 UtilVmRead64(VmcsField field) {
#if defined(_AMD64_)
               return UtilVmRead(field);
#else
               // Only 64bit fields should be given on x86 because it access field + 1 too.
               // Also, the field must be even number.
               NT_ASSERT(UtilIsInBounds(field, VmcsField::kIoBitmapA,
                   VmcsField::kHostIa32PerfGlobalCtrlHigh));
               NT_ASSERT((static_cast<ULONG>(field) % 2) == 0);

               ULARGE_INTEGER value64 = {};
               value64.LowPart = UtilVmRead(field);
               value64.HighPart =
                   UtilVmRead(static_cast<VmcsField>(static_cast<ULONG>(field) + 1));
               return value64.QuadPart;
#endif
           }
           // Executes the INVVPID instruction (type 3)
           _Use_decl_annotations_ VmxStatus
               UtilInvvpidSingleContextExceptGlobal(USHORT vpid) {
               InvVpidDescriptor desc = {};
               desc.vpid = vpid;
               return static_cast<VmxStatus>(AsmInvvpid(InvVpidType::kSingleContextInvalidationExceptGlobal, &desc));
           }

           // Executes the INVVPID instruction (type 0)
           _Use_decl_annotations_ VmxStatus UtilInvvpidIndividualAddress(USHORT vpid,void* address)
           {
               InvVpidDescriptor desc = {};
               desc.vpid = vpid;
               desc.linear_address = reinterpret_cast<ULONG64>(address);
               return static_cast<VmxStatus>(
                   AsmInvvpid(InvVpidType::kIndividualAddressInvalidation, &desc));
           }


           void UtilTermination()
           {
               if (g_utilp_physical_memory_ranges) {
                   ExFreePoolWithTag(g_utilp_physical_memory_ranges,
                       kHyperPlatformCommonPoolTag);
                   g_utilp_physical_memory_ranges = nullptr;
               }

           }
           void Sleep(LONG msec)
           {
               LARGE_INTEGER li;
               li.QuadPart = -10 * 1000;
               li.QuadPart *= msec;
               KeDelayExecutionThread(KernelMode, FALSE, &li);
           }

           HANDLE GetProcessByName(const WCHAR* ProcessName)
           {
               HANDLE hTempHanle = NULL;
               NTSTATUS Status;
               ULONG Bytes;

               ZwQuerySystemInformation(SystemProcessInformation, NULL, NULL, &Bytes);
               PSYSTEM_PROCESS_INFO ProcInfo = (PSYSTEM_PROCESS_INFO)ExAllocatePoolWithTag(NonPagedPool, Bytes, 0);
               if (ProcInfo == NULL)
                   return hTempHanle;

               RtlSecureZeroMemory(ProcInfo, Bytes);

               Status = ZwQuerySystemInformation(SystemProcessInformation, ProcInfo, Bytes, &Bytes);
               if (!NT_SUCCESS(Status))
               {
                   ExFreePoolWithTag(ProcInfo, 0);
                   return hTempHanle;
               }

               UNICODE_STRING ProcessImageName;

               RtlInitUnicodeString(&ProcessImageName, ProcessName);

               for (PSYSTEM_PROCESS_INFO Entry = ProcInfo; Entry->NextEntryOffset != NULL; Entry = (PSYSTEM_PROCESS_INFO)((UCHAR*)Entry + Entry->NextEntryOffset))
               {
                   if (Entry->ImageName.Buffer != NULL)
                   {
                       if (RtlCompareUnicodeString(&Entry->ImageName, &ProcessImageName, TRUE) == 0)
                       {
                           hTempHanle = Entry->ProcessId;
                           break;
                       }
                   }
               }

               ExFreePoolWithTag(ProcInfo, 0);
               return hTempHanle;
           }

           BOOLEAN ProcessHasExited(PEPROCESS process)
           {
               return (process && (PsGetProcessExitStatus(process) == STATUS_PENDING));
           }


           PVOID GetKernelBase(PULONG pImageSize)
           {
               typedef struct _SYSTEM_MODULE_ENTRY
               {
                   HANDLE Section;
                   PVOID MappedBase;
                   PVOID ImageBase;
                   ULONG ImageSize;
                   ULONG Flags;
                   USHORT LoadOrderIndex;
                   USHORT InitOrderIndex;
                   USHORT LoadCount;
                   USHORT OffsetToFileName;
                   UCHAR FullPathName[256];
               } SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

#pragma warning(disable:4200)
               typedef struct _SYSTEM_MODULE_INFORMATION
               {
                   ULONG Count;
                   SYSTEM_MODULE_ENTRY Module[0];
               } SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

               PVOID pModuleBase = NULL;
               PSYSTEM_MODULE_INFORMATION pSystemInfoBuffer = NULL;

               ULONG SystemInfoBufferSize = 0;

               NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation,
                   &SystemInfoBufferSize,
                   0,
                   &SystemInfoBufferSize);

               if (!SystemInfoBufferSize)
               {
                   DbgPrint("[DeugMessage] ZwQuerySystemInformation (1) failed...\r\n");
                   return NULL;
               }

               pSystemInfoBuffer = (PSYSTEM_MODULE_INFORMATION)ExAllocatePool(NonPagedPool, SystemInfoBufferSize * 2);

               if (!pSystemInfoBuffer)
               {
                   DbgPrint("[DeugMessage] ExAllocatePool failed...\r\n");
                   return NULL;
               }

               memset(pSystemInfoBuffer, 0, SystemInfoBufferSize * 2);

               status = ZwQuerySystemInformation(SystemModuleInformation,
                   pSystemInfoBuffer,
                   SystemInfoBufferSize * 2,
                   &SystemInfoBufferSize);

               if (NT_SUCCESS(status))
               {
                   pModuleBase = pSystemInfoBuffer->Module[0].ImageBase;
                   if (pImageSize)
                       *pImageSize = pSystemInfoBuffer->Module[0].ImageSize;
               }
               else
                   DbgPrint("[DeugMessage] ZwQuerySystemInformation (2) failed...\r\n");

               ExFreePool(pSystemInfoBuffer);

               return pModuleBase;
           }


    }
}
