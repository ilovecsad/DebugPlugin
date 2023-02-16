#include "vm.h"
#include "utl.h"
#include "ept.h"
#include "vmm.h"
#include "stl.h"
#include "asm.h"



EXTERN_C
{

	// Data structure shared across all processors
struct AllProcessorData {
	std::vector<ProcessorData*> data;  // Hold installed hooks
};
bool bInstalled = false;
_IRQL_requires_max_(PASSIVE_LEVEL) bool VmpIsHyperPlatformInstalled();
bool VmpIsVmxAvailable();
_IRQL_requires_max_(PASSIVE_LEVEL) NTSTATUS VmpSetLockBitCallback(_In_opt_ void* context);
_IRQL_requires_max_(PASSIVE_LEVEL) SharedProcessorData* VmpInitializeSharedData();
_IRQL_requires_max_(PASSIVE_LEVEL) void* VmpBuildMsrBitmap();
_IRQL_requires_max_(PASSIVE_LEVEL) UCHAR* VmpBuildIoBitmaps();
_IRQL_requires_max_(PASSIVE_LEVEL) void VmpFreeSharedData(_In_ ProcessorData* processor_data);

_IRQL_requires_max_(PASSIVE_LEVEL) ProcessorData* VmpAllocateProcessorData(SharedProcessorData* shared_data);
_IRQL_requires_max_(PASSIVE_LEVEL)  bool VmpEnterVmxMode(
	_Inout_ ProcessorData* processor_data);
_IRQL_requires_max_(PASSIVE_LEVEL) static void VmpFreeProcessorData(
	_In_opt_ ProcessorData* processor_data);
NTSTATUS VmpStartVm(_In_opt_ void* context);
void VmpInitializeVm(_In_ ULONG_PTR guest_stack_pointer,_In_ ULONG_PTR guest_instruction_pointer, _In_opt_ void* context);
bool VmpInitializeVmcs(_Inout_ ProcessorData* processor_data);
bool VmpSetupVmcs(const ProcessorData* processor_data, ULONG_PTR guest_stack_pointer,ULONG_PTR guest_instruction_pointer, ULONG_PTR vmm_stack_pointer);
void VmpLaunchVm();
ULONG VmpAdjustControlValue(_In_ Msr msr, _In_ ULONG requested_value);
ULONG VmpGetSegmentAccessRight(_In_ USHORT segment_selector);
ULONG_PTR VmpGetSegmentBase(_In_ ULONG_PTR gdt_base, _In_ USHORT segment_selector);
SegmentDescriptor * VmpGetSegmentDescriptor(_In_ ULONG_PTR descriptor_table_base,_In_ USHORT segment_selector);
ULONG_PTR VmpGetSegmentBaseByDescriptor(_In_ const SegmentDescriptor* segment_descriptor);

NTSTATUS VmpStopVm(_In_opt_ void* context)
{
	UNREFERENCED_PARAMETER(context);

	if (!VmpIsHyperPlatformInstalled())return STATUS_SUCCESS;

	Log("Terminating VMX for the processor %lu.",KeGetCurrentProcessorNumberEx(nullptr));

	// Stop virtualization and get an address of the management structure
	ProcessorData* processor_data = nullptr;
	auto status = Uti::UtilVmCall(HypercallNumber::kTerminateVmm, &processor_data, kHyperVCpuidMark);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	// Clear CR4.VMXE, as there is no reason to leave the bit after vmxoff
	Cr4 cr4 = { __readcr4() };
	cr4.fields.vmxe = false;
	__writecr4(cr4.all);

	VmpFreeProcessorData(processor_data);
	return STATUS_SUCCESS;
}


// Returns a base address of segment_descriptor
ULONG_PTR VmpGetSegmentBaseByDescriptor(const SegmentDescriptor* segment_descriptor) 
{
	// Calculate a 32bit base address
	const auto base_high = segment_descriptor->fields.base_high << (6 * 4);
	const auto base_middle = segment_descriptor->fields.base_mid << (4 * 4);
	const auto base_low = segment_descriptor->fields.base_low;
	ULONG_PTR base = (base_high | base_middle | base_low) & MAXULONG;
	// Get upper 32bit of the base address if needed
	if (IsX64() && !segment_descriptor->fields.system) {
		auto desc64 =
			reinterpret_cast<const SegmentDesctiptorX64*>(segment_descriptor);
		ULONG64 base_upper32 = desc64->base_upper32;
		base |= (base_upper32 << 32);
	}
	return base;
}
// Returns the segment descriptor corresponds to the SegmentSelector
SegmentDescriptor* VmpGetSegmentDescriptor(ULONG_PTR descriptor_table_base, USHORT segment_selector) 
{
	const SegmentSelector ss = { segment_selector };
	return reinterpret_cast<SegmentDescriptor*>(
		descriptor_table_base + ss.fields.index * sizeof(SegmentDescriptor));
}
// Returns a base address of the segment specified by SegmentSelector
ULONG_PTR VmpGetSegmentBase(ULONG_PTR gdt_base, USHORT segment_selector) 
{
	const SegmentSelector ss = { segment_selector };
	if (!ss.all) {
		return 0;
	}
	if (ss.fields.ti) {
		const auto local_segment_descriptor =
			VmpGetSegmentDescriptor(gdt_base, AsmReadLDTR());
		const auto ldt_base =
			VmpGetSegmentBaseByDescriptor(local_segment_descriptor);
		const auto segment_descriptor =
			VmpGetSegmentDescriptor(ldt_base, segment_selector);
		return VmpGetSegmentBaseByDescriptor(segment_descriptor);
	}
	else {
		const auto segment_descriptor =
			VmpGetSegmentDescriptor(gdt_base, segment_selector);
		return VmpGetSegmentBaseByDescriptor(segment_descriptor);
	}
}
ULONG VmpGetSegmentAccessRight(_In_ USHORT segment_selector)
{
	VmxRegmentDescriptorAccessRight access_right = {};
	if (segment_selector) {
		const SegmentSelector ss = { segment_selector };
		auto native_access_right = AsmLoadAccessRightsByte(ss.all);
		native_access_right >>= 8;
		access_right.all = static_cast<ULONG>(native_access_right);
		access_right.fields.reserved1 = 0;
		access_right.fields.reserved2 = 0;
		access_right.fields.unusable = false;
	}
	else {
		access_right.fields.unusable = true;
	}
	return access_right.all;
}



// Adjust the requested control value with consulting a value of related MSR
ULONG VmpAdjustControlValue(Msr msr, ULONG requested_value) 
{
	LARGE_INTEGER msr_value = {};
	msr_value.QuadPart = Uti::UtilReadMsr64(msr);
	auto adjusted_value = requested_value;

	// bit == 0 in high word ==> must be zero
	adjusted_value &= msr_value.HighPart;
	// bit == 1 in low word  ==> must be one
	adjusted_value |= msr_value.LowPart;
	return adjusted_value;
}
// Executes vmlaunch
void VmpLaunchVm() 
{
	auto error_code = Uti::UtilVmRead(VmcsField::kVmInstructionError);
	if (error_code) {
		Log("VM_INSTRUCTION_ERROR = %Iu", error_code);
	}

	auto vmx_status = static_cast<VmxStatus>(__vmx_vmlaunch());

	// Here should not executed with successful vmlaunch. Instead, the context
	// jumps to an address specified by GUEST_RIP.
	if (vmx_status == VmxStatus::kErrorWithStatus) {
		error_code = Uti::UtilVmRead(VmcsField::kVmInstructionError);
		/*
          1 VMCALL executed in VMX root operation
          2 VMCLEAR with invalid physical address
          3 VMCLEAR with VMXON pointer
          4 VMLAUNCH with non-clear VMCS
          5 VMRESUME with non-launched VMCS
          6 VMRESUME after VMXOFF (VMXOFF and VMXON between VMLAUNCH and VMRESUME)1
		  7 VM entry with invalid control field(s)2,3
		  8 VM entry with invalid host-state field(s)2
          9 VMPTRLD with invalid physical address
          10 VMPTRLD with VMXON pointer
          11 VMPTRLD with incorrect VMCS revision identifier
          12 VMREAD/VMWRITE from/to unsupported VMCS component
          13 VMWRITE to read-only VMCS component
		  15 VMXON executed in VMX root operation
          16 VM entry with invalid executive-VMCS pointer2
          17 VM entry with non-launched executive VMCS2
          18 VM entry with executive-VMCS pointer not VMXON pointer (when attempting to deactivate the dual-monitor treatment of SMIs and SMM)2
          19 VMCALL with non-clear VMCS (when attempting to activate the dual-monitor treatment of SMIs and SMM)
          20 VMCALL with invalid VM-exit control fields
          22 VMCALL with incorrect MSEG revision identifier (when attempting to activate the dual-monitor treatment of SMIs and SMM)
          23 VMXOFF under dual-monitor treatment of SMIs and SMM
          24 VMCALL with invalid SMM-monitor features (when attempting to activate the dual-monitor treatment of SMIs and SMM)
          25 VM entry with invalid VM-execution control fields in executive VMCS (when attempting to return from SMM)2,3
          26 VM entry with events blocked by MOV SS.
          28 Invalid operand to INVEPT/INVVPID.
		*/
		Log("VM_INSTRUCTION_ERROR = %Iu", error_code);
	}
	HYPERPLATFORM_COMMON_DBG_BREAK();
}

bool VmpSetupVmcs(const ProcessorData* processor_data, ULONG_PTR guest_stack_pointer, ULONG_PTR guest_instruction_pointer, ULONG_PTR vmm_stack_pointer)
{

	Gdtr gdtr = {};
	_sgdt(&gdtr);

	Idtr idtr = {};
	__sidt(&idtr);

	// See: Algorithms for Determining VMX Capabilities
	const auto use_true_msrs = Ia32VmxBasicMsr{ Uti::UtilReadMsr64(Msr::kIa32VmxBasic) }.fields.vmx_capability_hint;


	VmxVmEntryControls vm_entryctl_requested = {};
	
	vm_entryctl_requested.fields.load_debug_controls = true;
	vm_entryctl_requested.fields.ia32e_mode_guest = IsX64();
	

	VmxVmEntryControls vm_entryctl = { VmpAdjustControlValue(
		(use_true_msrs) ? Msr::kIa32VmxTrueEntryCtls : Msr::kIa32VmxEntryCtls,
		vm_entryctl_requested.all) };

	VmxVmExitControls vm_exitctl_requested = {};

	vm_exitctl_requested.fields.acknowledge_interrupt_on_exit = true;
	vm_exitctl_requested.fields.host_address_space_size = IsX64();
	

	VmxVmExitControls vm_exitctl = { VmpAdjustControlValue(
		(use_true_msrs) ? Msr::kIa32VmxTrueExitCtls : Msr::kIa32VmxExitCtls,
		vm_exitctl_requested.all) };


	VmxPinBasedControls vm_pinctl_requested = {};
	VmxPinBasedControls vm_pinctl = {
		VmpAdjustControlValue((use_true_msrs) ? Msr::kIa32VmxTruePinbasedCtls
											  : Msr::kIa32VmxPinbasedCtls,
							  vm_pinctl_requested.all) };

	VmxProcessorBasedControls vm_procctl_requested = {};
	
	vm_procctl_requested.fields.cr3_load_exiting = true;
	vm_procctl_requested.fields.mov_dr_exiting = true;
	vm_procctl_requested.fields.use_io_bitmaps = true; 
	vm_procctl_requested.fields.use_msr_bitmaps = true;//https://www.cnblogs.com/onetrainee/p/13590000.html ① 开启虚拟机控制字段：VM-execution control[28] 置为1时，则开启 MSR BitMap;
	vm_procctl_requested.fields.activate_secondary_control = true; //win10必须开启 因为开启vmm后必须 处理某些指令
	
	VmxProcessorBasedControls vm_procctl = {
		VmpAdjustControlValue((use_true_msrs) ? Msr::kIa32VmxTrueProcBasedCtls
											  : Msr::kIa32VmxProcBasedCtls,
							  vm_procctl_requested.all) };

	VmxSecondaryProcessorBasedControls vm_procctl2_requested = {};
	
   // vm_procctl2_requested.fields.descriptor_table_exiting = true;//开火绒 cpu复位 这个代码应该有问题-2023.2.10
	vm_procctl2_requested.fields.enable_ept = true;
	vm_procctl2_requested.fields.enable_vpid = true;            //
	vm_procctl2_requested.fields.enable_rdtscp = true;         // for Win10 
	vm_procctl2_requested.fields.enable_invpcid = true;        // for Win10  异常回调没有处理，但是如果不置1 会蓝屏
	vm_procctl2_requested.fields.enable_xsaves_xstors = true;  // for Win10 
	
	VmxSecondaryProcessorBasedControls vm_procctl2 = { VmpAdjustControlValue(
		Msr::kIa32VmxProcBasedCtls2, vm_procctl2_requested.all) };

	Log("VmEntryControls                  = %08x\n",
		vm_entryctl.all);
	Log("VmExitControls                   = %08x\n",
		vm_exitctl.all);
	Log("PinBasedControls                 = %08x\n",
		vm_pinctl.all);
	Log("ProcessorBasedControls           = %08x\n",
		vm_procctl.all);
	Log("SecondaryProcessorBasedControls  = %08x\n",
		vm_procctl2.all);

	// NOTE: Comment in any of those as needed https://www.cnblogs.com/onetrainee/p/13582705.html

   // * 24.6.3 Exception Bitmap 
  //异常位图是一个32位字段，其中每个异常对应一位。 发生异常时，其向量会选择该字段中的一个位。 如果该位为1，则异常导致VM退出。
  //如果该位为0，通过IDT传递异常， 该异常使用对应的异常向量描述符。
  //页错误（矢量14的异常）是否导致VM退出， 由异常位图中的第14位 以及由缺页错误产生的错误码和VMCS中的两个32位字段（页错误- 错误码掩码和页错误错误码匹配）。
  //有关详细信息，请参见第25.2节。

	const auto exception_bitmap =
		1 << InterruptionVector::kBreakpointException |
		// 1 << InterruptionVector::kGeneralProtectionException |
		// 1 << InterruptionVector::kPageFaultException |
		0;



	// Set up CR0 and CR4 bitmaps
	// - Where a bit is     masked, the shadow bit appears
	// - Where a bit is not masked, the actual bit appears
	// VM-exit occurs when a guest modifies any of those fields
	Cr0 cr0_mask = {};
	Cr0 cr0_shadow = { __readcr0() };

	Cr4 cr4_mask = {};
	Cr4 cr4_shadow = { __readcr4() };
	// For example, when we want to hide CR4.VMXE from the guest, comment in below
	// cr4_mask.fields.vmxe = true;
	// cr4_shadow.fields.vmxe = false;

	// See: PDPTE Registers
	// If PAE paging would be in use following an execution of MOV to CR0 or MOV
	// to CR4 (see Section 4.1.1) and the instruction is modifying any of CR0.CD,
	// CR0.NW, CR0.PG, CR4.PAE, CR4.PGE, CR4.PSE, or CR4.SMEP; then the PDPTEs are
	// loaded from the address in CR3.
	if (Uti::UtilIsX86Pae()) {
		cr0_mask.fields.pg = true;
		cr0_mask.fields.cd = true;
		cr0_mask.fields.nw = true;
		cr4_mask.fields.pae = true;
		cr4_mask.fields.pge = true;
		cr4_mask.fields.pse = true;
		cr4_mask.fields.smep = true;
	}

	// clang-format off
	auto error = VmxStatus::kOk;

	/* 16-Bit Control Field */
	error |= Uti::UtilVmWrite(VmcsField::kVirtualProcessorId, KeGetCurrentProcessorNumberEx(nullptr) + 1);

	/* 16-Bit Guest-State Fields */
	error |= Uti::UtilVmWrite(VmcsField::kGuestEsSelector, AsmReadES());
	error |= Uti::UtilVmWrite(VmcsField::kGuestCsSelector, AsmReadCS());
	error |= Uti::UtilVmWrite(VmcsField::kGuestSsSelector, AsmReadSS());
	error |= Uti::UtilVmWrite(VmcsField::kGuestDsSelector, AsmReadDS());
	error |= Uti::UtilVmWrite(VmcsField::kGuestFsSelector, AsmReadFS());
	error |= Uti::UtilVmWrite(VmcsField::kGuestGsSelector, AsmReadGS());
	error |= Uti::UtilVmWrite(VmcsField::kGuestLdtrSelector, AsmReadLDTR());
	error |= Uti::UtilVmWrite(VmcsField::kGuestTrSelector, AsmReadTR());

	/* 16-Bit Host-State Fields */
	// RPL and TI have to be 0
	error |= Uti::UtilVmWrite(VmcsField::kHostEsSelector, AsmReadES() & 0xf8);
	error |= Uti::UtilVmWrite(VmcsField::kHostCsSelector, AsmReadCS() & 0xf8);
	error |= Uti::UtilVmWrite(VmcsField::kHostSsSelector, AsmReadSS() & 0xf8);
	error |= Uti::UtilVmWrite(VmcsField::kHostDsSelector, AsmReadDS() & 0xf8);
	error |= Uti::UtilVmWrite(VmcsField::kHostFsSelector, AsmReadFS() & 0xf8);
	error |= Uti::UtilVmWrite(VmcsField::kHostGsSelector, AsmReadGS() & 0xf8);
	error |= Uti::UtilVmWrite(VmcsField::kHostTrSelector, AsmReadTR() & 0xf8);

	/* 64-Bit Control Fields */
	error |= Uti::UtilVmWrite64(VmcsField::kIoBitmapA, Uti::UtilPaFromVa(processor_data->shared_data->io_bitmap_a));
	error |= Uti::UtilVmWrite64(VmcsField::kIoBitmapB, Uti::UtilPaFromVa(processor_data->shared_data->io_bitmap_b));
	error |= Uti::UtilVmWrite64(VmcsField::kMsrBitmap, Uti::UtilPaFromVa(processor_data->shared_data->msr_bitmap));
	error |= Uti::UtilVmWrite64(VmcsField::kEptPointer, ept::EptGetEptPointer(processor_data->ept_data));

	/* 64-Bit Guest-State Fields */
	error |= Uti::UtilVmWrite64(VmcsField::kVmcsLinkPointer, MAXULONG64);
	error |= Uti::UtilVmWrite64(VmcsField::kGuestIa32Debugctl, Uti::UtilReadMsr64(Msr::kIa32Debugctl));
	if (Uti::UtilIsX86Pae()) {
		Uti::UtilLoadPdptes(__readcr3());
	}

	/* 32-Bit Control Fields */
	error |= Uti::UtilVmWrite(VmcsField::kPinBasedVmExecControl, vm_pinctl.all);
	error |= Uti::UtilVmWrite(VmcsField::kCpuBasedVmExecControl, vm_procctl.all);
	error |= Uti::UtilVmWrite(VmcsField::kExceptionBitmap, exception_bitmap);
	error |= Uti::UtilVmWrite(VmcsField::kVmExitControls, vm_exitctl.all);  
	error |= Uti::UtilVmWrite(VmcsField::kVmEntryControls, vm_entryctl.all);
	error |= Uti::UtilVmWrite(VmcsField::kSecondaryVmExecControl, vm_procctl2.all);

	/* 32-Bit Guest-State Fields */
	error |= Uti::UtilVmWrite(VmcsField::kGuestEsLimit, GetSegmentLimit(AsmReadES()));
	error |= Uti::UtilVmWrite(VmcsField::kGuestCsLimit, GetSegmentLimit(AsmReadCS()));
	error |= Uti::UtilVmWrite(VmcsField::kGuestSsLimit, GetSegmentLimit(AsmReadSS()));
	error |= Uti::UtilVmWrite(VmcsField::kGuestDsLimit, GetSegmentLimit(AsmReadDS()));
	error |= Uti::UtilVmWrite(VmcsField::kGuestFsLimit, GetSegmentLimit(AsmReadFS()));
	error |= Uti::UtilVmWrite(VmcsField::kGuestGsLimit, GetSegmentLimit(AsmReadGS()));
	error |= Uti::UtilVmWrite(VmcsField::kGuestLdtrLimit, GetSegmentLimit(AsmReadLDTR()));
	error |= Uti::UtilVmWrite(VmcsField::kGuestTrLimit, GetSegmentLimit(AsmReadTR()));
	error |= Uti::UtilVmWrite(VmcsField::kGuestGdtrLimit, gdtr.limit);
	error |= Uti::UtilVmWrite(VmcsField::kGuestIdtrLimit, idtr.limit);
	error |= Uti::UtilVmWrite(VmcsField::kGuestEsArBytes, VmpGetSegmentAccessRight(AsmReadES()));
	error |= Uti::UtilVmWrite(VmcsField::kGuestCsArBytes, VmpGetSegmentAccessRight(AsmReadCS()));
	error |= Uti::UtilVmWrite(VmcsField::kGuestSsArBytes, VmpGetSegmentAccessRight(AsmReadSS()));
	error |= Uti::UtilVmWrite(VmcsField::kGuestDsArBytes, VmpGetSegmentAccessRight(AsmReadDS()));
	error |= Uti::UtilVmWrite(VmcsField::kGuestFsArBytes, VmpGetSegmentAccessRight(AsmReadFS()));
	error |= Uti::UtilVmWrite(VmcsField::kGuestGsArBytes, VmpGetSegmentAccessRight(AsmReadGS()));
	error |= Uti::UtilVmWrite(VmcsField::kGuestLdtrArBytes, VmpGetSegmentAccessRight(AsmReadLDTR()));
	error |= Uti::UtilVmWrite(VmcsField::kGuestTrArBytes, VmpGetSegmentAccessRight(AsmReadTR()));
	error |= Uti::UtilVmWrite(VmcsField::kGuestSysenterCs, Uti::UtilReadMsr(Msr::kIa32SysenterCs));

	/* 32-Bit Host-State Field */
	error |= Uti::UtilVmWrite(VmcsField::kHostIa32SysenterCs, Uti::UtilReadMsr(Msr::kIa32SysenterCs));

	/* Natural-Width Control Fields */
	error |= Uti::UtilVmWrite(VmcsField::kCr0GuestHostMask, cr0_mask.all);
	error |= Uti::UtilVmWrite(VmcsField::kCr4GuestHostMask, cr4_mask.all);
	error |= Uti::UtilVmWrite(VmcsField::kCr0ReadShadow, cr0_shadow.all);
	error |= Uti::UtilVmWrite(VmcsField::kCr4ReadShadow, cr4_shadow.all);

	/* Natural-Width Guest-State Fields */
	error |= Uti::UtilVmWrite(VmcsField::kGuestCr0, __readcr0());
	error |= Uti::UtilVmWrite(VmcsField::kGuestCr3, __readcr3());
	error |= Uti::UtilVmWrite(VmcsField::kGuestCr4, __readcr4());
#if defined(_AMD64_)
	error |= Uti::UtilVmWrite(VmcsField::kGuestEsBase, 0);
	error |= Uti::UtilVmWrite(VmcsField::kGuestCsBase, 0);
	error |= Uti::UtilVmWrite(VmcsField::kGuestSsBase, 0);
	error |= Uti::UtilVmWrite(VmcsField::kGuestDsBase, 0);
	error |= Uti::UtilVmWrite(VmcsField::kGuestFsBase, Uti::UtilReadMsr(Msr::kIa32FsBase));
	error |= Uti::UtilVmWrite(VmcsField::kGuestGsBase, Uti::UtilReadMsr(Msr::kIa32GsBase));
#else
	error |= Uti::UtilVmWrite(VmcsField::kGuestEsBase, VmpGetSegmentBase(gdtr.base, AsmReadES()));
	error |= Uti::UtilVmWrite(VmcsField::kGuestCsBase, VmpGetSegmentBase(gdtr.base, AsmReadCS()));
	error |= Uti::UtilVmWrite(VmcsField::kGuestSsBase, VmpGetSegmentBase(gdtr.base, AsmReadSS()));
	error |= Uti::UtilVmWrite(VmcsField::kGuestDsBase, VmpGetSegmentBase(gdtr.base, AsmReadDS()));
	error |= Uti::UtilVmWrite(VmcsField::kGuestFsBase, VmpGetSegmentBase(gdtr.base, AsmReadFS()));
	error |= Uti::UtilVmWrite(VmcsField::kGuestGsBase, VmpGetSegmentBase(gdtr.base, AsmReadGS()));
#endif
	error |= Uti::UtilVmWrite(VmcsField::kGuestLdtrBase, VmpGetSegmentBase(gdtr.base, AsmReadLDTR()));
	error |= Uti::UtilVmWrite(VmcsField::kGuestTrBase, VmpGetSegmentBase(gdtr.base, AsmReadTR()));
	error |= Uti::UtilVmWrite(VmcsField::kGuestGdtrBase, gdtr.base);
	error |= Uti::UtilVmWrite(VmcsField::kGuestIdtrBase, idtr.base);
	error |= Uti::UtilVmWrite(VmcsField::kGuestDr7, __readdr(7));
	error |= Uti::UtilVmWrite(VmcsField::kGuestRsp, guest_stack_pointer);
	error |= Uti::UtilVmWrite(VmcsField::kGuestRip, guest_instruction_pointer);
	error |= Uti::UtilVmWrite(VmcsField::kGuestRflags, __readeflags());
	error |= Uti::UtilVmWrite(VmcsField::kGuestSysenterEsp, Uti::UtilReadMsr(Msr::kIa32SysenterEsp));
	error |= Uti::UtilVmWrite(VmcsField::kGuestSysenterEip, Uti::UtilReadMsr(Msr::kIa32SysenterEip));

	/* Natural-Width Host-State Fields */
	error |= Uti::UtilVmWrite(VmcsField::kHostCr0, __readcr0());
	error |= Uti::UtilVmWrite(VmcsField::kHostCr3, __readcr3());
	error |= Uti::UtilVmWrite(VmcsField::kHostCr4, __readcr4());
#if defined(_AMD64_)
	error |= Uti::UtilVmWrite(VmcsField::kHostFsBase, Uti::UtilReadMsr(Msr::kIa32FsBase));
	error |= Uti::UtilVmWrite(VmcsField::kHostGsBase, Uti::UtilReadMsr(Msr::kIa32GsBase));
#else
	error |= UtilVmWrite(VmcsField::kHostFsBase, VmpGetSegmentBase(gdtr.base, AsmReadFS()));
	error |= UtilVmWrite(VmcsField::kHostGsBase, VmpGetSegmentBase(gdtr.base, AsmReadGS()));
#endif
	error |= Uti::UtilVmWrite(VmcsField::kHostTrBase, VmpGetSegmentBase(gdtr.base, AsmReadTR()));
	error |= Uti::UtilVmWrite(VmcsField::kHostGdtrBase, gdtr.base);
	error |= Uti::UtilVmWrite(VmcsField::kHostIdtrBase, idtr.base);
	error |= Uti::UtilVmWrite(VmcsField::kHostIa32SysenterEsp, Uti::UtilReadMsr(Msr::kIa32SysenterEsp));
	error |= Uti::UtilVmWrite(VmcsField::kHostIa32SysenterEip, Uti::UtilReadMsr(Msr::kIa32SysenterEip));
	error |= Uti::UtilVmWrite(VmcsField::kHostRsp, vmm_stack_pointer);
	error |= Uti::UtilVmWrite(VmcsField::kHostRip, reinterpret_cast<ULONG_PTR>(AsmVmmEntryPoint));
	// clang-format on

	const auto vmx_status = static_cast<VmxStatus>(error);
	return vmx_status == VmxStatus::kOk;

}

bool VmpInitializeVmcs(_Inout_ ProcessorData* processor_data)
{
	// Write a VMCS revision identifier
	const Ia32VmxBasicMsr vmx_basic_msr = { Uti::UtilReadMsr64(Msr::kIa32VmxBasic) };
	processor_data->vmcs_region->revision_identifier = vmx_basic_msr.fields.revision_identifier;

	auto vmcs_region_pa = Uti::UtilPaFromVa(processor_data->vmcs_region);
	if (__vmx_vmclear(&vmcs_region_pa)) {
		return false;
	}
	if (__vmx_vmptrld(&vmcs_region_pa)) {
		return false;
	}

	// The launch state of current VMCS is "clear"
	return true;
}

void VmpInitializeVm(_In_ ULONG_PTR guest_stack_pointer, _In_ ULONG_PTR guest_instruction_pointer, _In_opt_ void* context)
{
	PAGED_CODE();
	if (VmpIsHyperPlatformInstalled())return;
	const auto shared_data = reinterpret_cast<SharedProcessorData*>(context);
	if (!shared_data) {
		return;
	}

	const auto processor_data = VmpAllocateProcessorData(shared_data);
	if (!processor_data) {
		return;
	}


	Log("CPU[%lu] processor_data:%llx \n", KeGetCurrentProcessorNumberEx(nullptr), processor_data);

	const auto vmm_stack_base = reinterpret_cast<ULONG_PTR>(processor_data->vmm_stack_limit) + KERNEL_STACK_SIZE - sizeof(void*) * 2;

	// Set up VMCS
	if (!VmpEnterVmxMode(processor_data)) {
		
		goto __exit;
	}

	if (!VmpInitializeVmcs(processor_data)) {
		goto __exit;
	}
	if (!VmpSetupVmcs(processor_data, guest_stack_pointer,
		guest_instruction_pointer, vmm_stack_base)) {
		goto __exit;
	}


	// Do virtualize the processor
	VmpLaunchVm();

	// Here is not be executed with successful vmlaunch. Instead, the context
	// jumps to an address specified by guest_instruction_pointer.

__exit:
	__vmx_off();
	VmpFreeProcessorData(processor_data);


}


NTSTATUS VmpStartVm(_In_opt_ void* context)
{

	Log("Initializing VMX for the processor %lu.\n",KeGetCurrentProcessorNumberEx(nullptr));
	const auto ok = AsmInitializeVm(VmpInitializeVm, context);
	NT_ASSERT(VmpIsHyperPlatformInstalled() == ok);
	if (!ok) {
		return STATUS_UNSUCCESSFUL;
	}
	Log("Initialized successfully.\n");
	return STATUS_SUCCESS;
}


// See: VMM SETUP & TEAR DOWN
_Use_decl_annotations_  bool VmpEnterVmxMode(ProcessorData* processor_data) 
{
	//参考第三章 24.8 可知 如果不修复这个寄存器 可能 __vmx_on 会失败
	// Apply FIXED bits
	// See: VMX-FIXED BITS IN CR0

	//        IA32_VMX_CRx_FIXED0 IA32_VMX_CRx_FIXED1 Meaning
	// Values 1                   *                   bit of CRx is fixed to 1
	// Values 0                   1                   bit of CRx is flexible
	// Values *                   0                   bit of CRx is fixed to 0
	const Cr0 cr0_fixed0 = { Uti::UtilReadMsr(Msr::kIa32VmxCr0Fixed0) };
	const Cr0 cr0_fixed1 = { Uti::UtilReadMsr(Msr::kIa32VmxCr0Fixed1) };
	Cr0 cr0 = { __readcr0() };
	Cr0 cr0_original = cr0;
	cr0.all &= cr0_fixed1.all;
	cr0.all |= cr0_fixed0.all;
	__writecr0(cr0.all);

	Log("IA32_VMX_CR0_FIXED0   = %08Ix \n", cr0_fixed0.all);
	Log("IA32_VMX_CR0_FIXED1   = %08Ix \n", cr0_fixed1.all);
	Log("Original CR0          = %08Ix \n", cr0_original.all);
	Log("Fixed CR0             = %08Ix \n", cr0.all);

	// See: VMX-FIXED BITS IN CR4
	const Cr4 cr4_fixed0 = { Uti::UtilReadMsr(Msr::kIa32VmxCr4Fixed0) };
	const Cr4 cr4_fixed1 = { Uti::UtilReadMsr(Msr::kIa32VmxCr4Fixed1) };
	Cr4 cr4 = { __readcr4() };
	Cr4 cr4_original = cr4;
	cr4.all &= cr4_fixed1.all;
	cr4.all |= cr4_fixed0.all;
	__writecr4(cr4.all);

	Log("IA32_VMX_CR4_FIXED0   = %08Ix \n", cr4_fixed0.all);
	Log("IA32_VMX_CR4_FIXED1   = %08Ix \n", cr4_fixed1.all);
	Log("Original CR4          = %08Ix \n", cr4_original.all);
	Log("Fixed CR4             = %08Ix \n", cr4.all);

	// Write a VMCS revision identifier
	const Ia32VmxBasicMsr vmx_basic_msr = { Uti::UtilReadMsr64(Msr::kIa32VmxBasic) };
	processor_data->vmxon_region->revision_identifier =
		vmx_basic_msr.fields.revision_identifier;

	auto vmxon_region_pa = Uti::UtilPaFromVa(processor_data->vmxon_region);
	if (__vmx_on(&vmxon_region_pa)) {
		return false;
	}

	// See: Guidelines for Use of the INVVPID Instruction, and Guidelines for Use
	// of the INVEPT Instruction
	Uti::UtilInveptGlobal(); // capability.fields.support_all_context_invept == 1
	Uti::UtilInvvpidAllContext(); //capability.fields.support_all_context_invvpid == 1
	return true;
}


// Frees all related memory
_Use_decl_annotations_ static void VmpFreeProcessorData(
	ProcessorData* processor_data) {


	if (!processor_data) {
		return;
	}
	if (processor_data->vmm_stack_limit) {
		Uti::UtilFreeContiguousMemory(processor_data->vmm_stack_limit);
	}
	if (processor_data->vmcs_region) {
		ExFreePoolWithTag(processor_data->vmcs_region, kHyperPlatformCommonPoolTag);
	}
	if (processor_data->vmxon_region) {
		ExFreePoolWithTag(processor_data->vmxon_region,
			kHyperPlatformCommonPoolTag);
	}
	//if (processor_data->sh_data) {
	//	ShFreeShadowHookData(processor_data->sh_data);
	//}
	if (processor_data->ept_data) {
		ept::EptTermination(processor_data->ept_data);
	}

	VmpFreeSharedData(processor_data);

	ExFreePoolWithTag(processor_data, kHyperPlatformCommonPoolTag);
}

ProcessorData* VmpAllocateProcessorData(SharedProcessorData* shared_data)
{
	PAGED_CODE();
	if (!shared_data)return nullptr;

	// Allocate related structures
	const auto processor_data =
		reinterpret_cast<ProcessorData*>(ExAllocatePoolWithTag(
			NonPagedPool, sizeof(ProcessorData), kHyperPlatformCommonPoolTag));
	if (!processor_data) {
		return nullptr;
	}
	RtlZeroMemory(processor_data, sizeof(ProcessorData));
	processor_data->shared_data = shared_data;
	InterlockedIncrement(&processor_data->shared_data->reference_count);

	// Set up EPT
	processor_data->ept_data = ept::EptInitialization();
	if (!processor_data->ept_data) {
		VmpFreeProcessorData(processor_data);
		return nullptr;
	}

	
	/*
	processor_data->sh_data = ShAllocateShadowHookData();
    if (!processor_data->sh_data) {
      VmpFreeProcessorData(processor_data);
      return;
    }
	*/

	// Allocate other processor data fields
	processor_data->vmm_stack_limit =
		Uti::UtilAllocateContiguousMemory(KERNEL_STACK_SIZE);
	if (!processor_data->vmm_stack_limit) {
		VmpFreeProcessorData(processor_data);
		return nullptr;
	}
	RtlZeroMemory(processor_data->vmm_stack_limit, KERNEL_STACK_SIZE);

	processor_data->vmcs_region =
		reinterpret_cast<VmControlStructure*>(ExAllocatePoolWithTag(
			NonPagedPool, kVmxMaxVmcsSize, kHyperPlatformCommonPoolTag));
	if (!processor_data->vmcs_region) {
		VmpFreeProcessorData(processor_data);
		return nullptr;
	}
	RtlZeroMemory(processor_data->vmcs_region, kVmxMaxVmcsSize);

	processor_data->vmxon_region =
		reinterpret_cast<VmControlStructure*>(ExAllocatePoolWithTag(
			NonPagedPool, kVmxMaxVmcsSize, kHyperPlatformCommonPoolTag));
	if (!processor_data->vmxon_region) {
		VmpFreeProcessorData(processor_data);
		return nullptr;
	}
	RtlZeroMemory(processor_data->vmxon_region, kVmxMaxVmcsSize);

	// Initialize stack memory for VMM like this:
/*（low）                                               <- vmm_stack_limit
* 
* 
	0x000001F2CA135E70  01 00 00 00 00 00 00 00 <-Xmm0
	0x000001F2CA135E78  01 00 00 00 00 00 00 00 
	
	0x000001F2CA135E80  ff ff ff ff ff ff ff ff <-Xmm1
	0x000001F2CA135E88  ff ff ff ff ff ff ff ff 
	
	0x000001F2CA135E90  ff ff ff ff ff ff ff ff <-Xmm2
	0x000001F2CA135E98  ff ff ff ff ff ff ff ff 
	
	0x000001F2CA135EA0  ff ff ff ff ff ff ff ff <-Xmm3
	0x000001F2CA135EA8  ff ff ff ff ff ff ff ff 
	
	0x000001F2CA135EB0  ff ff ff ff ff ff ff ff 
	0x000001F2CA135EB8  ff ff ff ff ff ff ff ff <-Xmm4
	
	0x000001F2CA135EC0  ff ff ff ff ff ff ff ff <-Xmm5
	0x000001F2CA135EC8  ff ff ff ff ff ff ff ff 
	
	0x000001F2CA135ED0  ff ff ff ff ff ff ff ff <-Xmm6
	0x000001F2CA135ED8  ff ff ff ff ff ff ff ff 
	
	0x000001F2CA135EE0  ff ff ff ff ff ff ff ff <-Xmm7
	0x000001F2CA135EE8  ff ff ff ff ff ff ff ff 
	
	0x000001F2CA135EF0  ff ff ff ff ff ff ff ff <-Xmm8
	0x000001F2CA135EF8  ff ff ff ff ff ff ff ff 
	
	0x000001F2CA135F00  ff ff ff ff ff ff ff ff <-Xmm9
	0x000001F2CA135F08  ff ff ff ff ff ff ff ff 
	
	0x000001F2CA135F10  ff ff ff ff ff ff ff ff 
	0x000001F2CA135F18  ff ff ff ff ff ff ff ff <-Xmm10
	
	0x000001F2CA135F20  ff ff ff ff ff ff ff ff 
	0x000001F2CA135F28  ff ff ff ff ff ff ff ff <-Xmm11
	
	0x000001F2CA135F30  ff ff ff ff ff ff ff ff 
	0x000001F2CA135F38  ff ff ff ff ff ff ff ff <-Xmm12
	
	0x000001F2CA135F40  ff ff ff ff ff ff ff ff 
	0x000001F2CA135F48  ff ff ff ff ff ff ff ff <-Xmm13
	
	0x000001F2CA135F50  ff ff ff ff ff ff ff ff 
	0x000001F2CA135F58  ff ff ff ff ff ff ff ff <-Xmm14
	
	0x000001F2CA135F60  ff ff ff ff ff ff ff ff 
	0x000001F2CA135F68  ff ff ff ff ff ff ff ff <-Xmm15

	0x000001F2CA135F70  ff ff ff ff ff ff ff ff <-r15
	0x000001F2CA135F78  ff ff ff ff ff ff ff ff <-r14
	0x000001F2CA135F80  ff ff ff ff ff ff ff ff <-r13
	0x000001F2CA135F88  ff ff ff ff ff ff ff ff <-r12
	0x000001F2CA135F90  ff ff ff ff ff ff ff ff <-r11
	0x000001F2CA135F98  ff ff ff ff ff ff ff ff <-r10
	0x000001F2CA135FA0  ff ff ff ff ff ff ff ff <-r9
	0x000001F2CA135FA8  ff ff ff ff ff ff ff ff <-r8
	0x000001F2CA135FB0  ff ff ff ff ff ff ff ff <-rdi
	0x000001F2CA135FB8  ff ff ff ff ff ff ff ff <-rsi
	0x000001F2CA135FC0  ff ff ff ff ff ff ff ff <-rbp
	0x000001F2CA135FC8  ff ff ff ff ff ff ff ff <-rsp(-1)
	0x000001F2CA135FD0  ff ff ff ff ff ff ff ff <-rbx
	0x000001F2CA135FD8  ff ff ff ff ff ff ff ff <-rdx
	0x000001F2CA135FE0  ff ff ff ff ff ff ff ff <-rcx
	0x000001F2CA135FE8  ff ff ff ff ff ff ff ff <-rax
	0x000001F2CA135FF0  0b 00 00 00 00 00 00 00 <-reserved         <- vmm_stack_base
	0x000001F2CA135FF8  0a 00 00 00 00 00 00 00 <-processor_data
	(Hign)
*/

	const auto vmm_stack_region_base = reinterpret_cast<ULONG_PTR>(processor_data->vmm_stack_limit) + KERNEL_STACK_SIZE;
	const auto vmm_stack_base = vmm_stack_region_base - sizeof(void*) * 2;
	const auto vmm_stack_data = vmm_stack_region_base - sizeof(void*);
	*reinterpret_cast<ProcessorData**>(vmm_stack_data) = processor_data;
	*reinterpret_cast<ULONG_PTR*>(vmm_stack_base) = MAXULONG_PTR;


	return processor_data;
}


void VmpFreeSharedData(_In_ ProcessorData* processor_data)
{
	PAGED_CODE();

	if (!processor_data->shared_data) {
		return;
	}

	if (InterlockedDecrement(&processor_data->shared_data->reference_count) !=
		0) {
		return;
	}
	Log("Freeing shared data...\n");
	if (processor_data->shared_data->io_bitmap_a) {
		ExFreePoolWithTag(processor_data->shared_data->io_bitmap_a,
			kHyperPlatformCommonPoolTag);
	}
	if (processor_data->shared_data->msr_bitmap) {
		ExFreePoolWithTag(processor_data->shared_data->msr_bitmap,
			kHyperPlatformCommonPoolTag);
	}
	//if (processor_data->shared_data->shared_sh_data) {
	//	ShFreeSharedShadowHookData(processor_data->shared_data->shared_sh_data);
	//}
	ExFreePoolWithTag(processor_data->shared_data, kHyperPlatformCommonPoolTag);
}
void* VmpBuildMsrBitmap()
{
	PAGED_CODE();
	//https://www.cnblogs.com/onetrainee/p/13590000.html
	const auto msr_bitmap = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE,
		kHyperPlatformCommonPoolTag);
	if (!msr_bitmap) {
		return nullptr;
	}
	RtlZeroMemory(msr_bitmap, PAGE_SIZE);

	// Activate VM-exit for RDMSR against all MSRs
	const auto bitmap_read_low = reinterpret_cast<UCHAR*>(msr_bitmap);
	const auto bitmap_read_high = bitmap_read_low + 1024;
	RtlFillMemory(bitmap_read_low, 1024, 0xff);   // read        0 -     1fff
	RtlFillMemory(bitmap_read_high, 1024, 0xff);  // read c0000000 - c0001fff

	// Ignore IA32_MPERF (000000e7) and IA32_APERF (000000e8)
	RTL_BITMAP bitmap_read_low_header = {};
	RtlInitializeBitMap(&bitmap_read_low_header,
		reinterpret_cast<PULONG>(bitmap_read_low), 1024 * 8);
	RtlClearBits(&bitmap_read_low_header, 0xe7, 2);

	// Checks MSRs that cause #GP from 0 to 0xfff, and ignore all of them
	for (auto msr = 0ul; msr < 0x1000; ++msr) {
		__try {
			Uti::UtilReadMsr(static_cast<Msr>(msr));

#pragma prefast(suppress: __WARNING_EXCEPTIONEXECUTEHANDLER, "Catch all.");
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			RtlClearBits(&bitmap_read_low_header, msr, 1);
		}
	}

	// Ignore IA32_GS_BASE (c0000101) and IA32_KERNEL_GS_BASE (c0000102)
	RTL_BITMAP bitmap_read_high_header = {};
	RtlInitializeBitMap(&bitmap_read_high_header,
		reinterpret_cast<PULONG>(bitmap_read_high),
		1024 * CHAR_BIT);
	RtlClearBits(&bitmap_read_high_header, 0x101, 2);

	return msr_bitmap;
}

UCHAR* VmpBuildIoBitmaps()
{
	/*
	24.6.4 I/O-Bitmap Addresses
    VM执行控制字段包括两个64位物理地址的I / O位图A和B（每一个的大小为4 KB）。 I / O位图A的每一位表示一个端口，范围为0000H至7FFFH。 
    I / O位图B包含8000H至FFFFH范围内的端口的位。
    当且仅当“使用I / O位图”控制为1时，逻辑处理器才使用这些位图。如果使用了位图，则如果它访问的端口对应的I / O位为1，则 / O指令的执行将导致VM退出。 
    有关详细信息，请参见第25.1.3节。 如果使用位图，则其地址必须4 KB对齐
	*/
	// Allocate two IO bitmaps as one contiguous 4K+4K page https://www.cnblogs.com/onetrainee/p/13590000.html
	const auto io_bitmaps = reinterpret_cast<UCHAR*>(ExAllocatePoolWithTag(
		NonPagedPool, PAGE_SIZE * 2, kHyperPlatformCommonPoolTag));
	if (!io_bitmaps) {
		return nullptr;
	}

	const auto io_bitmap_a = io_bitmaps;              // for    0x0 - 0x7fff
	const auto io_bitmap_b = io_bitmaps + PAGE_SIZE;  // for 0x8000 - 0xffff
	RtlFillMemory(io_bitmap_a, PAGE_SIZE, 0);
	RtlFillMemory(io_bitmap_b, PAGE_SIZE, 0);

	// Activate VM-exit for IO port 0x10 - 0x2010 as an example
	RTL_BITMAP bitmap_a_header = {};
	RtlInitializeBitMap(&bitmap_a_header, reinterpret_cast<PULONG>(io_bitmap_a),
		PAGE_SIZE * CHAR_BIT);
	// RtlSetBits(&bitmap_a_header, 0x10, 0x2000);

	RTL_BITMAP bitmap_b_header = {};
	RtlInitializeBitMap(&bitmap_b_header, reinterpret_cast<PULONG>(io_bitmap_b),
		PAGE_SIZE * CHAR_BIT);
	// RtlSetBits(&bitmap_b_header, 0, 0x8000);
	//io_bitmaps 所有内存为0 因此不会拦截IO
	return io_bitmaps;
}

SharedProcessorData* VmpInitializeSharedData()
{
	const auto shared_data = reinterpret_cast<SharedProcessorData*>(
		ExAllocatePoolWithTag(NonPagedPool, sizeof(SharedProcessorData),
			kHyperPlatformCommonPoolTag));
	if (!shared_data) {
		return nullptr;
	}
	RtlZeroMemory(shared_data, sizeof(SharedProcessorData));
	Log("shared_data           = %p", shared_data);

	// Setup MSR bitmap
	shared_data->msr_bitmap = VmpBuildMsrBitmap();
	if (!shared_data->msr_bitmap) {
		ExFreePoolWithTag(shared_data, kHyperPlatformCommonPoolTag);
		return nullptr;
	}

	// Setup IO bitmaps
	const auto io_bitmaps = VmpBuildIoBitmaps();
	if (!io_bitmaps) {
		ExFreePoolWithTag(shared_data->msr_bitmap, kHyperPlatformCommonPoolTag);
		ExFreePoolWithTag(shared_data, kHyperPlatformCommonPoolTag);
		return nullptr;
	}
	shared_data->io_bitmap_a = io_bitmaps;
	shared_data->io_bitmap_b = io_bitmaps + PAGE_SIZE;

	/*
	// Set up shared shadow hook data
	shared_data->shared_sh_data = ShAllocateSharedShaowHookData();
	if (!shared_data->shared_sh_data) {
		ExFreePoolWithTag(shared_data->io_bitmap_a, kHyperPlatformCommonPoolTag);
		ExFreePoolWithTag(shared_data->msr_bitmap, kHyperPlatformCommonPoolTag);
		ExFreePoolWithTag(shared_data, kHyperPlatformCommonPoolTag);
		return nullptr;
	}
	*/

	return shared_data;
}

NTSTATUS VmpSetLockBitCallback(_In_opt_ void* context)
{
	UNREFERENCED_PARAMETER(context);
	Ia32FeatureControlMsr vmx_feature_control = {
	Uti::UtilReadMsr64(Msr::kIa32FeatureControl) };
	if (vmx_feature_control.fields.lock) {
		return STATUS_SUCCESS;
	}
	vmx_feature_control.fields.lock = true;
	Uti::UtilWriteMsr64(Msr::kIa32FeatureControl, vmx_feature_control.all);
	vmx_feature_control.all = Uti::UtilReadMsr64(Msr::kIa32FeatureControl);
	if (!vmx_feature_control.fields.lock) {
		Log("[hzw]The lock bit is still clear.\n");
		return STATUS_DEVICE_CONFIGURATION_ERROR;
	}
	return STATUS_SUCCESS;
}


/// <summary>
/// 检查 HyperPlatform 是否安装了
/// </summary>
/// <returns></returns>
bool VmpIsHyperPlatformInstalled()
{

	int cpu_info[4] = {};
	__cpuid(cpu_info, 1);
	const CpuFeaturesEcx cpu_features = { static_cast<ULONG_PTR>(cpu_info[2]) };
	if (!cpu_features.fields.not_used) {
		return false;
	}

	__cpuid(cpu_info, kHyperVCpuidInterface);
	return cpu_info[0] == kHyperVCpuidMark;
}

bool VmpIsVmxAvailable()
{
	// See: DISCOVERING SUPPORT FOR VMX
// If CPUID.1:ECX.VMX[bit 5]=1, then VMX operation is supported.
	int cpu_info[4] = {};
	__cpuid(cpu_info, 1);
	const CpuFeaturesEcx cpu_features = { static_cast<ULONG_PTR>(cpu_info[2]) };
	if (!cpu_features.fields.vmx) {
		Log("[hzw]VMX features are not supported\n");
		return false;
	}

	// See: BASIC VMX INFORMATION
	// The first processors to support VMX operation use the write-back type.
	const Ia32VmxBasicMsr vmx_basic_msr = { Uti::UtilReadMsr64(Msr::kIa32VmxBasic) };
	if (static_cast<memory_type>(vmx_basic_msr.fields.memory_type) !=
		memory_type::kWriteBack) {
		Log("[hzw]Write-back cache type is not supported.\n");
		return false;
	}

	// See: ENABLING AND ENTERING VMX OPERATION
	Ia32FeatureControlMsr vmx_feature_control = {
		Uti::UtilReadMsr64(Msr::kIa32FeatureControl) };
	if (!vmx_feature_control.fields.lock) {
		Log("[hzw]The lock bit is clear. Attempting to set 1.\n");
		const auto status = Uti::UtilForEachProcessor(VmpSetLockBitCallback, nullptr);
		if (!NT_SUCCESS(status)) {
			return false;
		}
	}
	if (!vmx_feature_control.fields.enable_vmxon) {
		Log("[hzw]VMX features are not enabled\n");
		return false;
	}

	if (!ept::EptIsEptAvailable()) {
		Log("[hzw]EPT features are not fully supported\n");
		return false;
	}
	return true;
}







namespace VM {



	NTSTATUS VmInitialization()
	{
		auto status = STATUS_SUCCESS;
		if (bInstalled)return status;
		if (KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS) > 64)return STATUS_NOT_SUPPORTED;

		if (VmpIsHyperPlatformInstalled()) {
			return STATUS_CANCELLED;
		}

		if (!VmpIsVmxAvailable()) {
			return STATUS_HV_FEATURE_UNAVAILABLE;
		}

		const auto shared_data = VmpInitializeSharedData();
		if (!shared_data) {
			return STATUS_MEMORY_NOT_ALLOCATED;
		}


		// Read and store all MTRRs to set a correct memory type for EPT
		ept::EptInitializeMtrrEntries();


		// Virtualize all processors
		status = Uti::UtilForEachProcessor(VmpStartVm, shared_data);
		if (!NT_SUCCESS(status)) {
			Uti::UtilForEachProcessor(VmpStopVm, nullptr);
			return status;
		}
		bInstalled = true;

		return status;
	}

	void VmTermination()
	{
		if (!bInstalled)return;
		auto status = Uti::UtilForEachProcessor(VmpStopVm, nullptr);

		if (NT_SUCCESS(status)) 
		{
			Log("The VMM has been uninstalled.\n");
		}
		else {
			Log("The VMM has not been uninstalled (%08x).\n", status);
		}
		NT_ASSERT(!VmpIsHyperPlatformInstalled());
		bInstalled = false;
	}

	bool IsStartVt()
	{
		bool b = true;
		const auto number_of_processors = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
		for (ULONG processor_index = 0; processor_index < number_of_processors;
			processor_index++) {
			PROCESSOR_NUMBER processor_number = {};
			auto status = KeGetProcessorNumberFromIndex(processor_index, &processor_number);
			if (!NT_SUCCESS(status)) {
				return false;
			}

			// Switch the current processor
			GROUP_AFFINITY affinity = {};
			affinity.Group = processor_number.Group;
			affinity.Mask = 1ull << processor_number.Number;
			GROUP_AFFINITY previous_affinity = {};
			KeSetSystemGroupAffinityThread(&affinity, &previous_affinity);

			// Execute callback
			b &= VmpIsHyperPlatformInstalled();

			KeRevertToUserGroupAffinityThread(&previous_affinity);
			if (!NT_SUCCESS(status)) {
				return false;
			}
		}

		return b;

	}


}

}