#include "vmm.h"
#include "ia32_type.h"
#include "common.h"
#include "utl.h"
#include "vtdump.h"
#include "asm.h"
#include "common.h"
#include "ept.h"
#include "exapi.h"

EXTERN_C{

// Represents raw structure of stack of VMM when VmmVmExitHandler() is called
struct VmmInitialStack {
    GpRegisters gp_regs;
    ULONG_PTR reserved;
    ProcessorData* processor_data;
};

// Things need to be read and written by each VM-exit handler
struct GuestContext {
    union {
        VmmInitialStack* stack;
        GpRegisters* gp_regs;
    };
    FlagRegister flag_reg;
    ULONG_PTR ip;
    ULONG_PTR cr8;
    KIRQL irql;
    bool vm_continue;
};
#if defined(_AMD64_)
static_assert(sizeof(GuestContext) == 40, "Size check");
#else
static_assert(sizeof(GuestContext) == 20, "Size check");
#endif

// Context at the moment of vmexit
struct VmExitHistory {
    GpRegisters gp_regs;
    ULONG_PTR ip;
    VmExitInformation exit_reason;
    ULONG_PTR exit_qualification;
    ULONG_PTR instruction_info;
};

////////////////////////////////////////////////////////////////////////////////

bool __stdcall VmmVmExitHandler(_Inout_ VmmInitialStack* stack);
static void VmmpHandleVmExit(GuestContext* guest_context);
static void VmmpHandleCpuid(_Inout_ GuestContext* guest_context);
//如果 eflags.tf=1 就要注入一个#DB异常
static void VmmpAdjustGuestInstructionPointer(_In_ GuestContext* guest_context);
static void VmmpInjectInterruption(_In_ InterruptionType interruption_type,_In_ InterruptionVector vector,_In_ bool deliver_error_code,_In_ ULONG32 error_code);
static void VmmpHandleMsrReadAccess(_Inout_ GuestContext* guest_context);
static void VmmpHandleMsrAccess(_Inout_ GuestContext* guest_context, _In_ bool read_access);
static void VmmpHandleMsrWriteAccess(GuestContext* guest_context);
static void VmmpHandleVmx(VmExitInformation exit_reason,_Inout_ GuestContext* guest_context);
static void VmmpHandleVmCall(_Inout_ GuestContext* guest_context);
//可以通过这个来判断 代码的环境 R3/ R0
static UCHAR VmmpGetGuestCpl();
static void VmmpIndicateUnsuccessfulVmcall(_In_ GuestContext* guest_context);
static void VmmpHandleRdtscp(_Inout_ GuestContext* guest_context);
static void VmmpHandleXsetbv(_Inout_ GuestContext* guest_context);
static void VmmpHandleVmCallTermination(_In_ GuestContext* guest_context,_Inout_ void* context);
static void VmmpHandleMonitorTrap(GuestContext* guest_context);
static void VmmpHandleInvalidateInternalCaches(GuestContext* guest_context);
static void VmmpHandleCrAccess(_Inout_ GuestContext* guest_context);
static ULONG_PTR* VmmpSelectRegister(_In_ ULONG index,_In_ GuestContext* guest_context);
static ULONG_PTR VmmpGetKernelCr3();
static void VmmpHandleDrAccess(_Inout_ GuestContext* guest_context);
static void VmmpHandleInvalidateTlbEntry(_Inout_ GuestContext* guest_context);
static void VmmpHandleRdtsc(_Inout_ GuestContext* guest_context);
static void VmmpHandleGdtrOrIdtrAccess(_Inout_ GuestContext* guest_context);
static void VmmpHandleLdtrOrTrAccess(_Inout_ GuestContext* guest_context);
static void VmmpHandleException(_Inout_ GuestContext* guest_context);
static void VmmpHandleEptViolation(_Inout_ GuestContext* guest_context);
static void VmmpHandleEptMisconfig(_Inout_ GuestContext* guest_context);
static void VmmpHandleTripleFault(GuestContext* guest_context);
static void VmmpHandleTripleFault(GuestContext* guest_context)
{
    HYPERPLATFORM_COMMON_BUG_CHECK(HyperPlatformBugCheck::kTripleFaultVmExit, (ULONG_PTR)guest_context, 0, 0);
}
// LIDT, SIDT, LGDT and SGDT
_Use_decl_annotations_ static void VmmpHandleGdtrOrIdtrAccess(
    GuestContext* guest_context) {
  
    const GdtrOrIdtrInstInformation instruction_info = {
        static_cast<ULONG32>(Uti::UtilVmRead(VmcsField::kVmxInstructionInfo)) };

    // Calculate an address to be used for the instruction
    const auto displacement = Uti::UtilVmRead(VmcsField::kExitQualification);

    // Base
    ULONG_PTR base_value = 0;
    if (!instruction_info.fields.base_register_invalid) {
        const auto register_used = VmmpSelectRegister(
            instruction_info.fields.base_register, guest_context);
        base_value = *register_used;
    }

    // Index
    ULONG_PTR index_value = 0;
    if (!instruction_info.fields.index_register_invalid) {
        const auto register_used = VmmpSelectRegister(
            instruction_info.fields.index_register, guest_context);
        index_value = *register_used;
        switch (static_cast<Scaling>(instruction_info.fields.scalling)) {
        case Scaling::kNoScaling:
            index_value = index_value;
            break;
        case Scaling::kScaleBy2:
            index_value = index_value * 2;
            break;
        case Scaling::kScaleBy4:
            index_value = index_value * 4;
            break;
        case Scaling::kScaleBy8:
            index_value = index_value * 8;
            break;
        default:
            break;
        }
    }

    // clang-format off
    ULONG_PTR segment_base = 0;
    switch (instruction_info.fields.segment_register) {
    case 0: segment_base = Uti::UtilVmRead(VmcsField::kGuestEsBase); break;
    case 1: segment_base = Uti::UtilVmRead(VmcsField::kGuestCsBase); break;
    case 2: segment_base = Uti::UtilVmRead(VmcsField::kGuestSsBase); break;
    case 3: segment_base = Uti::UtilVmRead(VmcsField::kGuestDsBase); break;
    case 4: segment_base = Uti::UtilVmRead(VmcsField::kGuestFsBase); break;
    case 5: segment_base = Uti::UtilVmRead(VmcsField::kGuestGsBase); break;
    default: HYPERPLATFORM_COMMON_DBG_BREAK(); break;
    }
    // clang-format on

    auto operation_address =
        segment_base + base_value + index_value + displacement;
    if (static_cast<AddressSize>(instruction_info.fields.address_size) ==
        AddressSize::k32bit) {
        operation_address &= MAXULONG;
    }

    // Update CR3 with that of the guest since below code is going to access
    // memory.
    const auto guest_cr3 = VmmpGetKernelCr3();
    const auto vmm_cr3 = __readcr3();
    __writecr3(guest_cr3);

    // Emulate the instruction
    auto descriptor_table_reg = reinterpret_cast<Idtr*>(operation_address);
    switch (static_cast<GdtrOrIdtrInstructionIdentity>(
        instruction_info.fields.instruction_identity)) {
    case GdtrOrIdtrInstructionIdentity::kSgdt: {
        // On 64bit system, SIDT and SGDT can be executed from a 32bit process
        // where runs with the 32bit operand size. The following checks the
        // current guest's operand size and writes either full 10 bytes (for the
        // 64bit more) or 6 bytes or IDTR or GDTR as the processor does. See:
        // Operand Size and Address Size in 64-Bit Mode See: SGDT-Store Global
        // Descriptor Table Register See: SIDT-Store Interrupt Descriptor Table
        // Register
        const auto gdt_base = Uti::UtilVmRead(VmcsField::kGuestGdtrBase);
        const auto gdt_limit =
            static_cast<unsigned short>(Uti::UtilVmRead(VmcsField::kGuestGdtrLimit));

        const SegmentSelector ss = {
            static_cast<USHORT>(Uti::UtilVmRead(VmcsField::kGuestCsSelector)) };
        const auto segment_descriptor = reinterpret_cast<SegmentDescriptor*>(
            gdt_base + ss.fields.index * sizeof(SegmentDescriptor));
        if (segment_descriptor->fields.l) {
            // 64bit
            descriptor_table_reg->base = gdt_base;
            descriptor_table_reg->limit = gdt_limit;
        }
        else {
            // 32bit
            const auto descriptor_table_reg32 =
                reinterpret_cast<Idtr32*>(descriptor_table_reg);
            descriptor_table_reg32->base = static_cast<ULONG32>(gdt_base);
            descriptor_table_reg32->limit = gdt_limit;
        }
        break;
    }
    case GdtrOrIdtrInstructionIdentity::kSidt: {
        const auto idt_base = Uti::UtilVmRead(VmcsField::kGuestIdtrBase);
        const auto idt_limit =
            static_cast<unsigned short>(Uti::UtilVmRead(VmcsField::kGuestIdtrLimit));

        const auto gdt_base = Uti::UtilVmRead(VmcsField::kGuestGdtrBase);
        const SegmentSelector ss = {
            static_cast<USHORT>(Uti::UtilVmRead(VmcsField::kGuestCsSelector)) };
        const auto segment_descriptor = reinterpret_cast<SegmentDescriptor*>(
            gdt_base + ss.fields.index * sizeof(SegmentDescriptor));
        if (segment_descriptor->fields.l) {
            // 64bit
            descriptor_table_reg->base = idt_base;
            descriptor_table_reg->limit = idt_limit;
        }
        else {
            // 32bit
            const auto descriptor_table_reg32 =
                reinterpret_cast<Idtr32*>(descriptor_table_reg);
            descriptor_table_reg32->base = static_cast<ULONG32>(idt_base);
            descriptor_table_reg32->limit = idt_limit;
        }
        break;
    }
    case GdtrOrIdtrInstructionIdentity::kLgdt:
        Uti::UtilVmWrite(VmcsField::kGuestGdtrBase, descriptor_table_reg->base);
        Uti::UtilVmWrite(VmcsField::kGuestGdtrLimit, descriptor_table_reg->limit);
        break;
    case GdtrOrIdtrInstructionIdentity::kLidt:
        Uti::UtilVmWrite(VmcsField::kGuestIdtrBase, descriptor_table_reg->base);
        Uti::UtilVmWrite(VmcsField::kGuestIdtrLimit, descriptor_table_reg->limit);
        break;
    }

    __writecr3(vmm_cr3);
    VmmpAdjustGuestInstructionPointer(guest_context);
}

// LLDT, LTR, SLDT, and STR
_Use_decl_annotations_ static void VmmpHandleLdtrOrTrAccess(
    GuestContext* guest_context) {
 
    const LdtrOrTrInstInformation instruction_info = {
        static_cast<ULONG32>(Uti::UtilVmRead(VmcsField::kVmxInstructionInfo)) };

    // Calculate an address or a register to be used for the instruction
    const auto displacement = Uti::UtilVmRead(VmcsField::kExitQualification);

    ULONG_PTR operation_address = 0;
    if (instruction_info.fields.register_access) {
        // Register
        const auto register_used =
            VmmpSelectRegister(instruction_info.fields.register1, guest_context);
        operation_address = reinterpret_cast<ULONG_PTR>(register_used);
    }
    else {
        // Base
        ULONG_PTR base_value = 0;
        if (!instruction_info.fields.base_register_invalid) {
            const auto register_used = VmmpSelectRegister(
                instruction_info.fields.base_register, guest_context);
            base_value = *register_used;
        }

        // Index
        ULONG_PTR index_value = 0;
        if (!instruction_info.fields.index_register_invalid) {
            const auto register_used = VmmpSelectRegister(
                instruction_info.fields.index_register, guest_context);
            index_value = *register_used;
            switch (static_cast<Scaling>(instruction_info.fields.scalling)) {
            case Scaling::kNoScaling:
                index_value = index_value;
                break;
            case Scaling::kScaleBy2:
                index_value = index_value * 2;
                break;
            case Scaling::kScaleBy4:
                index_value = index_value * 4;
                break;
            case Scaling::kScaleBy8:
                index_value = index_value * 8;
                break;
            default:
                break;
            }
        }

        // clang-format off
        ULONG_PTR segment_base = 0;
        switch (instruction_info.fields.segment_register) {
        case 0: segment_base = Uti::UtilVmRead(VmcsField::kGuestEsBase); break;
        case 1: segment_base = Uti::UtilVmRead(VmcsField::kGuestCsBase); break;
        case 2: segment_base = Uti::UtilVmRead(VmcsField::kGuestSsBase); break;
        case 3: segment_base = Uti::UtilVmRead(VmcsField::kGuestDsBase); break;
        case 4: segment_base = Uti::UtilVmRead(VmcsField::kGuestFsBase); break;
        case 5: segment_base = Uti::UtilVmRead(VmcsField::kGuestGsBase); break;
        default: HYPERPLATFORM_COMMON_DBG_BREAK(); break;
        }
        // clang-format on

        operation_address = segment_base + base_value + index_value + displacement;
        if (static_cast<AddressSize>(instruction_info.fields.address_size) ==
            AddressSize::k32bit) {
            operation_address &= MAXULONG;
        }
    }

    // Update CR3 with that of the guest since below code is going to access
    // memory.
    const auto guest_cr3 = VmmpGetKernelCr3();
    const auto vmm_cr3 = __readcr3();
    __writecr3(guest_cr3);

    // Emulate the instruction
    auto selector = reinterpret_cast<USHORT*>(operation_address);
    switch (static_cast<LdtrOrTrInstructionIdentity>(
        instruction_info.fields.instruction_identity)) {
    case LdtrOrTrInstructionIdentity::kSldt:
        *selector =
            static_cast<USHORT>(Uti::UtilVmRead(VmcsField::kGuestLdtrSelector));
        break;
    case LdtrOrTrInstructionIdentity::kStr:
        *selector = static_cast<USHORT>(Uti::UtilVmRead(VmcsField::kGuestTrSelector));
        break;
    case LdtrOrTrInstructionIdentity::kLldt:
        Uti::UtilVmWrite(VmcsField::kGuestLdtrSelector, *selector);
        break;
    case LdtrOrTrInstructionIdentity::kLtr: {
        Uti::UtilVmWrite(VmcsField::kGuestTrSelector, *selector);
        // Set the Busy bit in TSS.
        // See: LTR - Load Task Register
        const SegmentSelector ss = { *selector };
        const auto sd = reinterpret_cast<SegmentDescriptor*>(
            Uti::UtilVmRead(VmcsField::kGuestGdtrBase) +
            ss.fields.index * sizeof(SegmentDescriptor));
        sd->fields.type |= 2;  // Set the Busy bit
        break;
    }
    }

    __writecr3(vmm_cr3);
    VmmpAdjustGuestInstructionPointer(guest_context);
}
// RDTSC
_Use_decl_annotations_ static void VmmpHandleRdtsc(
    GuestContext* guest_context) {
   
    ULARGE_INTEGER tsc = {};
    tsc.QuadPart = __rdtsc();
    guest_context->gp_regs->dx = tsc.HighPart;
    guest_context->gp_regs->ax = tsc.LowPart;

    VmmpAdjustGuestInstructionPointer(guest_context);
}

// INVLPG
_Use_decl_annotations_ static void VmmpHandleInvalidateTlbEntry(
    GuestContext* guest_context) {
 
    const auto invalidate_address =
        reinterpret_cast<void*>(Uti::UtilVmRead(VmcsField::kExitQualification));
    Uti::UtilInvvpidIndividualAddress(
        static_cast<USHORT>(KeGetCurrentProcessorNumberEx(nullptr) + 1),
        invalidate_address);
    VmmpAdjustGuestInstructionPointer(guest_context);
}
// MOV to / from DRx
_Use_decl_annotations_ static void VmmpHandleDrAccess(GuestContext* guest_context) 
{
    // Normally, when the privileged instruction is executed at CPL3, #GP(0)
    // occurs instead of VM-exit. However, access to the debug registers is
    // exception. Inject #GP(0) in such case to emulate what the processor
    // normally does. See: Instructions That Cause VM Exits Conditionally
    if (VmmpGetGuestCpl() != 0) {
        VmmpInjectInterruption(InterruptionType::kHardwareException,
            InterruptionVector::kGeneralProtectionException,
            true, 0);
        return;
    }

    const MovDrQualification exit_qualification = {
        Uti::UtilVmRead(VmcsField::kExitQualification) };
    auto debugl_register = exit_qualification.fields.debugl_register;

    // Access to DR4 and 5 causes #UD when CR4.DE (Debugging Extensions) is set.
    // Otherwise, these registers are aliased to DR6 and 7 respectively.
    // See: Debug Registers DR4 and DR5
    if (debugl_register == 4 || debugl_register == 5) {
        const Cr4 guest_cr4 = { Uti::UtilVmRead(VmcsField::kGuestCr4) };
        if (guest_cr4.fields.de) 
        {
            //Software that accesses DR4 or DR5 when DE = 1 causes a invalid opcode exception(#UD)
            VmmpInjectInterruption(InterruptionType::kHardwareException,
                InterruptionVector::kInvalidOpcodeException, false,
                0);
            return;
        }
        /*
        When the DE bit is cleared to 0, I/O breakpointcapabilities are disabled. Software references to the
        DR4 and DR5 registers are aliased to the DR6 and DR7registers, respectively.
        */
        else if (debugl_register == 4) {
            debugl_register = 6;
        }
        else {
            debugl_register = 7;
        }
    }

    // Access to any of DRs causes #DB when DR7.GD (General Detect Enable) is set.
    // See: Debug Control Register (DR7)
    Dr7 guest_dr7 = { Uti::UtilVmRead(VmcsField::kGuestDr7) };
    if (guest_dr7.fields.gd) 
    {
        Dr6 guest_dr6 = { __readdr(6) };
        // Clear DR6.B0-3 since the #DB being injected is not due to match of a
        // condition specified in DR6. The processor is allowed to clear those bits
        // as "Certain debug exceptions may clear bits 0-3."
        guest_dr6.fields.b0 = false;
        guest_dr6.fields.b1 = false;
        guest_dr6.fields.b2 = false;
        guest_dr6.fields.b3 = false;
        // "When such a condition is detected, the BD flag in debug status register
        // DR6 is set prior to generating the exception."
        guest_dr6.fields.bd = true;
        __writedr(6, guest_dr6.all);

        VmmpInjectInterruption(InterruptionType::kHardwareException,
            InterruptionVector::kDebugException, false, 0);

        // While the processor clears the DR7.GD bit on #DB ("The processor clears
        // the GD flag upon entering to the debug exception handler"), it does not
        // change that in the VMCS. Emulate that behavior here. Note that this bit
        // should actually be cleared by intercepting #DB and in the handler instead
        // of here, since the processor clears it on any #DB. We do not do that as
        // we do not intercept #DB as-is.
        guest_dr7.fields.gd = false;
        Uti::UtilVmWrite(VmcsField::kGuestDr7, guest_dr7.all);
        return;
    }

    const auto register_used = VmmpSelectRegister(exit_qualification.fields.gp_register, guest_context);
    const auto direction = static_cast<MovDrDirection>(exit_qualification.fields.direction);

    // In 64-bit mode, the upper 32 bits of DR6 and DR7 are reserved and must be
    // written with zeros. Writing 1 to any of the upper 32 bits results in a
    // #GP(0) exception. See: Debug Registers and Intel® 64 Processors
    if (IsX64() && direction == MovDrDirection::kMoveToDr) {
        const auto value64 = static_cast<ULONG64>(*register_used);
        if ((debugl_register == 6 || debugl_register == 7) && (value64 >> 32)) //value64 = 0xaaaabbbb11112222>>32; a=0xaaaabbbb
        {
            //如果DR6 DR7的高32位被写入 就注入一个异常
            VmmpInjectInterruption(InterruptionType::kHardwareException,
                InterruptionVector::kGeneralProtectionException,
                true, 0);
            return;
        }
    }

    switch (direction) {
    case MovDrDirection::kMoveToDr:
        switch (debugl_register) {
            // clang-format off
        case 0: __writedr(0, *register_used); break;
        case 1: __writedr(1, *register_used); break;
        case 2: __writedr(2, *register_used); break;
        case 3: __writedr(3, *register_used); break;
            // clang-format on
        case 6: {
            // Make sure that we write 0 and 1 into the bits that are stated to be
            // so. The Intel SDM does not appear to state what happens when the
            // processor attempts to write 1 to the always 0 bits, and vice versa,
            // however, observation is that writes to those bits are ignored
            // *as long as it is done on the non-root mode*, and other hypervisors
            // emulate in that way as well.
            Dr6 write_value = { *register_used };
            write_value.fields.reserved1 |= ~write_value.fields.reserved1;
            write_value.fields.reserved2 = 0;
            write_value.fields.reserved3 |= ~write_value.fields.reserved3;
            __writedr(6, write_value.all);
            break;
        }
        case 7: {
            // Similar to the case of CR6, enforce always 1 and 0 behavior.
            Dr7 write_value = { *register_used };
            write_value.fields.reserved1 |= ~write_value.fields.reserved1;
            write_value.fields.reserved2 = 0;
            write_value.fields.reserved3 = 0;
            Uti::UtilVmWrite(VmcsField::kGuestDr7, write_value.all);
            break;
        }
        default:
            break;
        }
        break;
    case MovDrDirection::kMoveFromDr:
        // clang-format off
        switch (debugl_register) {
        case 0: *register_used = __readdr(0); break;
        case 1: *register_used = __readdr(1); break;
        case 2: *register_used = __readdr(2); break;
        case 3: *register_used = __readdr(3); break;
        case 6: *register_used = __readdr(6); break;
        case 7: *register_used = Uti::UtilVmRead(VmcsField::kGuestDr7); break;
        default: break;
        }
        // clang-format on
        break;
    default:
        HYPERPLATFORM_COMMON_BUG_CHECK(HyperPlatformBugCheck::kUnspecified, 0, 0,
            0);
        break;
    }

    VmmpAdjustGuestInstructionPointer(guest_context);
}

// Returns a kernel CR3 value of the current process;
static ULONG_PTR VmmpGetKernelCr3() 
{
    ULONG_PTR guest_cr3 = 0;
    static const long kDirectoryTableBaseOffset = IsX64() ? 0x28 : 0x18;
    if constexpr (IsX64()) {
        // On x64, assume it is an user-mode CR3 when the lowest bit is set. If so,
        // get CR3 from _KPROCESS::DirectoryTableBase.
        guest_cr3 = Uti::UtilVmRead(VmcsField::kGuestCr3);
        if (guest_cr3 & 1) 
        {
            const auto process = reinterpret_cast<PUCHAR>(PsGetCurrentProcess());
            guest_cr3 =*reinterpret_cast<PULONG_PTR>(process + kDirectoryTableBaseOffset);
        }
    }
    else 
    {
        // On x86, there is no easy way to tell whether the CR3 taken from VMCS is
        // a user-mode CR3 or kernel-mode CR3 by only looking at the value.
        // Therefore, we simply use _KPROCESS::DirectoryTableBase always.
        const auto process = reinterpret_cast<PUCHAR>(PsGetCurrentProcess());
        guest_cr3 = *reinterpret_cast<PULONG_PTR>(process + kDirectoryTableBaseOffset);
    }
    return guest_cr3;
}
// Selects a register to be used based on the index
_Use_decl_annotations_ static ULONG_PTR* VmmpSelectRegister(
    ULONG index, GuestContext* guest_context) {
    ULONG_PTR* register_used = nullptr;
    // clang-format off
    switch (index) {
    case 0: register_used = &guest_context->gp_regs->ax; break;
    case 1: register_used = &guest_context->gp_regs->cx; break;
    case 2: register_used = &guest_context->gp_regs->dx; break;
    case 3: register_used = &guest_context->gp_regs->bx; break;
    case 4: register_used = &guest_context->gp_regs->sp; break;
    case 5: register_used = &guest_context->gp_regs->bp; break;
    case 6: register_used = &guest_context->gp_regs->si; break;
    case 7: register_used = &guest_context->gp_regs->di; break;
#if defined(_AMD64_)
    case 8: register_used = &guest_context->gp_regs->r8; break;
    case 9: register_used = &guest_context->gp_regs->r9; break;
    case 10: register_used = &guest_context->gp_regs->r10; break;
    case 11: register_used = &guest_context->gp_regs->r11; break;
    case 12: register_used = &guest_context->gp_regs->r12; break;
    case 13: register_used = &guest_context->gp_regs->r13; break;
    case 14: register_used = &guest_context->gp_regs->r14; break;
    case 15: register_used = &guest_context->gp_regs->r15; break;
#endif
    default: HYPERPLATFORM_COMMON_DBG_BREAK(); break;
    }
    // clang-format on
    return register_used;
}
// MOV to / from CRx
_Use_decl_annotations_ static void VmmpHandleCrAccess(GuestContext* guest_context) 
{

    const MovCrQualification exit_qualification = { Uti::UtilVmRead(VmcsField::kExitQualification) };

    const auto register_used = VmmpSelectRegister(exit_qualification.fields.gp_register, guest_context);

    switch (static_cast<MovCrAccessType>(exit_qualification.fields.access_type)) {
    case MovCrAccessType::kMoveToCr:
        switch (exit_qualification.fields.control_register) {
            // CR0 <- Reg
        case 0: 
        {
          
            if (Uti::UtilIsX86Pae()) {Uti::UtilLoadPdptes(Uti::UtilVmRead(VmcsField::kGuestCr3));}
            const Cr0 cr0_fixed0 = { Uti::UtilReadMsr(Msr::kIa32VmxCr0Fixed0) };
            const Cr0 cr0_fixed1 = { Uti::UtilReadMsr(Msr::kIa32VmxCr0Fixed1) };
            Cr0 cr0 = { *register_used };
            cr0.all &= cr0_fixed1.all;
            cr0.all |= cr0_fixed0.all;
            Uti::UtilVmWrite(VmcsField::kGuestCr0, cr0.all);
            Uti::UtilVmWrite(VmcsField::kCr0ReadShadow, cr0.all);
            break;
        }

              // CR3 <- Reg
        case 3: {
           
            if (Uti::UtilIsX86Pae()) {
                Uti::UtilLoadPdptes(VmmpGetKernelCr3());
            }
            // Under some circumstances MOV to CR3 is not *required* to flush TLB
            // entries, but also NOT prohibited to do so. Therefore, we flush it
            // all time.
            // See: Operations that Invalidate TLBs and Paging-Structure Caches
            Uti::UtilInvvpidSingleContextExceptGlobal(
                static_cast<USHORT>(KeGetCurrentProcessorNumberEx(nullptr) + 1));

            // The MOV to CR3 does not modify the bit63 of CR3. Emulate this
            // behavior.
            // See: MOV - Move to/from Control Registers 当对CR3进行更新时，CR3第63位决定是否需要处理器的TLB和paging-struct cache
            Uti::UtilVmWrite(VmcsField::kGuestCr3, (*register_used & ~(1ULL << 63))); //去掉63位
            break;
        }

              // CR4 <- Reg
        case 4: {
          
            if (Uti::UtilIsX86Pae()) {
                Uti::UtilLoadPdptes(Uti::UtilVmRead(VmcsField::kGuestCr3));
            }
            Uti::UtilInvvpidAllContext();
            const Cr4 cr4_fixed0 = { Uti::UtilReadMsr(Msr::kIa32VmxCr4Fixed0) };
            const Cr4 cr4_fixed1 = { Uti::UtilReadMsr(Msr::kIa32VmxCr4Fixed1) };
            Cr4 cr4 = { *register_used };
            cr4.all &= cr4_fixed1.all;
            cr4.all |= cr4_fixed0.all;
            Uti::UtilVmWrite(VmcsField::kGuestCr4, cr4.all);
            Uti::UtilVmWrite(VmcsField::kCr4ReadShadow, cr4.all);
            break;
        }

              // CR8 <- Reg
        case 8: {
 
            guest_context->cr8 = *register_used;
            break;
        }

        default:
            HYPERPLATFORM_COMMON_BUG_CHECK(HyperPlatformBugCheck::kUnspecified, 0,
                0, 0);
            break;
        }
        break;

    case MovCrAccessType::kMoveFromCr:
        switch (exit_qualification.fields.control_register) {
            // Reg <- CR3
        case 3: {
           
            *register_used = Uti::UtilVmRead(VmcsField::kGuestCr3);
            break;
        }

              // Reg <- CR8
        case 8: {
           
            *register_used = guest_context->cr8;
            break;
        }

        default:
            HYPERPLATFORM_COMMON_BUG_CHECK(HyperPlatformBugCheck::kUnspecified, 0,0, 0);
            break;
        }
        break;

        // Unimplemented
    case MovCrAccessType::kClts:
    case MovCrAccessType::kLmsw:
    default:
        HYPERPLATFORM_COMMON_DBG_BREAK();
        break;
    }

    VmmpAdjustGuestInstructionPointer(guest_context);
}

// INVD
static void VmmpHandleInvalidateInternalCaches(GuestContext* guest_context) 
{
    AsmInvalidateInternalCaches();
    VmmpAdjustGuestInstructionPointer(guest_context);
}
static void VmmpHandleMonitorTrap(GuestContext* guest_context)
{
 /*
MTF全程是 Monitor Trap flag，其在 VM-execution control字段的第27位；
我们可以理解为其是一个单步异常，当设置该标志位时，回到guest时第一条指令会再次触发 VM-Exit，且退出理由为MTF；
注意，当回到Guest且有注入事件时，其依据的是注入事件的第一条汇编指令，而不是guest中的第一条；
有关详细信息，其还涉及pending等相关知识，查阅Intel手册或《处理器虚拟化》来看详情操作；
我们需要补充一点：对于MTF产生的vm-exit，我们恢复GUEST的RIP时，并不需要处理添加指令长度
 */
    UNREFERENCED_PARAMETER(guest_context);
    HYPERPLATFORM_COMMON_DBG_BREAK();
    VmxProcessorBasedControls vm_procctl = { static_cast<unsigned int>(Uti::UtilVmRead(VmcsField::kCpuBasedVmExecControl)) };
    vm_procctl.fields.monitor_trap_flag = false;
    Uti::UtilVmWrite(VmcsField::kCpuBasedVmExecControl, vm_procctl.all);

}

bool __stdcall VmmVmExitHandler(_Inout_ VmmInitialStack* stack)
{

    // Save guest's context and raise IRQL as quick as possible
    const auto guest_irql = KeGetCurrentIrql();
    const auto guest_cr8 = IsX64() ? __readcr8() : 0;
    if (guest_irql < DISPATCH_LEVEL) {
      KeRaiseIrqlToDpcLevel();
    }
    NT_ASSERT(stack->reserved == MAXULONG_PTR);

    // Capture the current guest state
    GuestContext guest_context = {stack,
                                  Uti::UtilVmRead(VmcsField::kGuestRflags),
                                  Uti::UtilVmRead(VmcsField::kGuestRip),
                                  guest_cr8,
                                  guest_irql,
                                  true};
    guest_context.gp_regs->sp = Uti::UtilVmRead(VmcsField::kGuestRsp);

    // Dispatch the current VM-exit event
    VmmpHandleVmExit(&guest_context);

    // See: Guidelines for Use of the INVVPID Instruction, and Guidelines for Use
    // of the INVEPT Instruction
    if (!guest_context.vm_continue) {
        Uti::UtilInveptGlobal();
        Uti::UtilInvvpidAllContext();
    }

    // Restore guest's context
    if (guest_context.irql < DISPATCH_LEVEL) {
      KeLowerIrql(guest_context.irql);
    }

    // Apply possibly updated CR8 by the handler
    if constexpr (IsX64()) {
      __writecr8(guest_context.cr8);
    }
    return guest_context.vm_continue;
}



static void VmmpHandleCpuid(_Inout_ GuestContext * guest_context)
{
    unsigned int cpu_info[4] = {};
    const auto function_id = static_cast<int>(guest_context->gp_regs->ax);
    const auto sub_function_id = static_cast<int>(guest_context->gp_regs->cx);
    __cpuidex(reinterpret_cast<int*>(cpu_info), function_id, sub_function_id);

    if (function_id == 1) {
        // Present existence of a hypervisor using the HypervisorPresent bit
        CpuFeaturesEcx cpu_features = { static_cast<ULONG_PTR>(cpu_info[2]) };
        cpu_features.fields.not_used = true;
        cpu_info[2] = static_cast<int>(cpu_features.all);
    }
    else if (function_id == kHyperVCpuidInterface) {
        // Leave signature of HyperPlatform onto EAX
        cpu_info[0] = kHyperVCpuidMark;

        Log("cpuid:地址:%llx 进程:%s cr3:%llx \n", guest_context->ip, PsGetProcessImageFileName(PsGetCurrentProcess()), Uti::UtilVmRead(VmcsField::kGuestCr3));
    }



    guest_context->gp_regs->ax = cpu_info[0];
    guest_context->gp_regs->bx = cpu_info[1];
    guest_context->gp_regs->cx = cpu_info[2];
    guest_context->gp_regs->dx = cpu_info[3];

  

    VmmpAdjustGuestInstructionPointer(guest_context);

}


// Advances guest's IP to the next instruction
 static void VmmpAdjustGuestInstructionPointer(
    GuestContext* guest_context) {
  const auto exit_inst_length = Uti::UtilVmRead(VmcsField::kVmExitInstructionLen);
  Uti::UtilVmWrite(VmcsField::kGuestRip, guest_context->ip + exit_inst_length);

  // Inject #DB if TF is set
  if (guest_context->flag_reg.fields.tf) {
    VmmpInjectInterruption(InterruptionType::kHardwareException,
                           InterruptionVector::kDebugException, false, 0);
    Uti::UtilVmWrite(VmcsField::kVmEntryInstructionLen, exit_inst_length);
  }
}

// Injects interruption to a guest
 static void VmmpInjectInterruption(
    InterruptionType interruption_type, InterruptionVector vector,
    bool deliver_error_code, ULONG32 error_code) {
  VmEntryInterruptionInformationField inject = {};
  inject.fields.valid = true;
  inject.fields.interruption_type = static_cast<ULONG32>(interruption_type);
  inject.fields.vector = static_cast<ULONG32>(vector);
  inject.fields.deliver_error_code = deliver_error_code;
  Uti::UtilVmWrite(VmcsField::kVmEntryIntrInfoField, inject.all);

  if (deliver_error_code) {
      Uti::UtilVmWrite(VmcsField::kVmEntryExceptionErrorCode, error_code);
  }

}

// RDMSR
 static void VmmpHandleMsrReadAccess(GuestContext* guest_context) 
{

     VmmpHandleMsrAccess(guest_context, true);
}


// RDMSR and WRMSR
static void VmmpHandleMsrAccess(GuestContext *guest_context, bool read_access)
{
  // Apply it for VMCS instead of a real MSR if a specified MSR is either of
  // them.
  const auto msr = static_cast<Msr>(guest_context->gp_regs->cx);

  bool transfer_to_vmcs = false;
  VmcsField vmcs_field = {};
  switch (msr) {
    case Msr::kIa32SysenterCs:
      vmcs_field = VmcsField::kGuestSysenterCs;
      transfer_to_vmcs = true;
      break;
    case Msr::kIa32SysenterEsp:
      vmcs_field = VmcsField::kGuestSysenterEsp;
      transfer_to_vmcs = true;
      break;
    case Msr::kIa32SysenterEip:
      vmcs_field = VmcsField::kGuestSysenterEip;
      transfer_to_vmcs = true;
      break;
    case Msr::kIa32Debugctl:
      vmcs_field = VmcsField::kGuestIa32Debugctl;
      transfer_to_vmcs = true;
      break;
    case Msr::kIa32GsBase:
      vmcs_field = VmcsField::kGuestGsBase;
      transfer_to_vmcs = true;
      break;
    case Msr::kIa32FsBase:
      vmcs_field = VmcsField::kGuestFsBase;
      transfer_to_vmcs = true;
      break;
    default:
      break;
  }

  const auto is_64bit_vmcs = UtilIsInBounds(vmcs_field, VmcsField::kIoBitmapA, VmcsField::kHostIa32PerfGlobalCtrlHigh);
  LARGE_INTEGER msr_value = {};
  if (read_access) 
  {
    if (transfer_to_vmcs) 
    {
      if (is_64bit_vmcs) 
      {
        msr_value.QuadPart = Uti::UtilVmRead64(vmcs_field);
      } else 
      {
        msr_value.QuadPart = Uti::UtilVmRead(vmcs_field);
      }
    } else 
    {
      msr_value.QuadPart = Uti::UtilReadMsr64(msr);
    }
    guest_context->gp_regs->ax = msr_value.LowPart;
    guest_context->gp_regs->dx = msr_value.HighPart;
  } 
  else {
    msr_value.LowPart = static_cast<ULONG>(guest_context->gp_regs->ax);
    msr_value.HighPart = static_cast<ULONG>(guest_context->gp_regs->dx);
    if (transfer_to_vmcs) {
      if (is_64bit_vmcs) {
          Uti::UtilVmWrite64(vmcs_field, static_cast<ULONG_PTR>(msr_value.QuadPart));
      } else {
          Uti::UtilVmWrite(vmcs_field, static_cast<ULONG_PTR>(msr_value.QuadPart));
      }
    } else {
        Uti::UtilWriteMsr64(msr, msr_value.QuadPart);
    }
  }

  VmmpAdjustGuestInstructionPointer(guest_context);
}


// WRMSR
static void VmmpHandleMsrWriteAccess( GuestContext* guest_context) {
    VmmpHandleMsrAccess(guest_context, false);
}


// VMX instructions except for VMCALL
_Use_decl_annotations_ static void VmmpHandleVmx(VmExitInformation exit_reason, GuestContext* guest_context)
{
    /*
    VMXON:开启 VMX 模式,可以执行后续的虚拟化相关指令。
    VMXOFF:关闭 VMX 模式，后续虚拟化指令的执行都会失败。
    VMLAUNCH:启动 VMCS指向的虚拟机 Guest OS。
    VMRESUME:从 Hypervisor 中恢复虚拟机 Guest OS 的执行。
    VMPTRLD:激活一块 VMCS,修改处理器当前 VMCS 指针为传入的 VMCS 物理地址。
    VMCLEAR:使一块 VMCS 变为非激活状态，更新处理器当前 VMCS 指针为空。
    VMPTRST:将 VMCS 存储到指定位置。
    VMREAD:读取当前 VMCS 中的数据。
    VMWRITE:向当前 VMCS 中写入数据。
    VMCALL:Guest OS 和 Hypervisor 交互指令，Guest OS 会产生 #VMExit 而陷入 Hypervisor。
    INVEPT:使 TLB 中缓存的地址映射失效。
    INVVPID:使某个 VPID 所对应的地址映射失效。
     */

     //对于这些特殊指令只要是 Guest执行的 我们全都交给系统处理  为什么 虚拟机可以vm_off? 答:因为 我们先vmcall 然后进入了vmm模式 才执行vmoff(已经不是Guest状态)
    if (exit_reason.fields.reason == VmxExitReason::kVmcall)
    {
        if (guest_context->gp_regs->r8 == kHyperVCpuidMark)
        {
            return VmmpHandleVmCall(guest_context);
        }
    }

    //VMfailInvalid
    guest_context->flag_reg.fields.cf = true;  // Error without status
    guest_context->flag_reg.fields.pf = false;
    guest_context->flag_reg.fields.af = false;
    guest_context->flag_reg.fields.zf = false;  // Error without status
    guest_context->flag_reg.fields.sf = false;
    guest_context->flag_reg.fields.of = false;
    VmmpInjectInterruption(InterruptionType::kHardwareException, InterruptionVector::kInvalidOpcodeException, false, 0);
}



// VMCALL
_Use_decl_annotations_ static void VmmpHandleVmCall( GuestContext* guest_context) 
{
    // VMCALL convention for HyperPlatform:
    //  ecx: hyper-call number (always 32bit)
    //  edx: arbitrary context parameter (pointer size)
    // Any unsuccessful VMCALL will inject #UD into a guest
    const auto hypercall_number = static_cast<HypercallNumber>(guest_context->gp_regs->cx);
    const auto context = reinterpret_cast<void*>(guest_context->gp_regs->dx);
    switch (hypercall_number) {
    case HypercallNumber::kTerminateVmm:
        // Unloading requested. This VMCALL is allowed to execute only from CPL=0
        if (VmmpGetGuestCpl() == 0) 
        {
            VmmpHandleVmCallTermination(guest_context, context);
        }
        else 
        {
            VmmpIndicateUnsuccessfulVmcall(guest_context);
        }
        break;
    case HypercallNumber::kPingVmm:
        // Sample VMCALL handler
       // HYPERPLATFORM_LOG_INFO_SAFE("Pong by VMM! (context = %p)", context);
       // VmmpIndicateSuccessfulVmcall(guest_context);
        break;
    case HypercallNumber::kGetSharedProcessorData:
       // *reinterpret_cast<void**>(context) = guest_context->stack->processor_data->shared_data;
       // VmmpIndicateSuccessfulVmcall(guest_context);
        break;
    case HypercallNumber::kShEnablePageShadowing:
        //ShEnablePageShadowing(
        //    guest_context->stack->processor_data->ept_data,
        //    guest_context->stack->processor_data->shared_data->shared_sh_data);
        //VmmpIndicateSuccessfulVmcall(guest_context);
        break;
    case HypercallNumber::kShDisablePageShadowing:
        //ShVmCallDisablePageShadowing(
        //    guest_context->stack->processor_data->ept_data,
        //    guest_context->stack->processor_data->shared_data->shared_sh_data);
        //VmmpIndicateSuccessfulVmcall(guest_context);
        break;
    default:
        // Unsupported hypercall
        VmmpIndicateUnsuccessfulVmcall(guest_context);
    }
}

// Returns guest's CPL
/*_Use_decl_annotations_*/ static UCHAR VmmpGetGuestCpl() {
    VmxRegmentDescriptorAccessRight ar = {
        static_cast<unsigned int>(Uti::UtilVmRead(VmcsField::kGuestSsArBytes)) };
    return ar.fields.dpl;
}


// Indicates unsuccessful VMCALL
_Use_decl_annotations_ static void VmmpIndicateUnsuccessfulVmcall(
    GuestContext* guest_context) {
    UNREFERENCED_PARAMETER(guest_context);

    VmmpInjectInterruption(InterruptionType::kHardwareException,InterruptionVector::kInvalidOpcodeException, false, 0);
    const auto exit_inst_length = Uti::UtilVmRead(VmcsField::kVmExitInstructionLen);
    Uti::UtilVmWrite(VmcsField::kVmEntryInstructionLen, exit_inst_length);
}


// RDTSCP
_Use_decl_annotations_ static void VmmpHandleRdtscp(
    GuestContext* guest_context) {

    unsigned int tsc_aux = 0;
    ULARGE_INTEGER tsc = {};
    tsc.QuadPart = __rdtscp(&tsc_aux);
    guest_context->gp_regs->dx = tsc.HighPart;
    guest_context->gp_regs->ax = tsc.LowPart;
    guest_context->gp_regs->cx = tsc_aux;

    VmmpAdjustGuestInstructionPointer(guest_context);
}

// XSETBV. It is executed at the time of system resuming
_Use_decl_annotations_ static void VmmpHandleXsetbv(
    GuestContext* guest_context) {
    ULARGE_INTEGER value = {};
    value.LowPart = static_cast<ULONG>(guest_context->gp_regs->ax);
    value.HighPart = static_cast<ULONG>(guest_context->gp_regs->dx);
    _xsetbv(static_cast<ULONG>(guest_context->gp_regs->cx), value.QuadPart);

    VmmpAdjustGuestInstructionPointer(guest_context);
}

// Handles an unloading request
_Use_decl_annotations_ static void VmmpHandleVmCallTermination(
    GuestContext* guest_context, void* context) 
{
    // The processor sets ffff to limits of IDT and GDT when VM-exit occurred.
    // It is not correct value but fine to ignore since vmresume loads correct
    // values from VMCS. But here, we are going to skip vmresume and simply
    // return to where VMCALL is executed. It results in keeping those broken
    // values and ends up with bug check 109, so we should fix them manually.
    const auto gdt_limit = Uti::UtilVmRead(VmcsField::kGuestGdtrLimit);
    const auto gdt_base = Uti::UtilVmRead(VmcsField::kGuestGdtrBase);
    const auto idt_limit = Uti::UtilVmRead(VmcsField::kGuestIdtrLimit);
    const auto idt_base = Uti::UtilVmRead(VmcsField::kGuestIdtrBase);
    Gdtr gdtr = { static_cast<USHORT>(gdt_limit), gdt_base };
    Idtr idtr = { static_cast<USHORT>(idt_limit), idt_base };
    __lgdt(&gdtr);
    __lidt(&idtr);

    // Store an address of the management structure to the context parameter
    const auto result_ptr = reinterpret_cast<ProcessorData**>(context);
    *result_ptr = guest_context->stack->processor_data;

    // Set rip to the next instruction of VMCALL
    const auto exit_instruction_length =
        Uti::UtilVmRead(VmcsField::kVmExitInstructionLen);
    const auto return_address = guest_context->ip + exit_instruction_length;

    // Since the flag register is overwritten after VMXOFF, we should manually
    // indicates that VMCALL was successful by clearing those flags.
    // See: CONVENTIONS
    guest_context->flag_reg.fields.cf = false;
    guest_context->flag_reg.fields.pf = false;
    guest_context->flag_reg.fields.af = false;
    guest_context->flag_reg.fields.zf = false;
    guest_context->flag_reg.fields.sf = false;
    guest_context->flag_reg.fields.of = false;
    guest_context->flag_reg.fields.cf = false;
    guest_context->flag_reg.fields.zf = false;

    // Set registers used after VMXOFF to recover the context. Volatile
    // registers must be used because those changes are reflected to the
    // guest's context after VMXOFF.
    guest_context->gp_regs->cx = return_address;
    guest_context->gp_regs->dx = guest_context->gp_regs->sp;
    guest_context->gp_regs->ax = guest_context->flag_reg.all;
    guest_context->vm_continue = false;
}


static void VmmpHandleException(_Inout_ GuestContext* guest_context)
{
    UNREFERENCED_PARAMETER(guest_context);
    //请注意一个问题:有一个问题 为什么原作者不去判断一下 exception.fields.valid 是否有效 而是用另一个 异常 kIdtVectoringInfoField
    if (Uti::UtilVmRead(VmcsField::kIdtVectoringInfoField) & 1) 
    {
        Log("kIdtVectoringInfoField 异常有效\n");
        HYPERPLATFORM_COMMON_DBG_BREAK();
    }
    VmcsField errorCode = VmcsField::kVmExitIntrErrorCode;
    VmExitInterruptionInformationField exception = { static_cast<ULONG32>(Uti::UtilVmRead(VmcsField::kVmExitIntrInfo)) }; 
    const auto interruption_type =static_cast<InterruptionType>(exception.fields.interruption_type);
    const auto vector = static_cast<InterruptionVector>(exception.fields.vector);
    const auto error_code_valid = static_cast<bool>(exception.fields.error_code_valid);
    const auto error_code = error_code_valid ? static_cast<ULONG32>(Uti::UtilVmRead(errorCode)) : 0;
    //__debugbreak();//PS:在这里下断调试，会有蓝屏的风险，这是正常情况
    if (interruption_type == InterruptionType::kHardwareException)
    {
        // Hardware exception
        if (vector == InterruptionVector::kPageFaultException)
        {
            // #PF
            const PageFaultErrorCode fault_code = { error_code };
            const auto fault_address = Uti::UtilVmRead(VmcsField::kExitQualification);

            VmmpInjectInterruption(interruption_type, vector, error_code_valid, fault_code.all);
            AsmWriteCR2(fault_address);
            
        }
        else if (vector == InterruptionVector::kGeneralProtectionException)
        {
           
            VmmpInjectInterruption(interruption_type, vector, error_code_valid, error_code);
    
        }
        else
        {
            HYPERPLATFORM_COMMON_BUG_CHECK(HyperPlatformBugCheck::kUnspecified, 0, 0,0);
        }
    }
    else if (interruption_type == InterruptionType::kSoftwareException)
    {
        // Software exception
        if (vector == InterruptionVector::kBreakpointException) 
        {
            // #BP

            ////7FFA8C8CB290
            //ULONG64 nRsp = 0;
            //if (strcmp((char*)PsGetProcessImageFileName(PsGetCurrentProcess()), "111.exe") == 0) 
            //{
            //    //7FFE5E2FB290
            //    nRsp = Uti::UtilVmRead(VmcsField::kGuestRsp);
            //    Uti::UtilVmWrite(VmcsField::kGuestRip, 0x7FFE5E2FB290/*veh回调函数*/);
            //    return;
            //}

            VmmpInjectInterruption(interruption_type, vector, error_code_valid, error_code);
            const auto exit_inst_length = Uti::UtilVmRead(VmcsField::kVmExitInstructionLen);
            Uti::UtilVmWrite(VmcsField::kVmEntryInstructionLen, exit_inst_length);

        }
        else 
        {
            HYPERPLATFORM_COMMON_BUG_CHECK(HyperPlatformBugCheck::kUnspecified, 0, 0, 0);
        }


    }
    else 
    {
        HYPERPLATFORM_COMMON_BUG_CHECK(HyperPlatformBugCheck::kUnspecified, 0, 0, 0);
    }

}

static void VmmpHandleVmExit(GuestContext* guest_context)
{
    const VmExitInformation exit_reason = {
    static_cast<ULONG32>(Uti::UtilVmRead(VmcsField::kVmExitReason)) };
    switch (exit_reason.fields.reason)
    {
    case VmxExitReason::kExceptionOrNmi:
        VmmpHandleException(guest_context);
        break;
    case VmxExitReason::kTripleFault:
        VmmpHandleTripleFault(guest_context);
        break;
    case VmxExitReason::kCpuid:
        VmmpHandleCpuid(guest_context); //必须处理
        break;
    case VmxExitReason::kInvd://必须处理
        VmmpHandleInvalidateInternalCaches(guest_context);
        break;
    case VmxExitReason::kInvlpg:
        VmmpHandleInvalidateTlbEntry(guest_context);
        break;
    case VmxExitReason::kRdtsc:
        VmmpHandleRdtsc(guest_context);
        break;
    case VmxExitReason::kCrAccess://必须处理
        VmmpHandleCrAccess(guest_context);
        break;
    case VmxExitReason::kDrAccess://vm_procctl_requested.fields.mov_dr_exiting = true;
        VmmpHandleDrAccess(guest_context);
        break;
    case VmxExitReason::kIoInstruction:
        break;
    case VmxExitReason::kMsrRead:;
        VmmpHandleMsrReadAccess(guest_context); //必须处理
        break;
    case VmxExitReason::kMsrWrite:
        VmmpHandleMsrWriteAccess(guest_context);//必须处理
        break;
    case VmxExitReason::kMonitorTrapFlag: //vm_procctl.fields.monitor_trap_flag =true 实验1_S
        VmmpHandleMonitorTrap(guest_context);
        break;
    case VmxExitReason::kGdtrOrIdtrAccess:// vm_procctl2_requested.fields.descriptor_table_exiting = true;
        VmmpHandleGdtrOrIdtrAccess(guest_context);//实验1_F
        break;
    case VmxExitReason::kLdtrOrTrAccess:// vm_procctl2_requested.fields.descriptor_table_exiting = true;
        VmmpHandleLdtrOrTrAccess(guest_context); //实验1_F
        break;
    case VmxExitReason::kEptViolation:
        VmmpHandleEptViolation(guest_context);
        break;
    case VmxExitReason::kEptMisconfig:
        VmmpHandleEptMisconfig(guest_context);
        break;
    case VmxExitReason::kVmcall:
    case VmxExitReason::kVmclear: //问题1:接管这些指令会有什么影响? 现象:当一个核成功 Vmlaunch后 才会进入VmmpHandleVmx()处理,如果不成功,则不会进入。(多核同理)
    case VmxExitReason::kVmlaunch://还没有验证的合理猜想:如果我们这样接管这些指令后,当某个软件想要开启的时候，他的成功与否取决你的 VmmpHandleVmx的逻辑
    case VmxExitReason::kVmptrld:
    case VmxExitReason::kVmptrst:
    case VmxExitReason::kVmread:
    case VmxExitReason::kVmresume:
    case VmxExitReason::kVmwrite:
    case VmxExitReason::kVmoff:
    case VmxExitReason::kVmon:
    case VmxExitReason::kInvept:
    case VmxExitReason::kInvvpid:
        VmmpHandleVmx(exit_reason,guest_context); // 实验1_S
        break;
    case VmxExitReason::kRdtscp:
        VmmpHandleRdtscp(guest_context);//必须处理 实验1_S

        break;
    case VmxExitReason::kXsetbv:
        VmmpHandleXsetbv(guest_context);//必须处理 实验1_S
        break;
    default:
        HYPERPLATFORM_COMMON_DBG_BREAK();
        break;

    }


}


// EXIT_REASON_EPT_VIOLATION
_Use_decl_annotations_ static void VmmpHandleEptViolation(GuestContext* guest_context) 
{
    auto processor_data = guest_context->stack->processor_data;
    //ept::EptHandleEptViolation(
    //    processor_data->ept_data, processor_data->sh_data,
    //    processor_data->shared_data->shared_sh_data);
    ept::EptHandleEptViolation(processor_data->ept_data);

}

// EXIT_REASON_EPT_MISCONFIG
_Use_decl_annotations_ static void VmmpHandleEptMisconfig(GuestContext* guest_context) 
{
    //必须[0:2]有值 ！！必须[0:2]有值！！必须[0:2]有值
    //一般发生这种异常的原因 : 配置Ept表的时候  属性位 错误 或者修复不正确 （MTRR寄存器）
    /*
    * 必须[0:2]有值
    * 1.EPT->[0:2] 010B(write-only)  或者110B(write/execute) 导致->EptMisconfig
    * 2.当Ia32VmxEptVpidCapMsr->support_execute_only_pages为1  
    * 3.保留位不为0值
    * 4.memory type错误
    * 
    */


    const auto fault_address = Uti::UtilVmRead(VmcsField::kGuestPhysicalAddress);
    const auto memory_type = EptpGetMemoryType(fault_address);
    const auto ept_pt_entry = ept::EptGetEptPtEntry(guest_context->stack->processor_data->ept_data, fault_address);
    HYPERPLATFORM_COMMON_BUG_CHECK(HyperPlatformBugCheck::kEptMisconfigVmExit,fault_address,reinterpret_cast<ULONG_PTR>(ept_pt_entry), (ULONG_PTR)guest_context);
}


}