// Copyright (c) 2015-2018, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

/// @file
/// Defines constants and structures defined by the x86-64 architecture

#ifndef HYPERPLATFORM_IA32_TYPE_H_
#define HYPERPLATFORM_IA32_TYPE_H_

#include <fltKernel.h>

////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

/// See: OVERVIEW
static const SIZE_T kVmxMaxVmcsSize = 4096;

/// A majority of modern hypervisors expose their signatures through CPUID with
/// this CPUID function code to indicate their existence. HyperPlatform follows
/// this convention.
static const ULONG32 kHyperVCpuidInterface = 0xeeeeeeee;
static const ULONG32 kHyperVCpuidMark = 'VT_X';
////////////////////////////////////////////////////////////////////////////////
//
// types
//

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

/// See: SYSTEM FLAGS AND FIELDS IN THE EFLAGS REGISTER
union FlagRegister {
    ULONG_PTR all;
    struct {
        ULONG_PTR cf : 1;          //!< [0] Carry flag
        ULONG_PTR reserved1 : 1;   //!< [1] Always 1
        ULONG_PTR pf : 1;          //!< [2] Parity flag
        ULONG_PTR reserved2 : 1;   //!< [3] Always 0
        ULONG_PTR af : 1;          //!< [4] Borrow flag
        ULONG_PTR reserved3 : 1;   //!< [5] Always 0
        ULONG_PTR zf : 1;          //!< [6] Zero flag
        ULONG_PTR sf : 1;          //!< [7] Sign flag
        ULONG_PTR tf : 1;          //!< [8] Trap flag
        ULONG_PTR intf : 1;        //!< [9] Interrupt flag
        ULONG_PTR df : 1;          //!< [10] Direction flag
        ULONG_PTR of : 1;          //!< [11] Overflow flag
        ULONG_PTR iopl : 2;        //!< [12:13] I/O privilege level
        ULONG_PTR nt : 1;          //!< [14] Nested task flag
        ULONG_PTR reserved4 : 1;   //!< [15] Always 0
        ULONG_PTR rf : 1;          //!< [16] Resume flag
        ULONG_PTR vm : 1;          //!< [17] Virtual 8086 mode
        ULONG_PTR ac : 1;          //!< [18] Alignment check
        ULONG_PTR vif : 1;         //!< [19] Virtual interrupt flag
        ULONG_PTR vip : 1;         //!< [20] Virtual interrupt pending
        ULONG_PTR id : 1;          //!< [21] Identification flag
        ULONG_PTR reserved5 : 10;  //!< [22:31] Always 0
    } fields;
};
static_assert(sizeof(FlagRegister) == sizeof(void*), "Size check");





struct M128EX {
    ULONGLONG Low;
    ULONGLONG High;
};
/// Represents a stack layout after PUSHAQ
struct GpRegistersX64 {

    M128EX Xmm0;
    M128EX Xmm1;
    M128EX Xmm2;
    M128EX Xmm3;
    M128EX Xmm4;
    M128EX Xmm5;
    M128EX Xmm6;
    M128EX Xmm7;
    M128EX Xmm8;
    M128EX Xmm9;
    M128EX Xmm10;
    M128EX Xmm11;
    M128EX Xmm12;
    M128EX Xmm13;
    M128EX Xmm14;
    M128EX Xmm15;
    ULONG_PTR r15;
    ULONG_PTR r14;
    ULONG_PTR r13;
    ULONG_PTR r12;
    ULONG_PTR r11;
    ULONG_PTR r10;
    ULONG_PTR r9;
    ULONG_PTR r8;
    ULONG_PTR di;
    ULONG_PTR si;
    ULONG_PTR bp;
    ULONG_PTR sp;
    ULONG_PTR bx;
    ULONG_PTR dx;
    ULONG_PTR cx;
    ULONG_PTR ax;
};

/// Represents a stack layout after PUSHAD
struct GpRegistersX86 {
    ULONG_PTR di;
    ULONG_PTR si;
    ULONG_PTR bp;
    ULONG_PTR sp;
    ULONG_PTR bx;
    ULONG_PTR dx;
    ULONG_PTR cx;
    ULONG_PTR ax;
};

/// Represents a stack layout after PUSHAx
#if defined(_AMD64_)
using GpRegisters = GpRegistersX64;
#else
using GpRegisters = GpRegistersX86;
#endif

/// Represents a stack layout after a sequence of PUSHFx, PUSHAx
struct AllRegisters {
    GpRegisters gp;
    FlagRegister flags;
};
#if defined(_AMD64_)
static_assert(sizeof(AllRegisters) == 0x188, "Size check");
#else
static_assert(sizeof(AllRegisters) == 0x24, "Size check");
#endif

/// See: CONTROL REGISTERS
union Cr0 {
    ULONG_PTR all;
    struct {
        unsigned pe : 1;          //!< [0] Protected Mode Enabled
        unsigned mp : 1;          //!< [1] Monitor Coprocessor FLAG
        unsigned em : 1;          //!< [2] Emulate FLAG
        unsigned ts : 1;          //!< [3] Task Switched FLAG
        unsigned et : 1;          //!< [4] Extension Type FLAG
        unsigned ne : 1;          //!< [5] Numeric Error
        unsigned reserved1 : 10;  //!< [6:15]
        unsigned wp : 1;          //!< [16] Write Protect
        unsigned reserved2 : 1;   //!< [17]
        unsigned am : 1;          //!< [18] Alignment Mask
        unsigned reserved3 : 10;  //!< [19:28]
        unsigned nw : 1;          //!< [29] Not Write-Through
        unsigned cd : 1;          //!< [30] Cache Disable
        unsigned pg : 1;          //!< [31] Paging Enabled
    } fields;
};
static_assert(sizeof(Cr0) == sizeof(void*), "Size check");

/// See: CONTROL REGISTERS
union Cr4 {
    ULONG_PTR all;
    struct {
        unsigned vme : 1;         //!< [0] Virtual Mode Extensions
        unsigned pvi : 1;         //!< [1] Protected-Mode Virtual Interrupts
        unsigned tsd : 1;         //!< [2] Time Stamp Disable
        unsigned de : 1;          //!< [3] Debugging Extensions
        unsigned pse : 1;         //!< [4] Page Size Extensions
        unsigned pae : 1;         //!< [5] Physical Address Extension
        unsigned mce : 1;         //!< [6] Machine-Check Enable
        unsigned pge : 1;         //!< [7] Page Global Enable
        unsigned pce : 1;         //!< [8] Performance-Monitoring Counter Enable
        unsigned osfxsr : 1;      //!< [9] OS Support for FXSAVE/FXRSTOR
        unsigned osxmmexcpt : 1;  //!< [10] OS Support for Unmasked SIMD Exceptions
        unsigned reserved1 : 2;   //!< [11:12]
        unsigned vmxe : 1;        //!< [13] Virtual Machine Extensions Enabled
        unsigned smxe : 1;        //!< [14] SMX-Enable Bit
        unsigned reserved2 : 2;   //!< [15:16]
        unsigned pcide : 1;       //!< [17] PCID Enable
        unsigned osxsave : 1;  //!< [18] XSAVE and Processor Extended States-Enable
        unsigned reserved3 : 1;  //!< [19]
        unsigned smep : 1;  //!< [20] Supervisor Mode Execution Protection Enable
        unsigned smap : 1;  //!< [21] Supervisor Mode Access Protection Enable
    } fields;
};
static_assert(sizeof(Cr4) == sizeof(void*), "Size check");

/// See: Debug Status Register (DR6)
union Dr6 {
    ULONG_PTR all;
    struct {
        unsigned b0 : 1;          //!< [0] Breakpoint Condition Detected 0
        unsigned b1 : 1;          //!< [1] Breakpoint Condition Detected 1
        unsigned b2 : 1;          //!< [2] Breakpoint Condition Detected 2
        unsigned b3 : 1;          //!< [3] Breakpoint Condition Detected 3
        unsigned reserved1 : 8;   //!< [4:11] Always 1
        unsigned reserved2 : 1;   //!< [12] Always 0
        unsigned bd : 1;          //!< [13] Debug Register Access Detected
        unsigned bs : 1;          //!< [14] Single Step
        unsigned bt : 1;          //!< [15] Task Switch
        unsigned rtm : 1;         //!< [16] Restricted Transactional Memory
        unsigned reserved3 : 15;  //!< [17:31] Always 1
    } fields;
};
static_assert(sizeof(Dr6) == sizeof(void*), "Size check");

/// See: Debug Control Register (DR7)
union Dr7 {
    ULONG_PTR all;
    struct {
        unsigned l0 : 1;         //!< [0] Local Breakpoint Enable 0
        unsigned g0 : 1;         //!< [1] Global Breakpoint Enable 0
        unsigned l1 : 1;         //!< [2] Local Breakpoint Enable 1
        unsigned g1 : 1;         //!< [3] Global Breakpoint Enable 1
        unsigned l2 : 1;         //!< [4] Local Breakpoint Enable 2
        unsigned g2 : 1;         //!< [5] Global Breakpoint Enable 2
        unsigned l3 : 1;         //!< [6] Local Breakpoint Enable 3
        unsigned g3 : 1;         //!< [7] Global Breakpoint Enable 3
        unsigned le : 1;         //!< [8] Local Exact Breakpoint Enable
        unsigned ge : 1;         //!< [9] Global Exact Breakpoint Enable
        unsigned reserved1 : 1;  //!< [10] Always 1
        unsigned rtm : 1;        //!< [11] Restricted Transactional Memory
        unsigned reserved2 : 1;  //!< [12] Always 0
        unsigned gd : 1;         //!< [13] General Detect Enable 当DR7.GD=1时，对任何一个debug寄存器的访问都会产生#DB异常 处理器在进入#DB handler前会将GD清位，这将允许在#DB handler内访问debug寄存器。
        unsigned reserved3 : 2;  //!< [14:15] Always 0
        unsigned rw0 : 2;        //!< [16:17] Read / Write 0
        unsigned len0 : 2;       //!< [18:19] Length 0
        unsigned rw1 : 2;        //!< [20:21] Read / Write 1
        unsigned len1 : 2;       //!< [22:23] Length 1
        unsigned rw2 : 2;        //!< [24:25] Read / Write 2
        unsigned len2 : 2;       //!< [26:27] Length 2
        unsigned rw3 : 2;        //!< [28:29] Read / Write 3
        unsigned len3 : 2;       //!< [30:31] Length 3
    } fields;
};
static_assert(sizeof(Dr7) == sizeof(void*), "Size check");

/// See: MEMORY-MANAGEMENT REGISTERS
#include <pshpack1.h>
struct Idtr {
    unsigned short limit;
    ULONG_PTR base;
};

struct Idtr32 {
    unsigned short limit;
    ULONG32 base;
};
static_assert(sizeof(Idtr32) == 6, "Size check");

/// @copydoc Idtr
using Gdtr = Idtr;
#if defined(_AMD64_)
static_assert(sizeof(Idtr) == 10, "Size check");
static_assert(sizeof(Gdtr) == 10, "Size check");
#else
static_assert(sizeof(Idtr) == 6, "Size check");
static_assert(sizeof(Gdtr) == 6, "Size check");
#endif
#include <poppack.h>

/// IDT entry (nt!_KIDTENTRY)
#include <pshpack1.h>
union KidtEntry {
    ULONG64 all;
    struct {
        unsigned short offset_low;
        unsigned short selector;
        unsigned char ist_index : 3;  //!< [0:2]
        unsigned char reserved : 5;   //!< [3:7]
        unsigned char type : 5;       //!< [8:12]
        unsigned char dpl : 2;        //!< [13:14]
        unsigned char present : 1;    //!< [15]
        unsigned short offset_middle;
    } fields;
};
static_assert(sizeof(KidtEntry) == 8, "Size check");
#include <poppack.h>

/// IDT entry for x64 (nt!_KIDTENTRY64)
#include <pshpack1.h>
struct KidtEntry64 {
    KidtEntry idt_entry;
    ULONG32 offset_high;
    ULONG32 reserved;
};
static_assert(sizeof(KidtEntry64) == 16, "Size check");
#include <poppack.h>

/// See: Segment Selectors
#include <pshpack1.h>
union SegmentSelector {
    unsigned short all;
    struct {
        unsigned short rpl : 2;  //!< Requested Privilege Level
        unsigned short ti : 1;   //!< Table Indicator
        unsigned short index : 13;
    } fields;
};
static_assert(sizeof(SegmentSelector) == 2, "Size check");
#include <poppack.h>

/// See: Segment Descriptor
union SegmentDescriptor {
    ULONG64 all;
    struct {
        ULONG64 limit_low : 16;
        ULONG64 base_low : 16;
        ULONG64 base_mid : 8;
        ULONG64 type : 4;
        ULONG64 system : 1;
        ULONG64 dpl : 2;
        ULONG64 present : 1;
        ULONG64 limit_high : 4;
        ULONG64 avl : 1;
        ULONG64 l : 1;  //!< 64-bit code segment (IA-32e mode only)
        ULONG64 db : 1;
        ULONG64 gran : 1;
        ULONG64 base_high : 8;
    } fields;
};
static_assert(sizeof(SegmentDescriptor) == 8, "Size check");

/// @copydoc SegmentDescriptor
struct SegmentDesctiptorX64 {
    SegmentDescriptor descriptor;
    ULONG32 base_upper32;
    ULONG32 reserved;
};
static_assert(sizeof(SegmentDesctiptorX64) == 16, "Size check");

/// See: Feature Information Returned in the ECX Register
union CpuFeaturesEcx {
    ULONG32 all;
    struct {
        ULONG32 sse3 : 1;       //!< [0] Streaming SIMD Extensions 3 (SSE3)
        ULONG32 pclmulqdq : 1;  //!< [1] PCLMULQDQ
        ULONG32 dtes64 : 1;     //!< [2] 64-bit DS Area
        ULONG32 monitor : 1;    //!< [3] MONITOR/WAIT
        ULONG32 ds_cpl : 1;     //!< [4] CPL qualified Debug Store
        ULONG32 vmx : 1;        //!< [5] Virtual Machine Technology
        ULONG32 smx : 1;        //!< [6] Safer Mode Extensions
        ULONG32 est : 1;        //!< [7] Enhanced Intel Speedstep Technology
        ULONG32 tm2 : 1;        //!< [8] Thermal monitor 2
        ULONG32 ssse3 : 1;      //!< [9] Supplemental Streaming SIMD Extensions 3
        ULONG32 cid : 1;        //!< [10] L1 context ID
        ULONG32 sdbg : 1;       //!< [11] IA32_DEBUG_INTERFACE MSR
        ULONG32 fma : 1;        //!< [12] FMA extensions using YMM state
        ULONG32 cx16 : 1;       //!< [13] CMPXCHG16B
        ULONG32 xtpr : 1;       //!< [14] xTPR Update Control
        ULONG32 pdcm : 1;       //!< [15] Performance/Debug capability MSR
        ULONG32 reserved : 1;   //!< [16] Reserved
        ULONG32 pcid : 1;       //!< [17] Process-context identifiers
        ULONG32 dca : 1;        //!< [18] prefetch from a memory mapped device
        ULONG32 sse4_1 : 1;     //!< [19] SSE4.1
        ULONG32 sse4_2 : 1;     //!< [20] SSE4.2
        ULONG32 x2_apic : 1;    //!< [21] x2APIC feature
        ULONG32 movbe : 1;      //!< [22] MOVBE instruction
        ULONG32 popcnt : 1;     //!< [23] POPCNT instruction
        ULONG32 reserved3 : 1;  //!< [24] one-shot operation using a TSC deadline
        ULONG32 aes : 1;        //!< [25] AESNI instruction
        ULONG32 xsave : 1;      //!< [26] XSAVE/XRSTOR feature
        ULONG32 osxsave : 1;    //!< [27] enable XSETBV/XGETBV instructions
        ULONG32 avx : 1;        //!< [28] AVX instruction extensions
        ULONG32 f16c : 1;       //!< [29] 16-bit floating-point conversion
        ULONG32 rdrand : 1;     //!< [30] RDRAND instruction
        ULONG32 not_used : 1;   //!< [31] Always 0 (a.k.a. HypervisorPresent)
    } fields;
};
static_assert(sizeof(CpuFeaturesEcx) == 4, "Size check");

/// See: More on Feature Information Returned in the EDX Register
union CpuFeaturesEdx {
    ULONG32 all;
    struct {
        ULONG32 fpu : 1;        //!< [0] Floating Point Unit On-Chip
        ULONG32 vme : 1;        //!< [1] Virtual 8086 Mode Enhancements
        ULONG32 de : 1;         //!< [2] Debugging Extensions
        ULONG32 pse : 1;        //!< [3] Page Size Extension
        ULONG32 tsc : 1;        //!< [4] Time Stamp Counter
        ULONG32 msr : 1;        //!< [5] RDMSR and WRMSR Instructions
        ULONG32 mce : 1;        //!< [7] Machine Check Exception
        ULONG32 cx8 : 1;        //!< [8] Thermal monitor 2
        ULONG32 apic : 1;       //!< [9] APIC On-Chip
        ULONG32 reserved1 : 1;  //!< [10] Reserved
        ULONG32 sep : 1;        //!< [11] SYSENTER and SYSEXIT Instructions
        ULONG32 mtrr : 1;       //!< [12] Memory Type Range Registers
        ULONG32 pge : 1;        //!< [13] Page Global Bit
        ULONG32 mca : 1;        //!< [14] Machine Check Architecture
        ULONG32 cmov : 1;       //!< [15] Conditional Move Instructions
        ULONG32 pat : 1;        //!< [16] Page Attribute Table
        ULONG32 pse36 : 1;      //!< [17] 36-Bit Page Size Extension
        ULONG32 psn : 1;        //!< [18] Processor Serial Number
        ULONG32 clfsh : 1;      //!< [19] CLFLUSH Instruction
        ULONG32 reserved2 : 1;  //!< [20] Reserved
        ULONG32 ds : 1;         //!< [21] Debug Store
        ULONG32 acpi : 1;       //!< [22] TM and Software Controlled Clock
        ULONG32 mmx : 1;        //!< [23] Intel MMX Technology
        ULONG32 fxsr : 1;       //!< [24] FXSAVE and FXRSTOR Instructions
        ULONG32 sse : 1;        //!< [25] SSE
        ULONG32 sse2 : 1;       //!< [26] SSE2
        ULONG32 ss : 1;         //!< [27] Self Snoop
        ULONG32 htt : 1;        //!< [28] Max APIC IDs reserved field is Valid
        ULONG32 tm : 1;         //!< [29] Thermal Monitor
        ULONG32 reserved3 : 1;  //!< [30] Reserved
        ULONG32 pbe : 1;        //!< [31] Pending Break Enable
    } fields;
};
static_assert(sizeof(CpuFeaturesEdx) == 4, "Size check");

/// nt!_HARDWARE_PTE on x86 PAE-disabled Windows
struct HardwarePteX86 {
    ULONG valid : 1;               //!< [0]
    ULONG write : 1;               //!< [1]
    ULONG owner : 1;               //!< [2]
    ULONG write_through : 1;       //!< [3]
    ULONG cache_disable : 1;       //!< [4]
    ULONG accessed : 1;            //!< [5]
    ULONG dirty : 1;               //!< [6]
    ULONG large_page : 1;          //!< [7]
    ULONG global : 1;              //!< [8]
    ULONG copy_on_write : 1;       //!< [9]
    ULONG prototype : 1;           //!< [10]
    ULONG reserved0 : 1;           //!< [11]
    ULONG page_frame_number : 20;  //!< [12:31]
};
static_assert(sizeof(HardwarePteX86) == 4, "Size check");

/// nt!_HARDWARE_PTE on x86 PAE-enabled Windows
struct HardwarePteX86Pae {
    ULONG64 valid : 1;               //!< [0]
    ULONG64 write : 1;               //!< [1]
    ULONG64 owner : 1;               //!< [2]
    ULONG64 write_through : 1;       //!< [3]     PWT
    ULONG64 cache_disable : 1;       //!< [4]     PCD
    ULONG64 accessed : 1;            //!< [5]
    ULONG64 dirty : 1;               //!< [6]
    ULONG64 large_page : 1;          //!< [7]     PAT
    ULONG64 global : 1;              //!< [8]
    ULONG64 copy_on_write : 1;       //!< [9]
    ULONG64 prototype : 1;           //!< [10]
    ULONG64 reserved0 : 1;           //!< [11]
    ULONG64 page_frame_number : 26;  //!< [12:37]
    ULONG64 reserved1 : 25;          //!< [38:62]
    ULONG64 no_execute : 1;          //!< [63]
};
static_assert(sizeof(HardwarePteX86Pae) == 8, "Size check");

/// nt!_HARDWARE_PTE on x64 Windows
struct HardwarePteX64 {
    ULONG64 valid : 1;               //!< [0]
    ULONG64 write : 1;               //!< [1]
    ULONG64 owner : 1;               //!< [2]
    ULONG64 write_through : 1;       //!< [3]     PWT
    ULONG64 cache_disable : 1;       //!< [4]     PCD
    ULONG64 accessed : 1;            //!< [5]
    ULONG64 dirty : 1;               //!< [6]
    ULONG64 large_page : 1;          //!< [7]     PAT
    ULONG64 global : 1;              //!< [8]
    ULONG64 copy_on_write : 1;       //!< [9]
    ULONG64 prototype : 1;           //!< [10]
    ULONG64 reserved0 : 1;           //!< [11]
    ULONG64 page_frame_number : 36;  //!< [12:47]
    ULONG64 reserved1 : 4;           //!< [48:51]
    ULONG64 software_ws_index : 11;  //!< [52:62]
    ULONG64 no_execute : 1;          //!< [63]
};
static_assert(sizeof(HardwarePteX64) == 8, "Size check");

/// nt!_HARDWARE_PTE on ARM Windows
struct HardwarePteARM {
    ULONG no_execute : 1;
    ULONG present : 1;
    ULONG unknown1 : 5;
    ULONG writable : 1;
    ULONG unknown2 : 4;
    ULONG page_frame_number : 20;
};
static_assert(sizeof(HardwarePteARM) == 4, "Size check");

/// nt!_HARDWARE_PTE on the current platform
#if defined(_X86_)
using HardwarePte = HardwarePteX86;
#elif defined(_AMD64_)
using HardwarePte = HardwarePteX64;
#elif defined(_ARM_)
using HardwarePte = HardwarePteARM;
#endif

/// See: Use of CR3 with PAE Paging
union PaeCr3 {
    ULONG64 all;
    struct {
        ULONG64 ignored1 : 5;                          //!< [0:4]
        ULONG64 page_directory_pointer_table_pa : 27;  //!< [5:31]
        ULONG64 ignored2 : 32;                         //!< [32:63]
    } fields;
};
static_assert(sizeof(PaeCr3) == 8, "Size check");

/// See: PDPTE Registers
union PdptrRegister {
    ULONG64 all;
    struct {
        ULONG64 present : 1;             //!< [0]
        ULONG64 reserved1 : 2;           //!< [1:2]
        ULONG64 write_through : 1;       //!< [3]
        ULONG64 cache_disable : 1;       //!< [4]
        ULONG64 reserved2 : 4;           //!< [5:8]
        ULONG64 ignored : 3;             //!< [9:11]
        ULONG64 page_directory_pa : 41;  //!< [12:52]
        ULONG64 reserved3 : 11;          //!< [53:63]
    } fields;
};
static_assert(sizeof(PdptrRegister) == 8, "Size check");

/// See: Information Returned by CPUID Instruction
union Cpuid80000008Eax {
    ULONG32 all;
    struct {
        ULONG32 physical_address_bits : 8;  //!< [0:7]
        ULONG32 linear_address_bits : 8;    //!< [8:15]
    } fields;
};

/// See: IA32_MTRRCAP Register
union Ia32MtrrCapabilitiesMsr {
    ULONG64 all;
    struct {
        ULONG64 variable_range_count : 8;   //<! [0:7]
        ULONG64 fixed_range_supported : 1;  //<! [8]
        ULONG64 reserved : 1;               //<! [9]
        ULONG64 write_combining : 1;        //<! [10]
        ULONG64 smrr : 1;                   //<! [11]
    } fields;
};
static_assert(sizeof(Ia32MtrrCapabilitiesMsr) == 8, "Size check");

/// See: IA32_MTRR_DEF_TYPE MSR
union Ia32MtrrDefaultTypeMsr {
    ULONG64 all;
    struct {
        ULONG64 default_mtemory_type : 8;  //<! [0:7]
        ULONG64 reserved : 2;              //<! [8:9]
        ULONG64 fixed_mtrrs_enabled : 1;   //<! [10]
        ULONG64 mtrrs_enabled : 1;         //<! [11]
    } fields;
};
static_assert(sizeof(Ia32MtrrDefaultTypeMsr) == 8, "Size check");

/// See: Fixed Range MTRRs
union Ia32MtrrFixedRangeMsr {
    ULONG64 all;
    struct {
        UCHAR types[8];
    } fields;
};
static_assert(sizeof(Ia32MtrrFixedRangeMsr) == 8, "Size check");

/// See: IA32_MTRR_PHYSBASEn and IA32_MTRR_PHYSMASKn Variable-Range Register
/// Pair
union Ia32MtrrPhysBaseMsr {
    ULONG64 all;
    struct {
        ULONG64 type : 8;        //!< [0:7]
        ULONG64 reserved : 4;    //!< [8:11]
        ULONG64 phys_base : 36;  //!< [12:MAXPHYADDR]
    } fields;
};
static_assert(sizeof(Ia32MtrrPhysBaseMsr) == 8, "Size check");

/// See: IA32_MTRR_PHYSBASEn and IA32_MTRR_PHYSMASKn Variable-Range Register
/// Pair
union Ia32MtrrPhysMaskMsr {
    ULONG64 all;
    struct {
        ULONG64 reserved : 11;   //!< [0:10]
        ULONG64 valid : 1;       //!< [11]
        ULONG64 phys_mask : 36;  //!< [12:MAXPHYADDR]
    } fields;
};
static_assert(sizeof(Ia32MtrrPhysMaskMsr) == 8, "Size check");

/// See: IA32_APIC_BASE MSR Supporting x2APIC
union Ia32ApicBaseMsr {
    ULONG64 all;
    struct {
        ULONG64 reserved1 : 8;            //!< [0:7]
        ULONG64 bootstrap_processor : 1;  //!< [8]
        ULONG64 reserved2 : 1;            //!< [9]
        ULONG64 enable_x2apic_mode : 1;   //!< [10]
        ULONG64 enable_xapic_global : 1;  //!< [11]
        ULONG64 apic_base : 24;           //!< [12:35]
    } fields;
};
static_assert(sizeof(Ia32ApicBaseMsr) == 8, "Size check");

/// See: MODEL-SPECIFIC REGISTERS (MSRS)
enum class Msr : unsigned int {
    kIa32ApicBase = 0x01B,

    kIa32FeatureControl = 0x03A,

    kIa32SysenterCs = 0x174,
    kIa32SysenterEsp = 0x175,
    kIa32SysenterEip = 0x176,

    kIa32Debugctl = 0x1D9,

    kIa32MtrrCap = 0xFE,
    kIa32MtrrDefType = 0x2FF,
    kIa32MtrrPhysBaseN = 0x200,
    kIa32MtrrPhysMaskN = 0x201,
    kIa32MtrrFix64k00000 = 0x250,
    kIa32MtrrFix16k80000 = 0x258,
    kIa32MtrrFix16kA0000 = 0x259,
    kIa32MtrrFix4kC0000 = 0x268,
    kIa32MtrrFix4kC8000 = 0x269,
    kIa32MtrrFix4kD0000 = 0x26A,
    kIa32MtrrFix4kD8000 = 0x26B,
    kIa32MtrrFix4kE0000 = 0x26C,
    kIa32MtrrFix4kE8000 = 0x26D,
    kIa32MtrrFix4kF0000 = 0x26E,
    kIa32MtrrFix4kF8000 = 0x26F,

    kIa32VmxBasic = 0x480,
    kIa32VmxPinbasedCtls = 0x481,
    kIa32VmxProcBasedCtls = 0x482,
    kIa32VmxExitCtls = 0x483,
    kIa32VmxEntryCtls = 0x484,
    kIa32VmxMisc = 0x485,
    kIa32VmxCr0Fixed0 = 0x486,
    kIa32VmxCr0Fixed1 = 0x487,
    kIa32VmxCr4Fixed0 = 0x488,
    kIa32VmxCr4Fixed1 = 0x489,
    kIa32VmxVmcsEnum = 0x48A,
    kIa32VmxProcBasedCtls2 = 0x48B,
    kIa32VmxEptVpidCap = 0x48C,
    kIa32VmxTruePinbasedCtls = 0x48D,
    kIa32VmxTrueProcBasedCtls = 0x48E,
    kIa32VmxTrueExitCtls = 0x48F,
    kIa32VmxTrueEntryCtls = 0x490,
    kIa32VmxVmfunc = 0x491,

    kIa32Efer = 0xC0000080,
    kIa32Star = 0xC0000081,
    kIa32Lstar = 0xC0000082,

    kIa32Fmask = 0xC0000084,

    kIa32FsBase = 0xC0000100,
    kIa32GsBase = 0xC0000101,
    kIa32KernelGsBase = 0xC0000102,
    kIa32TscAux = 0xC0000103,
};

/// See: Page-Fault Error Code
union PageFaultErrorCode {
    ULONG32 all;
    struct {
        ULONG32 present : 1;   //!< [1] 0= NotPresent
        ULONG32 write : 1;     //!< [2] 0= Read
        ULONG32 user : 1;      //!< [3] 0= CPL==0
        ULONG32 reserved : 1;  //!< [4]
        ULONG32 fetch : 1;     //!< [5]
    } fields;
};
static_assert(sizeof(PageFaultErrorCode) == 4, "Size check");

/// See: FIELD ENCODING IN VMCS
enum class VmcsField : unsigned __int32 {
    // 16-Bit Control Field
    kVirtualProcessorId = 0x00000000,
    kPostedInterruptNotification = 0x00000002,
    kEptpIndex = 0x00000004,
    // 16-Bit Guest-State Fields
    kGuestEsSelector = 0x00000800,
    kGuestCsSelector = 0x00000802,
    kGuestSsSelector = 0x00000804,
    kGuestDsSelector = 0x00000806,
    kGuestFsSelector = 0x00000808,
    kGuestGsSelector = 0x0000080a,
    kGuestLdtrSelector = 0x0000080c,
    kGuestTrSelector = 0x0000080e,
    kGuestInterruptStatus = 0x00000810,
    kPmlIndex = 0x00000812,
    // 16-Bit Host-State Fields
    kHostEsSelector = 0x00000c00,
    kHostCsSelector = 0x00000c02,
    kHostSsSelector = 0x00000c04,
    kHostDsSelector = 0x00000c06,
    kHostFsSelector = 0x00000c08,
    kHostGsSelector = 0x00000c0a,
    kHostTrSelector = 0x00000c0c,
    // 64-Bit Control Fields
    kIoBitmapA = 0x00002000,
    kIoBitmapAHigh = 0x00002001,
    kIoBitmapB = 0x00002002,
    kIoBitmapBHigh = 0x00002003,
    kMsrBitmap = 0x00002004,
    kMsrBitmapHigh = 0x00002005,
    kVmExitMsrStoreAddr = 0x00002006,
    kVmExitMsrStoreAddrHigh = 0x00002007,
    kVmExitMsrLoadAddr = 0x00002008,
    kVmExitMsrLoadAddrHigh = 0x00002009,
    kVmEntryMsrLoadAddr = 0x0000200a,
    kVmEntryMsrLoadAddrHigh = 0x0000200b,
    kExecutiveVmcsPointer = 0x0000200c,
    kExecutiveVmcsPointerHigh = 0x0000200d,
    kTscOffset = 0x00002010,
    kTscOffsetHigh = 0x00002011,
    kVirtualApicPageAddr = 0x00002012,
    kVirtualApicPageAddrHigh = 0x00002013,
    kApicAccessAddr = 0x00002014,
    kApicAccessAddrHigh = 0x00002015,
    kEptPointer = 0x0000201a,
    kEptPointerHigh = 0x0000201b,
    kEoiExitBitmap0 = 0x0000201c,
    kEoiExitBitmap0High = 0x0000201d,
    kEoiExitBitmap1 = 0x0000201e,
    kEoiExitBitmap1High = 0x0000201f,
    kEoiExitBitmap2 = 0x00002020,
    kEoiExitBitmap2High = 0x00002021,
    kEoiExitBitmap3 = 0x00002022,
    kEoiExitBitmap3High = 0x00002023,
    kEptpListAddress = 0x00002024,
    kEptpListAddressHigh = 0x00002025,
    kVmreadBitmapAddress = 0x00002026,
    kVmreadBitmapAddressHigh = 0x00002027,
    kVmwriteBitmapAddress = 0x00002028,
    kVmwriteBitmapAddressHigh = 0x00002029,
    kVirtualizationExceptionInfoAddress = 0x0000202a,
    kVirtualizationExceptionInfoAddressHigh = 0x0000202b,
    kXssExitingBitmap = 0x0000202c,
    kXssExitingBitmapHigh = 0x0000202d,
    kEnclsExitingBitmap = 0x0000202e,
    kEnclsExitingBitmapHigh = 0x0000202f,
    kTscMultiplier = 0x00002032,
    kTscMultiplierHigh = 0x00002033,
    // 64-Bit Read-Only Data Field
    kGuestPhysicalAddress = 0x00002400,
    kGuestPhysicalAddressHigh = 0x00002401,
    // 64-Bit Guest-State Fields
    kVmcsLinkPointer = 0x00002800,
    kVmcsLinkPointerHigh = 0x00002801,
    kGuestIa32Debugctl = 0x00002802,
    kGuestIa32DebugctlHigh = 0x00002803,
    kGuestIa32Pat = 0x00002804,
    kGuestIa32PatHigh = 0x00002805,
    kGuestIa32Efer = 0x00002806,
    kGuestIa32EferHigh = 0x00002807,
    kGuestIa32PerfGlobalCtrl = 0x00002808,
    kGuestIa32PerfGlobalCtrlHigh = 0x00002809,
    kGuestPdptr0 = 0x0000280a,
    kGuestPdptr0High = 0x0000280b,
    kGuestPdptr1 = 0x0000280c,
    kGuestPdptr1High = 0x0000280d,
    kGuestPdptr2 = 0x0000280e,
    kGuestPdptr2High = 0x0000280f,
    kGuestPdptr3 = 0x00002810,
    kGuestPdptr3High = 0x00002811,
    kGuestIa32Bndcfgs = 0x00002812,
    kGuestIa32BndcfgsHigh = 0x00002813,
    // 64-Bit Host-State Fields
    kHostIa32Pat = 0x00002c00,
    kHostIa32PatHigh = 0x00002c01,
    kHostIa32Efer = 0x00002c02,
    kHostIa32EferHigh = 0x00002c03,
    kHostIa32PerfGlobalCtrl = 0x00002c04,
    kHostIa32PerfGlobalCtrlHigh = 0x00002c05,
    // 32-Bit Control Fields
    kPinBasedVmExecControl = 0x00004000,
    kCpuBasedVmExecControl = 0x00004002,
    kExceptionBitmap = 0x00004004,
    kPageFaultErrorCodeMask = 0x00004006,
    kPageFaultErrorCodeMatch = 0x00004008,
    kCr3TargetCount = 0x0000400a,
    kVmExitControls = 0x0000400c,
    kVmExitMsrStoreCount = 0x0000400e,
    kVmExitMsrLoadCount = 0x00004010,
    kVmEntryControls = 0x00004012,
    kVmEntryMsrLoadCount = 0x00004014,
    kVmEntryIntrInfoField = 0x00004016,
    kVmEntryExceptionErrorCode = 0x00004018,
    kVmEntryInstructionLen = 0x0000401a,
    kTprThreshold = 0x0000401c,
    kSecondaryVmExecControl = 0x0000401e,
    kPleGap = 0x00004020,
    kPleWindow = 0x00004022,
    // 32-Bit Read-Only Data Fields
    kVmInstructionError = 0x00004400,  // See: VM-Instruction Error Numbers
    kVmExitReason = 0x00004402,
    kVmExitIntrInfo = 0x00004404,
    kVmExitIntrErrorCode = 0x00004406,
    kIdtVectoringInfoField = 0x00004408,
    kIdtVectoringErrorCode = 0x0000440a,
    kVmExitInstructionLen = 0x0000440c,
    kVmxInstructionInfo = 0x0000440e,
    // 32-Bit Guest-State Fields
    kGuestEsLimit = 0x00004800,
    kGuestCsLimit = 0x00004802,
    kGuestSsLimit = 0x00004804,
    kGuestDsLimit = 0x00004806,
    kGuestFsLimit = 0x00004808,
    kGuestGsLimit = 0x0000480a,
    kGuestLdtrLimit = 0x0000480c,
    kGuestTrLimit = 0x0000480e,
    kGuestGdtrLimit = 0x00004810,
    kGuestIdtrLimit = 0x00004812,
    kGuestEsArBytes = 0x00004814,
    kGuestCsArBytes = 0x00004816,
    kGuestSsArBytes = 0x00004818,
    kGuestDsArBytes = 0x0000481a,
    kGuestFsArBytes = 0x0000481c,
    kGuestGsArBytes = 0x0000481e,
    kGuestLdtrArBytes = 0x00004820,
    kGuestTrArBytes = 0x00004822,
    kGuestInterruptibilityInfo = 0x00004824,
    kGuestActivityState = 0x00004826,
    kGuestSmbase = 0x00004828,
    kGuestSysenterCs = 0x0000482a,
    kVmxPreemptionTimerValue = 0x0000482e,
    // 32-Bit Host-State Field
    kHostIa32SysenterCs = 0x00004c00,
    // Natural-Width Control Fields
    kCr0GuestHostMask = 0x00006000,
    kCr4GuestHostMask = 0x00006002,
    kCr0ReadShadow = 0x00006004,
    kCr4ReadShadow = 0x00006006,
    kCr3TargetValue0 = 0x00006008,
    kCr3TargetValue1 = 0x0000600a,
    kCr3TargetValue2 = 0x0000600c,
    kCr3TargetValue3 = 0x0000600e,
    // Natural-Width Read-Only Data Fields
    kExitQualification = 0x00006400,
    kIoRcx = 0x00006402,
    kIoRsi = 0x00006404,
    kIoRdi = 0x00006406,
    kIoRip = 0x00006408,
    kGuestLinearAddress = 0x0000640a,
    // Natural-Width Guest-State Fields
    kGuestCr0 = 0x00006800,
    kGuestCr3 = 0x00006802,
    kGuestCr4 = 0x00006804,
    kGuestEsBase = 0x00006806,
    kGuestCsBase = 0x00006808,
    kGuestSsBase = 0x0000680a,
    kGuestDsBase = 0x0000680c,
    kGuestFsBase = 0x0000680e,
    kGuestGsBase = 0x00006810,
    kGuestLdtrBase = 0x00006812,
    kGuestTrBase = 0x00006814,
    kGuestGdtrBase = 0x00006816,
    kGuestIdtrBase = 0x00006818,
    kGuestDr7 = 0x0000681a,
    kGuestRsp = 0x0000681c,
    kGuestRip = 0x0000681e,
    kGuestRflags = 0x00006820,
    kGuestPendingDbgExceptions = 0x00006822,
    kGuestSysenterEsp = 0x00006824,
    kGuestSysenterEip = 0x00006826,
    // Natural-Width Host-State Fields
    kHostCr0 = 0x00006c00,
    kHostCr3 = 0x00006c02,
    kHostCr4 = 0x00006c04,
    kHostFsBase = 0x00006c06,
    kHostGsBase = 0x00006c08,
    kHostTrBase = 0x00006c0a,
    kHostGdtrBase = 0x00006c0c,
    kHostIdtrBase = 0x00006c0e,
    kHostIa32SysenterEsp = 0x00006c10,
    kHostIa32SysenterEip = 0x00006c12,
    kHostRsp = 0x00006c14,
    kHostRip = 0x00006c16
};

/// See: VMX BASIC EXIT REASONS  Table C-1. Basic Exit Reasons
enum class VmxExitReason : unsigned __int16 {
    kExceptionOrNmi = 0,               //Guest:(理解成软件app)会产生#BR #DB #BP #OF #UD 如果 NMI exiting 置了1 就发NMI异常给当前的核
    kExternalInterrupt = 1,            //An external interrupt arrived and the “external-interrupt exiting” VM-execution control was 1.
    kTripleFault = 2,                  //
    kInit = 3,                         //An INIT signal arrived
    kSipi = 4,                         //A SIPI arrived while the logical processor was in the “wait-for-SIPI” state
    kIoSmi = 5,                        //smm有关的东西 不懂
    kOtherSmi = 6,                     //smm有关的东西 不懂
    kPendingInterrupt = 7,             //At the beginning of an instruction, RFLAGS.IF was 1; events were not blocked by STI or by MOV SS; and the “interrupt-window exiting” VM-execution control was 1.
    kNmiWindow = 8,                    //
    kTaskSwitch = 9,                   //Guest software attempted a task switch
    kCpuid = 10,                       //Guest software attempted to execute CPUID
    kGetSec = 11,                      //Guest software attempted to execute GETSEC
    kHlt = 12,                         //Guest software attempted to execute HLT and the “HLT exiting” VM-execution control was 1
    kInvd = 13,                        //Guest software attempted to execute INVD
    kInvlpg = 14,                      //Guest software attempted to execute INVLPG and the “INVLPG exiting” VM-execution control was 1
    kRdpmc = 15,                       //Guest software attempted to execute RDPMC and the “RDPMC exiting” VM-execution control was 1
    kRdtsc = 16,                       //Guest software attempted to execute RDTSC and the “RDTSC exiting” VM-execution control was 1.
    kRsm = 17,                         //Guest software attempted to execute RSM in SMM
    kVmcall = 18,                      //
    kVmclear = 19,                     //
    kVmlaunch = 20,                    //
    kVmptrld = 21,                     //
    kVmptrst = 22,                     //
    kVmread = 23,                      //
    kVmresume = 24,                    //
    kVmwrite = 25,                     //
    kVmoff = 26,                       //
    kVmon = 27,                        //
    kCrAccess = 28,                    //Guest software attempted to access CR0, CR3, CR4, or CR8 using CLTS, LMSW
    kDrAccess = 29,                    //Guest software attempted a MOV to or from a debug register and the “MOV-DR exiting” VM-execution was 1
    kIoInstruction = 30,               //
    kMsrRead = 31,                     //1: The “use MSR bitmaps” VM-execution control was 0
    kMsrWrite = 32,                    //1: The “use MSR bitmaps” VM-execution control was 0
    kInvalidGuestState = 33,           // A VM entry failed one of the checks identified in
    kMsrLoading = 34,                  //A VM entry failed in an attempt to load MSRs
    kUndefined35 = 35,                 //
    kMwaitInstruction = 36,            //Guest software attempted to execute MWAIT and the “MWAIT exiting” VM-execution control was 1
    kMonitorTrapFlag = 37,             //A VM exit occurred due to the 1-setting of the “monitor trap flag” VM-execution control or VM entry injected a pending MTF VM exit as part of VM entry
    kUndefined38 = 38,                 //
    kMonitorInstruction = 39,          //
    kPauseInstruction = 40,            //
    kMachineCheck = 41,                //
    kUndefined42 = 42,                 //
    kTprBelowThreshold = 43,           //
    kApicAccess = 44,                  //
    kVirtualizedEoi = 45,              //
    kGdtrOrIdtrAccess = 46,            //
    kLdtrOrTrAccess = 47,              //
    kEptViolation = 48,                //1：non_present:[0:2]都是0  2.Guest尝试进行读访问，但EPT->readable=0 3.Guest尝试进行写访问，但EPT->writeable=0  4.Guest尝试进行执行代码，但EPT->executable=0
    kEptMisconfig = 49,                //An attempt to access memory with a guest-physical address encountered a misconfigured EPT paging-structure entry
    kInvept = 50,                      //
    kRdtscp = 51,                      //
    kVmxPreemptionTime = 52,           //
    kInvvpid = 53,                     //
    kWbinvd = 54,                      //
    kXsetbv = 55,                      //
    kApicWrite = 56,                   //
    kRdrand = 57,                      //
    kInvpcid = 58,                     //
    kVmfunc = 59,                      //
    kUndefined60 = 60,                 //
    kRdseed = 61,                      //Guest software attempted to execute RDSEED and the “RDSEED exiting” VM-execution control was 1.
    kUndefined62 = 62,                 //
    kXsaves = 63,                      //
    kXrstors = 64,                     //
    kPconfig = 65,                     //
    kSppRelatedEvent=66,               //
    kUmWait=67,                        //
    kTpause = 68,                      //
    kLoadIwkey=69,                     //
    kEnclv=70,                         //Guest software attempted to execute ENCLV, “enable ENCLV exiting” VM-execution control was 1
    kEnqcmdPasid=72,                   //
    kEnqcmdsPasid=73,                  //
};
static_assert(sizeof(VmxExitReason) == 2, "Size check");

/// See: VM-instruction error numbers
enum class VmxInstructionError {
    kVmcallInVmxRootOperation = 1,
    kVmclearInvalidAddress = 2,
    kVmclearVmxonPoiner = 3,
    kVmlaunchNonclearVmcs = 4,
    kVmresumeNonlaunchedVmcs = 5,
    kVmresumeAfterVmxoff = 6,
    kEntryInvalidControlField = 7,
    kEntryInvalidHostStateField = 8,
    kVmptrldInvalidAddress = 9,
    kVmptrldVmxonPointer = 10,
    kVmptrldIncorrectVmcsRevisionId = 11,
    kUnsupportedVmcsComponent = 12,
    kVmwriteReadOnlyVmcsComponent = 13,
    kVmxonInVmxRootOperation = 15,
    kEntryInvalidExecutiveVmcsPointer = 16,
    kEntryNonlaunchedExecutiveVmcs = 17,
    kEntryExecutiveVmcsPointerNonVmxonPointer = 18,
    kVmcallNonClearVmcs = 19,
    kVmcallInvalidVmExitControlFields = 20,
    kVmcallIncorrectMsegRevisionId = 22,
    kVmxoffUnderDualMonitorTreatmentOfSmisAndSmm = 23,
    kVmcallInvalidSmmMonitorFeatures = 24,
    kEntryInvalidVmExecutionControlFieldsInExecutiveVmcs = 25,
    kEntryEventsBlockedByMovSs = 26,
    kInvalidOperandToInveptInvvpid = 28,
};

/// See: Memory Types That Can Be Encoded With PAT Memory Types Recommended for
/// VMCS and Related Data Structures
enum class memory_type : unsigned __int8 {
    kUncacheable = 0,
    kWriteCombining = 1,
    kWriteThrough = 4,
    kWriteProtected = 5,
    kWriteBack = 6,
    kUncached = 7,
};

/// See: Virtual-Machine Control Structures & FORMAT OF THE VMCS REGION
struct VmControlStructure {
    unsigned long revision_identifier;
    unsigned long vmx_abort_indicator;
    unsigned long data[1];  //!< Implementation-specific format.
};

/// See: Definitions of Pin-Based VM-Execution Controls 第三章 25.6
union VmxPinBasedControls {
    unsigned int all;
    struct {
        unsigned external_interrupt_exiting : 1;    //!< [0]     (0或1) 1:发生外部中断则产生 VM_EXIT事件
        unsigned reserved1 : 2;                     //!< [1:2]   (固定1)
        unsigned nmi_exiting : 1;                   //!< [3]     (0或1) 1:发生NMI VM_EXIT事件
        unsigned reserved2 : 1;                     //!< [4]     (固定1)
        unsigned virtual_nmis : 1;                  //!< [5]     (0或1) 
        unsigned activate_vmx_peemption_timer : 1;  //!< [6]     (0或1) 1:启用vmx_peemption定时器
        unsigned process_posted_interrupts : 1;     //!< [7]     (0或1) 1:启用process_posted_interrupts机制处理虚拟中断
    } fields;
};
static_assert(sizeof(VmxPinBasedControls) == 4, "Size check");

/// See: Definitions of Primary Processor-Based VM-Execution Controls  IA32_VMX_PROCBASED_CTLS
union VmxProcessorBasedControls {
    unsigned int all;
    struct {
        unsigned reserved1 : 2;                   //!< [0:1]     
        unsigned interrupt_window_exiting : 1;    //!< [2]        (0或1) 1:a VM exit occurs at the beginning of any instruction if RFLAGS.IF = 1 
        unsigned use_tsc_offseting : 1;           //!< [3]        (0或1) 1:读取TSC值时，返回的TSC值加上一个偏移值
        unsigned reserved2 : 3;                   //!< [4:6]      固定1
        unsigned hlt_exiting : 1;                 //!< [7]        (0或1) 1:执行HLT指令 产生 VM-exit
        unsigned reserved3 : 1;                   //!< [8]
        unsigned invlpg_exiting : 1;              //!< [9]        (0或1) 1:执行Invlpg指令 产生 VM-exit
        unsigned mwait_exiting : 1;               //!< [10]       (0或1) 1:执行Mwait指令 产生 VM-exit
        unsigned rdpmc_exiting : 1;               //!< [11]       (0或1) 1:执行Rdpmc指令 产生 VM-exit
        unsigned rdtsc_exiting : 1;               //!< [12]       (0或1) 1:执行Rdtsc指令 产生 VM-exit
        unsigned reserved4 : 2;                   //!< [13:14]
        unsigned cr3_load_exiting : 1;            //!< [15]       (0或1) 1:写CR3 产生 VM-exit
        unsigned cr3_store_exiting : 1;           //!< [16]       (0或1) 1:读CR3 产生 VM-exit
        unsigned reserved5 : 2;                   //!< [17:18]
        unsigned cr8_load_exiting : 1;            //!< [19]       (0或1) 1:写CR8 产生 VM-exit
        unsigned cr8_store_exiting : 1;           //!< [20]       (0或1) 1:读CR8 产生 VM-exit
        unsigned use_tpr_shadow : 1;              //!< [21]       (0或1) 1:启用"virtual-apic page"页面来虚拟化local apic
        unsigned nmi_window_exiting : 1;          //!< [22]       (0或1) 1:开 virtual_nmi windows 时产生 vm-exit
        unsigned mov_dr_exiting : 1;              //!< [23]       (0或1) 1:读写 dr寄存器产生vm-exit
        unsigned unconditional_io_exiting : 1;    //!< [24]       (0或1) 1:执行in/out或ins/outs类执行产生vm-exit
        unsigned use_io_bitmaps : 1;              //!< [25]       (0或1) 1:启用i/o bitmap
        unsigned reserved6 : 1;                   //!< [26]
        unsigned monitor_trap_flag : 1;           //!< [27]       (0或1) 1:启用 MTF调试功能
        unsigned use_msr_bitmaps : 1;             //!< [28]       (0或1) 1:启用 MSR bitmap
        unsigned monitor_exiting : 1;             //!< [29]       (0或1) 1:执行 monitor指令产生vm-exit
        unsigned pause_exiting : 1;               //!< [30]       (0或1) 1:执行 pause指令产生 vm-exit
        unsigned activate_secondary_control : 1;  //!< [31]       (0或1) 1: secondary processor-based VM-execution controls 字段有效
    } fields;
};
static_assert(sizeof(VmxProcessorBasedControls) == 4, "Size check");

/// See: Definitions of Secondary Processor-Based VM-Execution Controls 第三章 24.7
/*
* 3. VPID （Virtual Processor Identifiers）
由于在VMX虚拟化环境中，一个逻辑CPU可以运行来自不同虚拟机的多个虚拟CPU，即vCPU，为了防止多个不同的vCPU之间，
vCPU和逻辑CPU之间的地址转换cache（TLB和Paging-Structure Cache）之间相互干扰，在每次进行VM Entry或者VM Exit操作的时候，
都需要把这些地址转换所用到的cache清掉，再重新加载目标CPU/vCPU的地址转换cache。Cache的清除和重新加载是一个比较耗时的操作，会影响到CPU/vCPU的性能，
特别是逻辑CPU一直在执行某个vCPU的时候，其实某些cache完全可以保留，不需要进行特殊的操作。
为了减少这些耗时的Cache清除和加载操作，VMX中引入了VPID（Virtual Processor Identifiers）机制，
即在为每个地址转换的Cache（TLB或者Paging-Structure Cache）打上一个VPID的标志（VMM为每个vCPU分配一个唯一的VPID（位于VMCS中），
逻辑CPU的VPID为0，其他vCPU的VPID大于0），这样就不用担心不同的vCPU/CPU所使用到的地址转换Cache混到一起，CPU硬件在寻找Cache的时候，
将会多进行一次比较，即将当前运行的vCPU/CPU的VPID和Cache中所包含的VPID进行匹配，只有相等才会使用该Cache条目。
这样在每次进行VM Entry或者VM Exit的时候就不需要将地址转换的Cache清除掉，完全可以复用之前保留着的Cache，只在必要的时候进行地址转换Cache的更新。
和之前非虚拟化环境下地址转换加速机制进行一下对比会发现，VPID的机制和PCID（Process Context Identifiers）的机制类似，都是在不同的层级上对地址转换的Cache进行保留，减少地址转换Cache的清除和加载次数。VPID针对的是虚拟化环境下不同vCPU的层面，而PCID针对的是在操作系统下，不同进程的层面，两者是可以同时起作用的
*/
union VmxSecondaryProcessorBasedControls {
    unsigned int all;
    struct {
        unsigned virtualize_apic_accesses : 1;            //!< [0]      (0或1) 1:虚拟化访问APIC-access page
        unsigned enable_ept : 1;                          //!< [1]      (0或1) 1:启用EPT
        unsigned descriptor_table_exiting : 1;            //!< [2]      (0或1) 1:访问 GDTR LDTR IDTR or TR 产生Vm-exit
        unsigned enable_rdtscp : 1;                       //!< [3]      (0或1) 0:任何坏境下执行Rdtscp指令 产生#UD异常
        unsigned virtualize_x2apic_mode : 1;              //!< [4]      (0或1) 1:If this control is 1, the logical processor treats specially RDMSR and WRMSR to APIC MSRs
        unsigned enable_vpid : 1;                         //!< [5]      (0或1) 1:启用VPID机制 VPID（Virtual Processor Identifier）机制用于加快地址的转换
        unsigned wbinvd_exiting : 1;                      //!< [6]      (0或1) 1:WBINVD and WBNOINVD cause VM exits
        unsigned unrestricted_guest : 1;                  //!< [7]      (0或1) 1:可以使用非分页保护模式或实模式
        unsigned apic_register_virtualization : 1;        //!< [8]      (0或1) 1:支持访问 virtual-apic page内的虚拟寄存器
        unsigned virtual_interrupt_delivery : 1;          //!< [9]      (0或1) 1:支持虚拟中断的delivery
        unsigned pause_loop_exiting : 1;                  //!< [10]     (0或1) 1:PAUSE can cause a VM exit
        unsigned rdrand_exiting : 1;                      //!< [11]     (0或1) 1:RDRAND cause VM exits
        unsigned enable_invpcid : 1;                      //!< [12]     (0或1) f this control is 0, any execution of INVPCID causes a #UD
        unsigned enable_vm_functions : 1;                 //!< [13]     (0或1) 1:任何环境下都可以执行 vmcall(pubg _try{call}_exception 检测异常)
        unsigned vmcs_shadowing : 1;                      //!< [14]     (0或1) 1:VMREAD VMWRITE 可以在 任何环境执行
        unsigned enable_encls_exiting : 1;                //!< [15]     (0或1) 1:executions of ENCLS consult the ENCLS-exiting bitmap to determine whether the instruction causes a VM exit.
        unsigned rdseed_exiting : 1;                      //!< [16]     (0或1) 1:RDSEED cause VM exits
        unsigned enable_pml : 1;                          //!< [17]     (0或1) 1:If this control is 1, an access to a guest-physical address that sets an EPT dirty bit first adds an entry to the page-modification log. See Section 29.3.6.
        unsigned ept_violation_ve : 1;                    //!< [18]     (0或1) 1:if this control is 1, EPT violations may cause virtualization exceptions (#VE) instead of VM exits
        unsigned conceal_vmx_from_pt : 1;                 //!< [19]      
        unsigned enable_xsaves_xstors : 1;                //!< [20]      If this control is 0, any execution of XSAVES or XRSTORS causes a #UD
        unsigned pasid_translation : 1;                   //!< [21]      (0或1) 1:PASID translation is performed for executions of ENQCMD and ENQCMDS
        unsigned mode_based_execute_control_for_ept : 1;  //!< [22]      If this control is 1, EPT execute permissions are based on whether the linear address being accessed is supervisor mode or user mode
        unsigned sub_page_write_permissions_for_pet : 1;  //!< [23]      If this control is 1, EPT write permissions may be specified at the granularity of 128 bytes
        unsigned inter_pt_uses_guest_physical_addresses : 1; //!<[24]    英特尔处理器跟踪使用的所有输出地址都被视为guestphysicaladdresses，并使用EPT进行翻译
        unsigned use_tsc_scaling : 1;                     //!< [25]
        unsigned enable_user_wait_and_pause : 1;          //!< [26]      If this control is 0, any execution of TPAUSE, UMONITOR, or UMWAIT causes a #UD
        unsigned enable_pconfig : 1;                      //!< [27]      If this control is 0, any execution of PCONFIG causes a #UD
        unsigned enable_enclv_exiting : 1;                //!< [28]      If this control is 1, executions of ENCLV consult the ENCLV-exiting bitmap to determine whether the instruction causes a VM exit
    } fields;
};
static_assert(sizeof(VmxSecondaryProcessorBasedControls) == 4, "Size check");

/// See: Definitions of VM-Exit Controls
union VmxVmExitControls {
    unsigned int all;
    struct {
        unsigned reserved1 : 2;                        //!< [0:1]   固定为 1
        unsigned save_debug_controls : 1;              //!< [2]     (0或1) 1:保存debug寄存器
        unsigned reserved2 : 6;                        //!< [3:8]   固定为 1
        unsigned host_address_space_size : 1;          //!< [9]     (0或1) 1:返回IA-32e模式（on every VM exit）必须设置不然__vmx_vmlaunch 失败
        unsigned reserved3 : 2;                        //!< [10:11] 固定为 1
        unsigned load_ia32_perf_global_ctrl : 1;       //!< [12]    (0或1) 1:IA32_PERF_GLOBAL_CTRL MSR寄存器
        unsigned reserved4 : 2;                        //!< [13:14] 固定为 1
        unsigned acknowledge_interrupt_on_exit : 1;    //!< [15]    (0或1) 1:规定了是否在由于外部中断导致退出的时候读取并保存中断向量号。这里可以填0或1都不影响使用，但是为了能够在以后的时候用到这个保存的信息，可以将其填为1，并不会影响性能
        unsigned reserved5 : 2;                        //!< [16:17] 固定为 1
        unsigned save_ia32_pat : 1;                    //!< [18]    (0或1) 1:保存IA32_PAT MSR
        unsigned load_ia32_pat : 1;                    //!< [19]    (0或1) 1:加载IA32_PAT MSR
        unsigned save_ia32_efer : 1;                   //!< [20]    (0或1) 1:保存IA32_EFER MSR
        unsigned load_ia32_efer : 1;                   //!< [21]    (0或1) 1:加载IA32_EFER MSR
        unsigned save_vmx_preemption_timer_value : 1;  //!< [22]    (0或1) 1:vm_exit时保存vmx定时器计数值
        unsigned clear_ia32_bndcfgs : 1;               //!< [23]    (0或1) 1:IA32_BNDCFGS MSR is cleared on VM exit
        unsigned conceal_vmexits_from_intel_pt : 1;    //!< [24]    (0或1) 1:不会 有PIP信号 or VMCS packet on an SMM VM exit
        unsigned clear_ia32_rtit_ctl : 1;              //!< [25]    (0或1) 1:Be cleared on VM exit 
        unsigned clear_ia32_lbr_ctl : 1;               //!< [26]    (0或1) 1:Be cleared on VM exit 
        unsigned clear_uinv : 1;                       //!< [27]    (0或1) 1:Be cleared on VM exit 
        unsigned load_cet_state : 1;                   //!< [28]    (0或1) 1:Be loaded on VM exit 
        unsigned load_pkrs : 1;                        //!< [29]    (0或1) 1:Be loaded on VM exit 
        unsigned save_ia32_perf_global_ctl : 1;        //!< [30]    (0或1) 1:Be cleared on VM exit 
        unsigned active_secondary_ctl : 1;             //!< [31]    (0或1) 0: the logical processor operates as if all the secondary VM-exit controls were also 0
    } fields;
};
static_assert(sizeof(VmxVmExitControls) == 4, "Size check");

/// See: Definitions of VM-Entry Controls
union VmxVmEntryControls {
    unsigned int all;
    struct {
        unsigned reserved1 : 2;                          //!< [0:1]  固定为 1
        unsigned load_debug_controls : 1;                //!< [2]    (0或1)      为 1时 在进入 VM_ENTRY 加载 debug寄存器
        unsigned reserved2 : 6;                          //!< [3:8]  固定为 1
        unsigned ia32e_mode_guest : 1;                   //!< [9]    (0或1)      时 进入 IA-32e模式 (必须设置不然__vmx_vmlaunch 失败)
        unsigned entry_to_smm : 1;                       //!< [10]   (0或1)      为1时 进入SMM模式
        unsigned deactivate_dual_monitor_treatment : 1;  //!< [11]   (0或1)      为1时 返回executive monitor,关闭SMM双重监控模式
        unsigned reserved3 : 1;                          //!< [12]   固定为 1
        unsigned load_ia32_perf_global_ctrl : 1;         //!< [13]   (0或1)      为1时 加载 IA32_PERF_GLOBAL_CTRL MSR
        unsigned load_ia32_pat : 1;                      //!< [14]   (0或1)      为1时 加载 IA32_PAT
        unsigned load_ia32_efer : 1;                     //!< [15]   (0或1)      为1时 加载 IA32_EFER
        unsigned load_ia32_bndcfgs : 1;                  //!< [16]   (0或1)      为1时 加载 IA32_BNDCFGS
        unsigned conceal_vmentries_from_intel_pt : 1;    //!< [17]   (0或1)      为1时 cpu跟踪时不会产生 pip信息
        unsigned load_ia32_rtit_ctl : 1;                 //!< [19]   (0或1)      为1时 加载 IA32_RTIT_CTL
        unsigned load_uinv : 1;                          //!< [18]   (0或1)      为1时 加载 UINV
        unsigned load_cet_state : 1;                 //!< [20]   (0或1)      为1时 加载 CET MSRs SSP
        unsigned load_ia32_lbr_ctl : 1;                  //!< [21]   (0或1)      为1时 加载 IA32_LBR_CTL
        unsigned load_load_pkrs : 1;                     //!< [22]   (0或1)      为1时 加载 IA32_PKRS
    } fields;
};
static_assert(sizeof(VmxVmExitControls) == 4, "Size check");

/// See: Guest Register State
union VmxRegmentDescriptorAccessRight {
    unsigned int all;
    struct {
        unsigned type : 4;        //!< [0:3]
        unsigned system : 1;      //!< [4]
        unsigned dpl : 2;         //!< [5:6]
        unsigned present : 1;     //!< [7]
        unsigned reserved1 : 4;   //!< [8:11]
        unsigned avl : 1;         //!< [12]
        unsigned l : 1;           //!< [13] Reserved (except for CS) 64-bit mode
        unsigned db : 1;          //!< [14]
        unsigned gran : 1;        //!< [15]
        unsigned unusable : 1;    //!< [16] Segment unusable
        unsigned reserved2 : 15;  //!< [17:31]
    } fields;
};
static_assert(sizeof(VmxRegmentDescriptorAccessRight) == 4, "Size check");

/// See: ARCHITECTURAL MSRS
union Ia32FeatureControlMsr {
    unsigned __int64 all;
    struct {
        unsigned lock : 1;                  //!< [0]
        unsigned enable_smx : 1;            //!< [1]
        unsigned enable_vmxon : 1;          //!< [2]
        unsigned reserved1 : 5;             //!< [3:7]
        unsigned enable_local_senter : 7;   //!< [8:14]
        unsigned enable_global_senter : 1;  //!< [15]
        unsigned reserved2 : 16;            //!<
        unsigned reserved3 : 32;            //!< [16:63]
    } fields;
};
static_assert(sizeof(Ia32FeatureControlMsr) == 8, "Size check");

/// See: BASIC VMX INFORMATION
union Ia32VmxBasicMsr {
    unsigned __int64 all;
    struct {
        unsigned revision_identifier : 31;    //!< [0:30]
        unsigned reserved1 : 1;               //!< [31]
        unsigned region_size : 12;            //!< [32:43]
        unsigned region_clear : 1;            //!< [44]
        unsigned reserved2 : 3;               //!< [45:47]
        unsigned supported_ia64 : 1;          //!< [48]
        unsigned supported_dual_moniter : 1;  //!< [49]
        unsigned memory_type : 4;             //!< [50:53]
        unsigned vm_exit_report : 1;          //!< [54]
        unsigned vmx_capability_hint : 1;     //!< [55]
        unsigned reserved3 : 8;               //!< [56:63]
    } fields;
};
static_assert(sizeof(Ia32VmxBasicMsr) == 8, "Size check");

/// See: MISCELLANEOUS DATA
union Ia32VmxMiscMsr {
    unsigned __int64 all;
    struct {
        unsigned time_stamp : 5;                               //!< [0:4]
        unsigned reserved1 : 1;                                //!< [5]
        unsigned supported_activity_state_hlt : 1;             //!< [6]
        unsigned supported_activity_state_shutdown : 1;        //!< [7]
        unsigned supported_activity_state_wait_for_sipi : 1;   //!< [8]
        unsigned reserved2 : 6;                                //!< [9:14]
        unsigned supported_read_ia32_smbase_msr : 1;           //!< [15]
        unsigned supported_cr3_target_value_number : 8;        //!< [16:23]
        unsigned supported_cr3_target_value_number_clear : 1;  //!< [24]
        unsigned maximum_msrs_number : 3;                      //!< [25:27]
        unsigned suppoeted_change_ia32_smm_monitor_ctl : 1;    //!< [28]
        unsigned supported_vmwrite_vm_exit_information : 1;    //!< [29]
        unsigned reserved3 : 2;                                //!< [30:31]
        unsigned revision_identifier : 32;                     //!< [32:63]
    } fields;
};
static_assert(sizeof(Ia32VmxMiscMsr) == 8, "Size check");

/// See: VMCS ENUMERATION
union Ia32VmxVmcsEnumMsr {
    unsigned __int64 all;
    struct {
        unsigned reserved1 : 1;                        //!< [0]
        unsigned supported_highest_vmcs_encoding : 9;  //!< [1:9]
        unsigned reserved2 : 22;                       //!<
        unsigned reserved3 : 32;                       //!< [10:63]
    } fields;
};
static_assert(sizeof(Ia32VmxVmcsEnumMsr) == 8, "Size check");

/// See: VPID AND EPT CAPABILITIES 
// IA32_VMX_EPT_VPID_CAP 0x48c
union Ia32VmxEptVpidCapMsr {
    unsigned __int64 all;
    struct {
        unsigned support_execute_only_pages : 1;                        //!< [0]   只有当这个IA32_VMX_EPT_VPID_CAP MSR的第0位为1时，才支持将EPT物理页面设置为可执行，但不可读写的权限
        unsigned reserved1 : 5;                                         //!< [1:5]
        unsigned support_page_walk_length4 : 1;                         //!< [6]    Bit 6 indicates support for a page-walk length of 4
        unsigned reserved2 : 1;                                         //!< [7]
        unsigned support_uncacheble_memory_type : 1;                    //!< [8]
        unsigned reserved3 : 5;                                         //!< [9:13]
        unsigned support_write_back_memory_type : 1;                    //!< [14]
        unsigned reserved4 : 1;                                         //!< [15]
        unsigned support_pde_2mb_pages : 1;                             //!< [16]
        unsigned support_pdpte_1_gb_pages : 1;                          //!< [17]
        unsigned reserved5 : 2;                                         //!< [18:19]
        unsigned support_invept : 1;                                    //!< [20]     Support for the INVEPT instruction (see Chapter 31 and Section 29.4.3.1):
        unsigned support_accessed_and_dirty_flag : 1;                   //!< [21]
        unsigned reserved6 : 3;                                         //!< [22:24]
        unsigned support_single_context_invept : 1;                     //!< [25]
        unsigned support_all_context_invept : 1;                        //!< [26]
        unsigned reserved7 : 5;                                         //!< [27:31]
        unsigned support_invvpid : 1;                                   //!< [32]
        unsigned reserved8 : 7;                                         //!< [33:39]
        unsigned support_individual_address_invvpid : 1;                //!< [40]
        unsigned support_single_context_invvpid : 1;                    //!< [41]
        unsigned support_all_context_invvpid : 1;                       //!< [42]
        unsigned support_single_context_retaining_globals_invvpid : 1;  //!< [43]
        unsigned reserved9 : 20;                                        //!< [44:63]
    } fields;
};
static_assert(sizeof(Ia32VmxEptVpidCapMsr) == 8, "Size check");

/// See: Format of Exit Reason in Basic VM-Exit Information
union VmExitInformation {
    unsigned int all;
    struct {
        VmxExitReason reason;                      //!< [0:15]
        unsigned short reserved1 : 12;             //!< [16:30]
        unsigned short pending_mtf_vm_exit : 1;    //!< [28]
        unsigned short vm_exit_from_vmx_root : 1;  //!< [29]
        unsigned short reserved2 : 1;              //!< [30]
        unsigned short vm_entry_failure : 1;       //!< [31]
    } fields;
};
static_assert(sizeof(VmExitInformation) == 4, "Size check");

/// See: Format of the VM-Exit Instruction-Information Field as Used for INS and
/// OUTS
union InsOrOutsInstInformation {
    ULONG32 all;
    struct {
        ULONG32 reserved1 : 7;         //!< [0:6]
        ULONG32 address_size : 3;      //!< [7:9]
        ULONG32 reserved2 : 5;         //!< [10:14]
        ULONG32 segment_register : 3;  //!< [15:17]
        ULONG32 reserved3 : 14;        //!< [18:31]
    } fields;
};
static_assert(sizeof(InsOrOutsInstInformation) == 4, "Size check");

/// See: Format of the VM-Exit Instruction-Information Field as Used for INVEPT,
/// INVPCID, and INVVPID
union InvEptOrPcidOrVpidInstInformation {
    ULONG32 all;
    struct {
        ULONG32 scalling : 2;                //!< [0:1]
        ULONG32 reserved1 : 5;               //!< [2:6]
        ULONG32 address_size : 3;            //!< [7:9]
        ULONG32 reserved2 : 1;               //!< [10]
        ULONG32 reserved3 : 4;               //!< [11:14]
        ULONG32 segment_register : 3;        //!< [15:17]
        ULONG32 index_register : 4;          //!< [18:21]
        ULONG32 index_register_invalid : 1;  //!< [22]
        ULONG32 base_register : 4;           //!< [23:26]
        ULONG32 base_register_invalid : 1;   //!< [27]
        ULONG32 index_register2 : 4;         //!< [28:31]
    } fields;
};
static_assert(sizeof(InvEptOrPcidOrVpidInstInformation) == 4, "Size check");

/// See: Format of the VM-Exit Instruction-Information Field as Used for
/// LIDT, LGDT, SIDT, or SGDT
union GdtrOrIdtrInstInformation {
    ULONG32 all;
    struct {
        ULONG32 scalling : 2;                //!< [0:1]
        ULONG32 reserved1 : 5;               //!< [2:6]
        ULONG32 address_size : 3;            //!< [7:9]
        ULONG32 reserved2 : 1;               //!< [10]
        ULONG32 operand_size : 1;            //!< [11]
        ULONG32 reserved3 : 3;               //!< [12:14]
        ULONG32 segment_register : 3;        //!< [15:17]
        ULONG32 index_register : 4;          //!< [18:21]
        ULONG32 index_register_invalid : 1;  //!< [22]
        ULONG32 base_register : 4;           //!< [23:26]
        ULONG32 base_register_invalid : 1;   //!< [27]
        ULONG32 instruction_identity : 2;    //!< [28:29]
        ULONG32 reserved4 : 2;               //!< [30:31]
    } fields;
};
static_assert(sizeof(GdtrOrIdtrInstInformation) == 4, "Size check");

/// @copydoc GdtrOrIdtrInstInformation
enum class Scaling {
    kNoScaling = 0,
    kScaleBy2,
    kScaleBy4,
    kScaleBy8,
};

/// @copydoc GdtrOrIdtrInstInformation
enum class AddressSize {
    k16bit = 0,
    k32bit,
    k64bit,
};

/// @copydoc GdtrOrIdtrInstInformation
enum class SegmentRegisters {
    kEs = 0,
    kCs,
    kSs,
    kDs,
    kFs,
    kGs,
};

/// @copydoc GdtrOrIdtrInstInformation
enum class GdtrOrIdtrInstructionIdentity {
    kSgdt = 0,
    kSidt,
    kLgdt,
    kLidt,
};

/// See: Format of the VM-Exit Instruction-Information Field as Used for
/// LLDT, LTR, SLDT, and STR
union LdtrOrTrInstInformation {
    ULONG32 all;
    struct {
        ULONG32 scalling : 2;                //!< [0:1]
        ULONG32 reserved1 : 1;               //!< [2]
        ULONG32 register1 : 4;               //!< [3:6]
        ULONG32 address_size : 3;            //!< [7:9]
        ULONG32 register_access : 1;         //!< [10]
        ULONG32 reserved2 : 4;               //!< [11:14]
        ULONG32 segment_register : 3;        //!< [15:17]
        ULONG32 index_register : 4;          //!< [18:21]
        ULONG32 index_register_invalid : 1;  //!< [22]
        ULONG32 base_register : 4;           //!< [23:26]
        ULONG32 base_register_invalid : 1;   //!< [27]
        ULONG32 instruction_identity : 2;    //!< [28:29]
        ULONG32 reserved4 : 2;               //!< [30:31]
    } fields;
};
static_assert(sizeof(LdtrOrTrInstInformation) == 4, "Size check");

/// @copydoc LdtrOrTrInstInformation
enum class LdtrOrTrInstructionIdentity {
    kSldt = 0,
    kStr,
    kLldt,
    kLtr,
};

/// See: Exit Qualification for MOV DR
enum class MovDrDirection {
    kMoveToDr = 0,
    kMoveFromDr,
};

/// @copydoc MovDrDirection
union MovDrQualification {
    ULONG_PTR all;
    struct {
        ULONG_PTR debugl_register : 3;  //!< [0:2]
        ULONG_PTR reserved1 : 1;        //!< [3]
        ULONG_PTR direction : 1;        //!< [4]
        ULONG_PTR reserved2 : 3;        //!< [5:7]
        ULONG_PTR gp_register : 4;      //!< [8:11]
        ULONG_PTR reserved3 : 20;       //!<
        ULONG_PTR reserved4 : 32;       //!< [12:63]
    } fields;
};
static_assert(sizeof(MovDrQualification) == 8, "Size check");

/// See: Exit Qualification for I/O Instructions
union IoInstQualification {
    ULONG_PTR all;
    struct {
        ULONG_PTR size_of_access : 3;      //!< [0:2]
        ULONG_PTR direction : 1;           //!< [3]
        ULONG_PTR string_instruction : 1;  //!< [4]
        ULONG_PTR rep_prefixed : 1;        //!< [5]
        ULONG_PTR operand_encoding : 1;    //!< [6]
        ULONG_PTR reserved1 : 9;           //!< [7:15]
        ULONG_PTR port_number : 16;        //!< [16:31]
    } fields;
};
static_assert(sizeof(IoInstQualification) == sizeof(void*), "Size check");

/// @copydoc IoInstQualification
enum class IoInstSizeOfAccess {
    k1Byte = 0,
    k2Byte = 1,
    k4Byte = 3,
};

/// See: Exit Qualification for Control-Register Accesses
enum class MovCrAccessType {
    kMoveToCr = 0,
    kMoveFromCr,
    kClts,
    kLmsw,
};

/// @copydoc MovCrAccessType
union MovCrQualification {
    ULONG_PTR all;
    struct {
        ULONG_PTR control_register : 4;   //!< [0:3]
        ULONG_PTR access_type : 2;        //!< [4:5]
        ULONG_PTR lmsw_operand_type : 1;  //!< [6]
        ULONG_PTR reserved1 : 1;          //!< [7]
        ULONG_PTR gp_register : 4;        //!< [8:11]
        ULONG_PTR reserved2 : 4;          //!< [12:15]
        ULONG_PTR lmsw_source_data : 16;  //!< [16:31]
        ULONG_PTR reserved3 : 32;         //!< [32:63]
    } fields;
};
static_assert(sizeof(MovCrQualification) == 8, "Size check");

/// See: Extended-Page-Table Pointer (EPTP)
union EptPointer {
    ULONG64 all;
    struct {
        ULONG64 memory_type : 3;                      //!< [0:2]  如果都是0 则是 not present状态 -> EPT violations
        ULONG64 page_walk_length : 3;                 //!< [3:5]
        ULONG64 enable_accessed_and_dirty_flags : 1;  //!< [6]
        ULONG64 reserved1 : 5;                        //!< [7:11]
        ULONG64 pml4_address : 36;                    //!< [12:48-1]
        ULONG64 reserved2 : 16;                       //!< [48:63]
    } fields;
};
static_assert(sizeof(EptPointer) == 8, "Size check");

// Note on interpretation of N in those definitions:
//
// N is the physical-address width supported by the logical processor. Software
// can determine a processor's physical-address width by executing CPUID with
// 80000008H in EAX.The physical - address width is returned in bits 7:0 of EAX.

/// See: Format of an EPT PML4 Entry (PML4E) that References an EPT
///      Page-Directory-Pointer Table
union EptPml4Entry {
    ULONG64 all;
    struct {
        ULONG64 read_access : 1;                                  //!< [0]
        ULONG64 write_access : 1;                                 //!< [1]
        ULONG64 execute_access : 1;                               //!< [2]
        ULONG64 reserved1 : 5;                                    //!< [3:7]
        ULONG64 accessed : 1;                                     //!< [8]
        ULONG64 ignored1 : 1;                                     //!< [9]
        ULONG64 execute_access_for_user_mode_linear_address : 1;  //!< [10]
        ULONG64 ignored2 : 1;                                     //!< [11]
        ULONG64 pdpt_address : 36;                                //!< [12:48-1]
        ULONG64 reserved2 : 4;                                    //!< [48:51]
        ULONG64 ignored3 : 12;                                    //!< [52:63]
    } fields;
};
static_assert(sizeof(EptPml4Entry) == 8, "Size check");

/// See: Format of an EPT Page-Directory-Pointer-Table Entry (PDPTE) that Maps
///      a 1-GByte Page
union EptPdptSuperPageEntry {
    ULONG64 all;
    struct {
        ULONG64 read_access : 1;                                  //!< [0]
        ULONG64 write_access : 1;                                 //!< [1]
        ULONG64 execute_access : 1;                               //!< [2]
        ULONG64 memory_type : 3;                                  //!< [3:5]
        ULONG64 ignore_pat_memory_type : 1;                       //!< [6]
        ULONG64 must_be1 : 1;                                     //!< [7]
        ULONG64 accessed : 1;                                     //!< [8]
        ULONG64 written : 1;                                      //!< [9]
        ULONG64 execute_access_for_user_mode_linear_address : 1;  //!< [10]
        ULONG64 ignored1 : 1;                                     //!< [11]
        ULONG64 reserved1 : 18;                                   //!< [12:29]
        ULONG64 physial_address : 18;                             //!< [30:48-1]
        ULONG64 reserved2 : 4;                                    //!< [48:51]
        ULONG64 ignored2 : 11;                                    //!< [52:62]
        ULONG64 suppress_ve : 1;                                  //!< [63]
    } fields;
};
static_assert(sizeof(EptPdptSuperPageEntry) == 8, "Size check");

/// See: Format of an EPT Page-Directory-Pointer-Table Entry (PDPTE) that
///      References an EPT Page Directory
union EptPdptEntry {
    ULONG64 all;
    struct {
        ULONG64 read_access : 1;                                  //!< [0]
        ULONG64 write_access : 1;                                 //!< [1]
        ULONG64 execute_access : 1;                               //!< [2]
        ULONG64 reserved1 : 5;                                    //!< [3:7]
        ULONG64 accessed : 1;                                     //!< [8]
        ULONG64 ignored1 : 1;                                     //!< [9]
        ULONG64 execute_access_for_user_mode_linear_address : 1;  //!< [10]
        ULONG64 ignored2 : 1;                                     //!< [11]
        ULONG64 pd_address : 36;                                  //!< [12:48-1]
        ULONG64 reserved2 : 4;                                    //!< [48:51]
        ULONG64 ignored3 : 12;                                    //!< [52:63]
    } fields;
};
static_assert(sizeof(EptPdptEntry) == 8, "Size check");

/// See: Format of an EPT Page-Directory Entry (PDE) that Maps a 2-MByte Page
union EptPdLargePageEntry {
    ULONG64 all;
    struct {
        ULONG64 read_access : 1;                                  //!< [0]
        ULONG64 write_access : 1;                                 //!< [1]
        ULONG64 execute_access : 1;                               //!< [2]
        ULONG64 memory_type : 3;                                  //!< [3:5]
        ULONG64 ignore_pat_memory_type : 1;                       //!< [6]
        ULONG64 must_be1 : 1;                                     //!< [7]
        ULONG64 accessed : 1;                                     //!< [8]
        ULONG64 written : 1;                                      //!< [9]
        ULONG64 execute_access_for_user_mode_linear_address : 1;  //!< [10]
        ULONG64 ignored1 : 1;                                     //!< [11]
        ULONG64 reserved1 : 9;                                    //!< [12:20]
        ULONG64 physial_address : 27;                             //!< [21:48-1]
        ULONG64 reserved2 : 4;                                    //!< [48:51]
        ULONG64 ignored2 : 11;                                    //!< [52:62]
        ULONG64 suppress_ve : 1;                                  //!< [63]
    } fields;
};
static_assert(sizeof(EptPdLargePageEntry) == 8, "Size check");

/// See: Format of an EPT Page-Directory Entry (PDE) that References an EPT Page
/// Table
union EptPdEntry {
    ULONG64 all;
    struct {
        ULONG64 read_access : 1;                                  //!< [0]
        ULONG64 write_access : 1;                                 //!< [1]
        ULONG64 execute_access : 1;                               //!< [2]
        ULONG64 reserved1 : 4;                                    //!< [3:6]
        ULONG64 must_be0 : 1;                                     //!< [7]
        ULONG64 accessed : 1;                                     //!< [8]
        ULONG64 ignored1 : 1;                                     //!< [9]
        ULONG64 execute_access_for_user_mode_linear_address : 1;  //!< [10]
        ULONG64 ignored2 : 1;                                     //!< [11]
        ULONG64 pt_address : 36;                                  //!< [12:48-1]
        ULONG64 reserved2 : 4;                                    //!< [48:51]
        ULONG64 ignored3 : 12;                                    //!< [52:63]
    } fields;
};
static_assert(sizeof(EptPdEntry) == 8, "Size check");

/// See: Format of an EPT Page-Table Entry that Maps a 4-KByte Page
union EptPtEntry {
    ULONG64 all;
    struct {
        ULONG64 read_access : 1;                                  //!< [0]
        ULONG64 write_access : 1;                                 //!< [1]
        ULONG64 execute_access : 1;                               //!< [2]
        ULONG64 memory_type : 3;                                  //!< [3:5]
        ULONG64 ignore_pat_memory_type : 1;                       //!< [6]
        ULONG64 ignored1 : 1;                                     //!< [7]
        ULONG64 accessed : 1;                                     //!< [8]
        ULONG64 written : 1;                                      //!< [9]
        ULONG64 execute_access_for_user_mode_linear_address : 1;  //!< [10]
        ULONG64 ignored2 : 1;                                     //!< [11]
        ULONG64 physial_address : 36;                             //!< [12:48-1]
        ULONG64 reserved1 : 4;                                    //!< [48:51]
        ULONG64 Ignored3 : 11;                                    //!< [52:62]
        ULONG64 suppress_ve : 1;                                  //!< [63]
    } fields;
};
static_assert(sizeof(EptPtEntry) == 8, "Size check");

/// See: Exit Qualification for EPT Violations
union EptViolationQualification {
    ULONG64 all;
    struct {
        ULONG64 read_access : 1;                   //!< [0] 访问操作(access),bits[2:0]指示发生EPT violation时,guest执行什么访问操作
        ULONG64 write_access : 1;                  //!< [1] 访问操作(access),bits[2:0]指示发生EPT violation时,guest执行什么访问操作
        ULONG64 execute_access : 1;                //!< [2] 访问操作(access),bits[2:0]指示发生EPT violation时,guest执行什么访问操作
        ULONG64 ept_readable : 1;                  //!< [3] 访问权限(access),bits[3:5]指示该guest-physical-address具有什么访问权限
        ULONG64 ept_writeable : 1;                 //!< [4] 访问权限(access),bits[3:5]指示该guest-physical-address具有什么访问权限
        ULONG64 ept_executable : 1;                //!< [5] 访问权限(access),bits[3:5]指示该guest-physical-address具有什么访问权限
        ULONG64 ept_executable_for_user_mode : 1;  //!< [6] 
        ULONG64 valid_guest_linear_address : 1;    //!< [7] 0:时因为 mov to CR3指令导致PDPTE加载   1:表明GPA是来自于对guest-linear address的转换(2-9-9-9-12任何一环)
        ULONG64 caused_by_translation : 1;         //!< [8] 0:表明EPT_Violations发生在访问 guest-paging-structure表项环节上  1:表明EPT_Violations发生在GPA转换HPA阶段。也就是已经通过guest-paging-structure转换而来的GPA值
        ULONG64 user_mode_linear_address : 1;      //!< [9]
        ULONG64 readable_writable_page : 1;        //!< [10]
        ULONG64 execute_disable_page : 1;          //!< [11]
        ULONG64 nmi_unblocking : 1;                //!< [12]
    } fields;
};
static_assert(sizeof(EptViolationQualification) == 8, "Size check");

/// See: INVEPT Descriptor
struct InvEptDescriptor {
    EptPointer ept_pointer;
    ULONG64 reserved1;
};
static_assert(sizeof(InvEptDescriptor) == 16, "Size check");

/// @copydoc InvEptDescriptor
enum class InvEptType : ULONG_PTR {
    kSingleContextInvalidation = 1,
    kGlobalInvalidation = 2,
};

/// See: INVVPID Descriptor
struct InvVpidDescriptor {
    USHORT vpid;
    USHORT reserved1;
    ULONG32 reserved2;
    ULONG64 linear_address;
};
static_assert(sizeof(InvVpidDescriptor) == 16, "Size check");

/// @copydoc InvVpidDescriptor
enum class InvVpidType : ULONG_PTR {
    kIndividualAddressInvalidation = 0,
    kSingleContextInvalidation = 1,
    kAllContextInvalidation = 2,
    kSingleContextInvalidationExceptGlobal = 3,
};

/// See: Format of the VM-Exit Interruption-Information Field
union VmExitInterruptionInformationField {
    ULONG32 all;
    struct {
        ULONG32 vector : 8;             //!< [0:7]
        ULONG32 interruption_type : 3;  //!< [8:10]
        ULONG32 error_code_valid : 1;   //!< [11]    //error_code有效
        ULONG32 nmi_unblocking : 1;     //!< [12]
        ULONG32 reserved : 18;          //!< [13:30]
        ULONG32 valid : 1;              //!< [31]   说明这里的所有信息是 有效的
    } fields;
};
static_assert(sizeof(VmExitInterruptionInformationField) == 4, "Size check");

/// See: Format of the VM-Entry Interruption-Information Field
union VmEntryInterruptionInformationField {
    ULONG32 all;
    struct {
        ULONG32 vector : 8;              //!< [0:7]
        ULONG32 interruption_type : 3;   //!< [8:10]
        ULONG32 deliver_error_code : 1;  //!< [11]
        ULONG32 reserved : 19;           //!< [12:30]
        ULONG32 valid : 1;               //!< [31]
    } fields;
};
static_assert(sizeof(VmEntryInterruptionInformationField) == 4, "Size check");

/// @copydoc VmEntryInterruptionInformationField
enum class InterruptionType {
    kExternalInterrupt = 0,
    kReserved = 1,  // Not used for VM-Exit
    kNonMaskableInterrupt = 2,
    kHardwareException = 3,
    kSoftwareInterrupt = 4,            // Not used for VM-Exit
    kPrivilegedSoftwareException = 5,  // Not used for VM-Exit
    kSoftwareException = 6,
    kOtherEvent = 7,  // Not used for VM-Exit
};

/// @copydoc VmEntryInterruptionInformationField
/* 原文链接：https://blog.csdn.net/Gyc8787/article/details/121879298
* 
广义分类
类别	对CPU来说	      和当前CPU所执行的指令的关系	                                     CPU接下来的事情	                   程序员和用户的态度
中断	 被动的	              异步执行，没关系	                                              跳转到对应的 ISR	                希望有对应的中断，以使得CPU可以响应对应的中断，执行对应的ISR
异常	 被动的	              同步执行，有关系，当前指令执行出问题会导致异常	              跳转到对应的异常处理	           不希望出现异常，如果出现了，那往往是指令执行出现某些错误了
陷阱	 主动的	            同步执行，有关系，执行当前软中断指令才能够进入的软中断	       执行对应的软中断处理函数	         对于想要实现调试功能的程序员，有需要此陷阱的必要，其他人不用关心此点

狭义分类（x86分类）

类别	原因	              异步/同步(线程一核一个线程)	返回行为
中断	来自I/O设备的信号	    异步	                   总是返回到下一条指令
陷阱	有意的异常	            同步	                   总是返回到下一条指令
故障	潜在可恢复的错误	    同步	                    返回到当前指令
终止	不可恢复的错误	        同步	                    不会返回
*/
enum class InterruptionVector {                              //  向量     助记        描述                          类型         产生源
    kDivideErrorException = 0,         //!< Error code: None      0       #DE        除出错                         故障         DIV或IDIV指令
    kDebugException = 1,               //!< Error code: None      1       #DB        调试                           故障/陷阱    任何代码或数据引用，或是INT 1指令
    kNmiInterrupt = 2,                 //!< Error code: N/A       2                  NMI中断                        中断         非屏蔽外部中断
    kBreakpointException = 3,          //!< Error code: None      3       #BP        断点                           陷阱         INT 3指令
    kOverflowException = 4,            //!< Error code: None      4       #OF        溢出                           陷阱         INTO指令
    kBoundRangeExceededException = 5,  //!< Error code: None      5       #BR        边界范围超出                   故障         BOUND指令
    kInvalidOpcodeException = 6,       //!< Error code: None      6       #UD        无效操作码                     故障         UD2指令或保留的操作码
    kDeviceNotAvailableException = 7,  //!< Error code: None      7       #NM        设备不存在                     故障         浮点或WAIT/FWAIT指令
    kDoubleFaultException = 8,         //!< Error code: Yes       8       #DF        双重错误                       异常终止     任何可产生异常、NMI或INTR的指令
    kCoprocessorSegmentOverrun = 9,    //!< Error code: None      9                  协处理器段超越(保留)           故障         浮点指令
    kInvalidTssException = 10,         //!< Error code: Yes       10      #TS        无效的任务状态段TSS            故障         任务交换或访问TSS
    kSegmentNotPresent = 11,           //!< Error code: Yes       11      #NP        段不存在                       故障         加载段寄存器或访问系统段
    kStackFaultException = 12,         //!< Error code: Yes       12      #SS        段不存在                       故障         堆栈操作或SS寄存器加载
    kGeneralProtectionException = 13,  //!< Error code: Yes       13      #GP        一般保护错误                   故障         任何内存引用和其他保护检查
    kPageFaultException = 14,          //!< Error code: Yes       14      #PF        页面错误                       故障         任何内存引用
    kx87FpuFloatingPointError = 16,    //!< Error code: None      16      #MF        x87 FPU浮点错误                故障         
    kAlignmentCheckException = 17,     //!< Error code: Yes       17      #AC        对齐检查                       故障         对内存中任何数据的引用
    kMachineCheckException = 18,       //!< Error code: None      18      #MC        机器检查                       异常终止     错误码（若有）和产生源与CPU类型有关
    kSimdFloatingPointException = 19,  //!< Error code: None      19      #XF        机器检查                       故障         
    kVirtualizationException = 20,     //!< Error code: None      20      #VE        EPT violations                 故障         
    kControlProtectionException = 21,  //!< Error code: None      20      #CP   Control Protection Exception        故障          RET、IRET、RSTORSSP和setsbsy指令可以生成此异常   
};

/// Provides << operator for VmEntryInterruptionInformationField
constexpr unsigned int operator<<(_In_ unsigned int lhs,
    _In_ InterruptionVector rhs) {
    return (lhs << static_cast<unsigned int>(rhs));
}

#endif  // HYPERPLATFORM_IA32_TYPE_H_
