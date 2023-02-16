#pragma once
#include <ntifs.h>
#include "ia32_type.h"
#include "utl.h"

EXTERN_C{


    /// Invalidates translations derived from EPT
    /// @param invept_type  A type of invalidation
    /// @param invept_descriptor  A reference to EPTP to invalidate
    /// @return 0 on success, 1 w/ an error code or 2 w/o an error code on failure
    unsigned char __stdcall AsmInvept(
        _In_ InvEptType invept_type,
        _In_ const InvEptDescriptor * invept_descriptor);


   /// Invalidate translations based on VPID
   /// @param invvpid_type  A type of invalidation
   /// @param invvpid_descriptor  A description of translations to invalidate
   /// @return 0 on success, 1 w/ an error code or 2 w/o an error code on failure
   unsigned char __stdcall AsmInvvpid(
        _In_ InvVpidType invvpid_type,
        _In_ const InvVpidDescriptor* invvpid_descriptor);

   /// A wrapper for vm_initialization_routine.
   /// @param vm_initialization_routine  A function pointer for entering VMX-mode
   /// @param context  A context parameter for vm_initialization_routine
   /// @return true if vm_initialization_routine was successfully executed
   bool __stdcall AsmInitializeVm(
       _In_ void (*vm_initialization_routine)(_In_ ULONG_PTR, _In_ ULONG_PTR,
           _In_opt_ void*),
       _In_opt_ void* context);


   /// Writes to GDT
/// @param gdtr   A value to write
   void __stdcall AsmWriteGDT(_In_ const Gdtr* gdtr);

   /// Reads SLDT
   /// @return LDT
   USHORT __stdcall AsmReadLDTR();

   /// Writes to TR
   /// @param task_register   A value to write
   void __stdcall AsmWriteTR(_In_ USHORT task_register);

   /// Reads STR
   /// @return TR
   USHORT __stdcall AsmReadTR();

   /// Writes to ES
   /// @param segment_selector   A value to write
   void __stdcall AsmWriteES(_In_ USHORT segment_selector);

   /// Reads ES
   /// @return ES
   USHORT __stdcall AsmReadES();

   /// Writes to CS
   /// @param segment_selector   A value to write
   void __stdcall AsmWriteCS(_In_ USHORT segment_selector);

   /// Reads CS
   /// @return CS
   USHORT __stdcall AsmReadCS();

   /// Writes to SS
   /// @param segment_selector   A value to write
   void __stdcall AsmWriteSS(_In_ USHORT segment_selector);

   /// Reads SS
   /// @return SS
   USHORT __stdcall AsmReadSS();

   /// Writes to DS
   /// @param segment_selector   A value to write
   void __stdcall AsmWriteDS(_In_ USHORT segment_selector);

   /// Reads DS
   /// @return DS
   USHORT __stdcall AsmReadDS();

   /// Writes to FS
   /// @param segment_selector   A value to write
   void __stdcall AsmWriteFS(_In_ USHORT segment_selector);

   /// Reads FS
   /// @return FS
   USHORT __stdcall AsmReadFS();

   /// Writes to GS
   /// @param segment_selector   A value to write
   void __stdcall AsmWriteGS(_In_ USHORT segment_selector);

   /// Reads GS
   /// @return GS
   USHORT __stdcall AsmReadGS();

   /// Loads access rights byte
   /// @param segment_selector   A value to get access rights byte
   /// @return An access rights byte
   ULONG_PTR __stdcall AsmLoadAccessRightsByte(_In_ ULONG_PTR segment_selector);

   /// An entry point of VMM where gets called whenever VM-exit occurred.
   void __stdcall AsmVmmEntryPoint();

   /// Executes VMCALL with the given hypercall number and a context.
   /// @param hypercall_number   A hypercall number
   /// @param context  A context parameter for VMCALL
   /// @return Equivalent to #VmxStatus
   unsigned char __stdcall AsmVmxCall(_In_ ULONG_PTR hypercall_number, _In_opt_ void* context, ULONG nMark);
   /// Reads SGDT
   /// @param gdtr   A pointer to read GDTR
   inline void __lgdt(_In_ void* gdtr) { AsmWriteGDT(static_cast<Gdtr*>(gdtr)); }
   /// Invalidates internal caches
   void __stdcall AsmInvalidateInternalCaches();

   /// Writes to CR2
/// @param cr2_value  A value to write
   void __stdcall AsmWriteCR2(_In_ ULONG_PTR cr2_value);

}