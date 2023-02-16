

EXTERN VmmVmExitHandler : PROC


.CONST

VMX_OK                      EQU     0
VMX_ERROR_WITH_STATUS       EQU     1
VMX_ERROR_WITHOUT_STATUS    EQU     2

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; macros
;

; Saves all general purpose registers to the stack
PUSHAQ MACRO
    push    rax
    push    rcx
    push    rdx
    push    rbx
    push    -1      ; dummy for rsp
    push    rbp
    push    rsi
    push    rdi
    push    r8
    push    r9
    push    r10
    push    r11
    push    r12
    push    r13
    push    r14
    push    r15
ENDM

; Loads all general purpose registers from the stack
POPAQ MACRO
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rdi
    pop     rsi
    pop     rbp
    add     rsp, 8    ; dummy for rsp
    pop     rbx
    pop     rdx
    pop     rcx
    pop     rax
ENDM



.CODE



; bool __stdcall AsmInitializeVm(
;     _In_ void (*vm_initialization_routine)(_In_ ULONG_PTR, _In_ ULONG_PTR,
;                                            _In_opt_ void *),
;     _In_opt_ void *context);
AsmInitializeVm PROC
    ; RSP is not 16 bit aligned when it gets called, but the following odd
    ; number (17 times) of push makes RSP 16 bit aligned.
    pushfq
    PUSHAQ              ; -8 * 16

    mov rax, rcx
    mov r8, rdx
    mov rdx, asmResumeVm
    mov rcx, rsp

    sub rsp, 20h
    call rax            ; vm_initialization_routine(rsp, asmResumeVm, context)
    add rsp, 20h

    POPAQ
    popfq
    xor rax, rax        ; return false
    ret

    ; This is where the virtualized guest start to execute after successful
    ; vmlaunch.
asmResumeVm:
    nop                 ; keep this nop for ease of debugging
    POPAQ
    popfq

    ;sub rsp, 8          ; align RSP
    ;ASM_DUMP_REGISTERS
    ;add rsp, 8          ; restore RSP

    xor rax, rax
    inc rax             ; return true
    ret
AsmInitializeVm ENDP


; unsigned char __stdcall AsmInvept(
;     _In_ InvEptType invept_type,
;     _In_ const InvEptDescriptor *invept_descriptor);
AsmInvept PROC
    ; invept  ecx, oword ptr [rdx]
    db  66h, 0fh, 38h, 80h, 0ah
    jz errorWithCode        ; if (ZF) jmp
    jc errorWithoutCode     ; if (CF) jmp
    xor rax, rax            ; return VMX_OK
    ret

errorWithoutCode:
    mov rax, VMX_ERROR_WITHOUT_STATUS
    ret

errorWithCode:
    mov rax, VMX_ERROR_WITH_STATUS
    ret
AsmInvept ENDP


; void __stdcall AsmInvalidateInternalCaches();
AsmInvalidateInternalCaches PROC
    invd
    ret
AsmInvalidateInternalCaches ENDP 

; unsigned char __stdcall AsmInvvpid(
;     _In_ InvVpidType invvpid_type,
;     _In_ const InvVpidDescriptor *invvpid_descriptor);
AsmInvvpid PROC
    ; invvpid  ecx, oword ptr [rdx]
    db  66h, 0fh, 38h, 81h, 0ah
    jz errorWithCode        ; if (ZF) jmp
    jc errorWithoutCode     ; if (CF) jmp
    xor rax, rax            ; return VMX_OK
    ret

errorWithoutCode:
    mov rax, VMX_ERROR_WITHOUT_STATUS
    ret

errorWithCode:
    mov rax, VMX_ERROR_WITH_STATUS
    ret
AsmInvvpid ENDP


; void __stdcall AsmWriteGDT(_In_ const GDTR *gdtr);
AsmWriteGDT PROC
    lgdt fword ptr [rcx]
    ret
AsmWriteGDT ENDP

; void __stdcall AsmWriteLDTR(_In_ USHORT local_segmeng_selector);
AsmWriteLDTR PROC
    lldt cx
    ret
AsmWriteLDTR ENDP

; USHORT __stdcall AsmReadLDTR();
AsmReadLDTR PROC
    sldt ax
    ret
AsmReadLDTR ENDP

; void __stdcall AsmWriteTR(_In_ USHORT task_register);
AsmWriteTR PROC
    ltr cx
    ret
AsmWriteTR ENDP

; USHORT __stdcall AsmReadTR();
AsmReadTR PROC
    str ax
    ret
AsmReadTR ENDP

; void __stdcall AsmWriteES(_In_ USHORT segment_selector);
AsmWriteES PROC
    mov es, cx
    ret
AsmWriteES ENDP

; USHORT __stdcall AsmReadES();
AsmReadES PROC
    mov ax, es
    ret
AsmReadES ENDP

; void __stdcall AsmWriteCS(_In_ USHORT segment_selector);
AsmWriteCS PROC
    mov cs, cx
    ret
AsmWriteCS ENDP

; USHORT __stdcall AsmReadCS();
AsmReadCS PROC
    mov ax, cs
    ret
AsmReadCS ENDP

; void __stdcall AsmWriteSS(_In_ USHORT segment_selector);
AsmWriteSS PROC
    mov ss, cx
    ret
AsmWriteSS ENDP

; USHORT __stdcall AsmReadSS();
AsmReadSS PROC
    mov ax, ss
    ret
AsmReadSS ENDP

; void __stdcall AsmWriteDS(_In_ USHORT segment_selector);
AsmWriteDS PROC
    mov ds, cx
    ret
AsmWriteDS ENDP

; USHORT __stdcall AsmReadDS();
AsmReadDS PROC
    mov ax, ds
    ret
AsmReadDS ENDP

; void __stdcall AsmWriteFS(_In_ USHORT segment_selector);
AsmWriteFS PROC
    mov fs, cx
    ret
AsmWriteFS ENDP

; USHORT __stdcall AsmReadFS();
AsmReadFS PROC
    mov ax, fs
    ret
AsmReadFS ENDP

; void __stdcall AsmWriteGS(_In_ USHORT segment_selector);
AsmWriteGS PROC
    mov gs, cx
    ret
AsmWriteGS ENDP

; USHORT __stdcall AsmReadGS();
AsmReadGS PROC
    mov ax, gs
    ret
AsmReadGS ENDP

; unsigned char __stdcall AsmVmxCall(_In_ ULONG_PTR hypercall_number,
;                                    _In_opt_ void *context);
AsmVmxCall PROC
    vmcall                  ; vmcall(hypercall_number, context)
    jz errorWithCode        ; if (ZF) jmp
    jc errorWithoutCode     ; if (CF) jmp
    xor rax, rax            ; return VMX_OK
    ret

errorWithoutCode:
    mov rax, VMX_ERROR_WITHOUT_STATUS
    ret

errorWithCode:
    mov rax, VMX_ERROR_WITH_STATUS
    ret
AsmVmxCall ENDP

; void __stdcall AsmWriteCR2(_In_ ULONG_PTR cr2_value);
AsmWriteCR2 PROC
    mov cr2, rcx
    ret
AsmWriteCR2 ENDP

; ULONG_PTR __stdcall AsmLoadAccessRightsByte(_In_ ULONG_PTR segment_selector);
AsmLoadAccessRightsByte PROC
    lar rax, rcx
    ret
AsmLoadAccessRightsByte ENDP



; void __stdcall AsmVmmEntryPoint();
AsmVmmEntryPoint PROC

PUSHAQ 
movaps xmmword ptr [rsp -  10h], xmm15
movaps xmmword ptr [rsp - 20h], xmm14
movaps xmmword ptr [rsp - 30h], xmm13
movaps xmmword ptr [rsp - 40h], xmm12
movaps xmmword ptr [rsp - 50h], xmm11
movaps xmmword ptr [rsp - 60h], xmm10
movaps xmmword ptr [rsp - 70h], xmm9
movaps xmmword ptr [rsp - 80h], xmm8
movaps xmmword ptr [rsp - 90h], xmm7
movaps xmmword ptr [rsp - 0a0h], xmm6
movaps xmmword ptr [rsp - 0b0h], xmm5
movaps xmmword ptr [rsp - 0c0h], xmm4
movaps xmmword ptr [rsp - 0d0h], xmm3
movaps xmmword ptr [rsp - 0e0h], xmm2
movaps xmmword ptr [rsp - 0f0h], xmm1
movaps xmmword ptr [rsp - 100h], xmm0

lea rcx,[rsp - 100h]

sub rsp,150h
call VmmVmExitHandler
add rsp,150h

movaps xmm15,xmmword ptr [rsp -  10h]
movaps xmm14,xmmword ptr [rsp - 20h]
movaps xmm13,xmmword ptr [rsp - 30h]
movaps xmm12,xmmword ptr [rsp - 40h]
movaps xmm11,xmmword ptr [rsp - 50h]
movaps xmm10,xmmword ptr [rsp - 60h]
movaps xmm9,xmmword ptr [rsp - 70h]
movaps xmm8,xmmword ptr [rsp - 80h]
movaps xmm7,xmmword ptr [rsp - 90h]
movaps xmm6,xmmword ptr [rsp - 0a0h]
movaps xmm5,xmmword ptr [rsp - 0b0h]
movaps xmm4,xmmword ptr [rsp - 0c0h]
movaps xmm3,xmmword ptr [rsp - 0d0h]
movaps xmm2,xmmword ptr [rsp - 0e0h]
movaps xmm1,xmmword ptr [rsp - 0f0h]
movaps xmm0,xmmword ptr [rsp - 100h]

test al, al
jz exitVm               ; if (!vm_continue) jmp exitVm

POPAQ
vmresume


exitVm:
; Executes vmxoff and ends virtualization
;   rax = Guest's rflags
;   rdx = Guest's rsp
;   rcx = Guest's rip for the next instruction
POPAQ
vmxoff
jz vmxError             ; if (ZF) jmp
jc vmxError             ; if (CF) jmp
push rax
popfq                   ; rflags <= GurstFlags
mov rsp, rdx            ; rsp <= GuestRsp
push rcx
ret                     ; jmp AddressToReturn

vmxError:
; Diagnose a critical error
pushfq
PUSHAQ                      ; -8 * 16
mov rcx, rsp                ; all_regs

sub rsp, 28h                ; 28h for alignment
;call VmmVmxFailureHandler   ; VmmVmxFailureHandler(all_regs);
add rsp, 28h
int 3


AsmVmmEntryPoint ENDP
END