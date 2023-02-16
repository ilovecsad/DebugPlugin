#pragma once
#include <ntifs.h>

/* https://www.cnblogs.com/Rev-omi/p/14063037.html
VMM：Virtual Machine Monitor，虚拟机监控器。也称为 “Hypervisior”，特权层(Ring -1)，能够监控操作系统的各种行为。
VMX：Virtual Machine Extension，虚拟机扩展。是 CPU 提供的一种功能。
VMCS：Virtual-Machine Control Structure，虚拟机控制结构，一块内存区域。
APIC：Advanced Programmable Interrupt Controller 高级可编程中断控制器，硬件设备
MSR：Model Specific Register，一组64位寄存器，通过 RDMSR 和 WRMSR 进行读写操作。命名以 IA32_ 为前缀，
一系列用于控制 CPU 运行、功能开关、调试、跟踪程序执行、监测 CPU 性能等方面的寄存器

CR0-CR3:控制寄存器。
CR0：控制处理器操作模式和状态
CR1：保留不用
CR2：导致页面错误的线性地址
CR3：页目录表物理内存基地址


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




/// Represents VMM related data shared across all processors
struct SharedProcessorData {
	volatile long reference_count;  //!< Number of processors sharing this data
	void* msr_bitmap;               //!< Bitmap to activate MSR I/O VM-exit
	void* io_bitmap_a;              //!< Bitmap to activate IO VM-exit (~ 0x7FFF)
	void* io_bitmap_b;              //!< Bitmap to activate IO VM-exit (~ 0xffff)
	//struct SharedShadowHookData* shared_sh_data;  //!< Shared shadow hook data
};

/// Represents VMM related data associated with each processor
struct ProcessorData {
	SharedProcessorData* shared_data;         //!< Shared data
	void* vmm_stack_limit;                    //!< A head of VA for VMM stack
	struct VmControlStructure* vmxon_region;  //!< VA of a VMXON region
	struct VmControlStructure* vmcs_region;   //!< VA of a VMCS region
	struct EptData* ept_data;                 //!< A pointer to EPT related data
	//struct ShadowHookData* sh_data;           //!< Per-processor shadow hook data
};

/*
* 
* vm_entryctl_requested.fields.ia32e_mode_guest = IsX64();  vm_exitctl_requested.fields.host_address_space_size = IsX64(); 这是 __vmx_vmlaunch 执行的最小条件
* 下面这些异常 可以被 windbg int3接管 也就是必须
1.cpuid
2.rdmsr
3.wrmsr
//////然后 windbg 无法接管异常  ida的 gdbserver 也无法在 VmmpHandleVmExit 断下来 找原因     /////////
经过 大量时间测试 得知   当  vm_procctl_requested.fields.mov_dr_exiting = true; 才能被断下
4. kDrAccess = 29,

必须交由我们自己处理的VM-EXIT事件(即不在CPU_BASED_VM_EXEC_CONTROL或EXCEPTION_BITMAP控制内的)：



原文链接：https://blog.csdn.net/zhuhuibeishadiao/article/details/52470491

必须处理
EXIT_REASON_MSR_READ(0x1F)31
EXIT_REASON_MSR_WRITE(0x20)32
EXIT_REASON_CR_ACCESS(0x1C)28
EXIT_REASON_INVD(0xD)13
EXIT_REASON_CPUID(0xA)10
EXIT_REASON_VMCALL(0x12)18
win10 还要添加




实验1_S:标准 在虚拟机下(vmware),开四核 且开火绒 一个小时 不蓝屏
实验1_F:说明 实验1 失败


实验2_S:

*/