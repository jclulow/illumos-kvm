/*
 * Kernel-based Virtual Machine driver for Linux
 *
 * AMD SVM support
 *
 * Copyright (C) 2006 Qumranet, Inc.
 *
 * Authors:
 *   Yaniv Kamay  <yaniv@qumranet.com>
 *   Avi Kivity   <avi@qumranet.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Modifications Copyright 2011 Joshua M. Clulow
 *                                <josh@sysmgr.org>
 *
 */
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/mach_mmu.h>
#include <asm/cpu.h>
#include <sys/x86_archext.h>
#include <sys/xc_levels.h>

#include "kvm_bitops.h"
#include "kvm_msr.h"
#include "kvm_cpuid.h"
#include "kvm_impl.h"
#include "kvm_x86impl.h"
#include "kvm_cache_regs.h"
#include "kvm_host.h"
#include "kvm_iodev.h"
#include "kvm_irq.h"
#include "kvm_mmu.h"
#include "kvm_svm.h"


#define __ex(x) __kvm_handle_fault_on_reboot(x)


/* JMC */
static kmem_cache_t *kvm_svm_vcpu_cache;
static kmem_cache_t *kvm_svm_vmcb_cache;
static kmem_cache_t *kvm_svm_msrpm_cache;
static kmem_cache_t *kvm_svm_iopm_cache;
static kmem_cache_t *kvm_svm_cpudata_cache;
static kmem_cache_t *kvm_svm_savearea_cache;

/* per-CPU structure: */
static struct svm_cpu_data **kvm_svm_cpu_data;

/* JOYENT */

#if 0
static struct vmcs **vmxarea;  /* 1 per cpu */
static struct vmcs **current_vmcs;
static uint64_t *vmxarea_pa;   /* physical address of each vmxarea */
#endif





#define IOPM_ALLOC_ORDER 2
#define MSRPM_ALLOC_ORDER 1

#define SEG_TYPE_LDT 2
#define SEG_TYPE_BUSY_TSS16 3

#define SVM_FEATURE_NPT  (1 << 0)
#define SVM_FEATURE_LBRV (1 << 1)
#define SVM_FEATURE_SVML (1 << 2)
#define SVM_FEATURE_PAUSE_FILTER (1 << 10)

#define NESTED_EXIT_HOST	0	/* Exit handled on host level */
#define NESTED_EXIT_DONE	1	/* Exit caused nested vmexit  */
#define NESTED_EXIT_CONTINUE	2	/* Further checks needed      */

#define DEBUGCTL_RESERVED_BITS (~(0x3fULL))

static const uint32_t host_save_user_msrs[] = {
	MSR_STAR, MSR_LSTAR, MSR_CSTAR, MSR_SYSCALL_MASK, MSR_KERNEL_GS_BASE,
	MSR_FS_BASE,
	MSR_IA32_SYSENTER_CS, MSR_IA32_SYSENTER_ESP, MSR_IA32_SYSENTER_EIP,
};


#define NR_HOST_SAVE_USER_MSRS ARRAY_SIZE(host_save_user_msrs)


struct kvm_vcpu;

typedef struct vcpu_svm {
	struct kvm_vcpu vcpu;
	struct vmcb *vmcb;
	uint64_t vmcb_pa; /* physical address of svm's vmcb */
	struct svm_cpu_data *svm_data;
	uint64_t asid_generation;
	uint64_t sysenter_esp;
	uint64_t sysenter_eip;

	uint64_t next_rip;

	uint64_t host_user_msrs[NR_HOST_SAVE_USER_MSRS];
	uint64_t host_gs_base;

	uint32_t *msrpm;

	char nmi_singlestep;
} vcpu_svm_t;

static char npt_enabled = 1; /* XXX was for x64 or x86+PAE */
static int npt = 1;

/* module_param(npt, int, S_IRUGO); */

static void svm_flush_tlb(struct kvm_vcpu *vcpu);
static void svm_complete_interrupts(struct vcpu_svm *svm);

static struct vcpu_svm *
to_svm(struct kvm_vcpu *vcpu)
{
	return ((struct vcpu_svm *)((uintptr_t)vcpu -
	    offsetof(struct vcpu_svm, vcpu)));
}

static void
enable_gif(struct vcpu_svm *svm)
{
	svm->vcpu.arch.hflags |= HF_GIF_MASK;
}

static void
disable_gif(struct vcpu_svm *svm)
{
	svm->vcpu.arch.hflags &= ~HF_GIF_MASK;
}

static char
gif_set(struct vcpu_svm *svm)
{
	return (!!(svm->vcpu.arch.hflags & HF_GIF_MASK));
}

static unsigned long iopm_base;
static void *iopm_va;

/*
struct kvm_ldttss_desc {
	uint16_t limit0;
	uint16_t base0;
	unsigned base1 : 8, type : 5, dpl : 2, p : 1;
	unsigned limit1 : 4, zero0 : 3, g : 1, base2 : 8;
	uint32_t base3;
	uint32_t zero1;
} __attribute__((packed));
*/

struct svm_cpu_data {
	int cpu;

	uint64_t asid_generation;
	uint32_t max_asid;
	uint32_t next_asid;
	/*struct kvm_ldttss_desc *tss_desc; */
	/*struct desc_struct *tss_desc;*/

	void *save_area;
};

#if 0
static DEFINE_PER_CPU(struct svm_cpu_data *, svm_data);
#endif
static uint32_t svm_features;

struct svm_init_data {
	int cpu;
	int r;
};

static uint32_t msrpm_ranges[] = {0, 0xc0000000, 0xc0010000};

#define NUM_MSR_MAPS ARRAY_SIZE(msrpm_ranges)
#define MSRS_RANGE_SIZE 2048
#define MSRS_IN_RANGE (MSRS_RANGE_SIZE * 8 / 2)

#define MAX_INST_SIZE 15

static char
svm_has(uint32_t feat)
{
	return (!!(svm_features & feat));
}

static int
cpu_has_svm(const char **msg)
{
	struct cpuid_regs cp;

	/* assume boot cpu == amd for now */

#if 0
	cp.cp_eax = 0x80000000;
	cp.cp_ebx = cp.cp_ecx = cp.cp_edx = 0;
	(void) __cpuid_insn(&cp);
	if (cp.cp_eax < SVM_CPUID_FUNC) {
		if (msg)
			*msg = "can't execute cpuid_8000000a";
		return (0);
	}

	cp.cp_eax = 0x80000001;
	cp.cp_ebx = cp.cp_ecx = cp.cp_edx = 0;
	(void) __cpuid_insn(&cp);
	if (!(cp.cp_ecx & (1 << SVM_CPUID_FEATURE_SHIFT))) {
		if (msg)
			*msg = "svm not available";
		return (0);
	}
	return (1);
#endif

	if (is_x86_feature(x86_featureset, X86FSET_SVM))
		return (1);

	return (0);

}

static void
cpu_svm_disable(void)
{
	uint64_t efer;

	wrmsrl(MSR_VM_HSAVE_PA, 0);
	rdmsrl(MSR_EFER, efer);
	wrmsrl(MSR_EFER, efer & ~EFER_SVME);
}

static int
cpuid_ebx(unsigned int op)
{
	struct cpuid_regs cp;

	cp.cp_eax = op;
	cp.cp_ecx = 0;
	(void) __cpuid_insn(&cp);

	return (cp.cp_ebx);
}

static int
cpuid_edx(unsigned int op)
{
	struct cpuid_regs cp;

	cp.cp_eax = op;
	cp.cp_ecx = 0;
	(void) __cpuid_insn(&cp);

	return (cp.cp_edx);
}

static unsigned int
__get_cs_val(void)
{
	unsigned int x;

	__asm__ volatile ("mov %%cs, %0\n" : "=r"(x));
	return x;
}

/* CLGI: clear global interrupt flag */
static void
clgi(void)
{
	__asm__ volatile (__ex(SVM_CLGI));
}

/* STGI: set global interrupt flag */
static void
stgi(void)
{
	__asm__ volatile (__ex(SVM_STGI));
}

/* INVLPGA: invalidate TLB mapping for given virtual page + asid */
static  void invlpga(unsigned long addr, uint32_t asid)
{
	__asm__ volatile (__ex(SVM_INVLPGA) :: "a"(addr), "c"(asid));
}

static void
force_new_asid(struct kvm_vcpu *vcpu)
{
	to_svm(vcpu)->asid_generation--;
}

static void
flush_guest_tlb(struct kvm_vcpu *vcpu)
{
	force_new_asid(vcpu);
}

static void
svm_set_efer(struct kvm_vcpu *vcpu, uint64_t efer)
{
	if (!npt_enabled && !(efer & EFER_LMA))
		efer &= ~EFER_LME;

	to_svm(vcpu)->vmcb->save.efer = efer | EFER_SVME;
	vcpu->arch.efer = efer;
}

static void
svm_queue_exception(struct kvm_vcpu *vcpu, unsigned nr,
    int has_error_code, uint32_t error_code)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	svm->vmcb->control.event_inj = nr
		| SVM_EVTINJ_VALID
		| (has_error_code ? SVM_EVTINJ_VALID_ERR : 0)
		| SVM_EVTINJ_TYPE_EXEPT;
	svm->vmcb->control.event_inj_err = error_code;
}

static int
is_external_interrupt(uint32_t intr_info)
{
	return ((intr_info & (SVM_EVTINJ_TYPE_MASK |
	    SVM_EVTINJ_VALID)) == (SVM_EVTINJ_VALID |
	    SVM_EVTINJ_TYPE_INTR));
}

static uint32_t
svm_get_interrupt_shadow(struct kvm_vcpu *vcpu, int mask)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	uint32_t ret = 0;

	if (svm->vmcb->control.int_state & SVM_INTERRUPT_SHADOW_MASK)
		ret |= X86_SHADOW_INT_STI | X86_SHADOW_INT_MOV_SS;
	return (ret & mask);
}

static void
svm_set_interrupt_shadow(struct kvm_vcpu *vcpu, int mask)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	if (mask == 0)
		svm->vmcb->control.int_state &= ~SVM_INTERRUPT_SHADOW_MASK;
	else
		svm->vmcb->control.int_state |= SVM_INTERRUPT_SHADOW_MASK;

}

static void
skip_emulated_instruction(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	if (!svm->next_rip) {
		if (emulate_instruction(vcpu, 0, 0, EMULTYPE_SKIP) !=
				EMULATE_DONE)
			cmn_err(CE_NOTE, "%s: NOP\n", __func__);
		return;
	}
	if (svm->next_rip - kvm_rip_read(vcpu) > MAX_INST_SIZE)
		cmn_err(CE_WARN, "%s: ip 0x%lx next 0x%llx\n",
		       __func__, kvm_rip_read(vcpu), (long long unsigned)svm->next_rip);

	kvm_rip_write(vcpu, svm->next_rip);
	svm_set_interrupt_shadow(vcpu, 0);
}

static int
has_svm(void)
{
	const char *msg;

	if (!cpu_has_svm(&msg)) {
		cmn_err(CE_NOTE, "has_svm: %s\n", msg);
		return (-1);
	}

	return (0);
}

static void
svm_hardware_disable(void *garbage)
{
	cmn_err(CE_NOTE, "KVM: svm_hardware_disable\n");
	cpu_svm_disable();
}

static int
svm_hardware_enable(void *garbage)
{

	struct svm_cpu_data *sd;
	uint64_t efer;
	/*struct descriptor_table gdt;
	struct desc_struct *descs;*/
	int cpu = curthread->t_cpu->cpu_seqid;

	cmn_err(CE_NOTE, "KVM: svm_hardware_enable\n");

	rdmsrl(MSR_EFER, efer);
	if (efer & EFER_SVME)
		return (DDI_FAILURE);

	/* XXX surely we already do this check.
	if (!has_svm()) {
		cmn_err(CE_WARN, "svm_hardware_enable: err EOPNOTSUPP "
		    "on %d\n", cpu);
		return (DDI_FAILURE);
	}*/
	sd = kvm_svm_cpu_data[cpu];

	if (!sd) {
		cmn_err(CE_WARN, "svm_hardware_enable: svm_data is "
		    "NULL on %d\n", cpu);
		return (DDI_FAILURE);
	}

	sd->asid_generation = 1;
	sd->max_asid = cpuid_ebx(SVM_CPUID_FUNC) - 1;
	sd->next_asid = sd->max_asid + 1;

/*
	kvm_get_gdt(&gdt);
	descs = (void *)gdt.base;
	sd->tss_desc = (struct desc_struct *)descs[GDT_KTSS];
*/

	wrmsrl(MSR_EFER, efer | EFER_SVME);

	wrmsrl(MSR_VM_HSAVE_PA, kvm_va2pa((caddr_t)sd->save_area));

	return (0);
}

static void
svm_cpu_uninit(int cpu)
{
	/*int cpu = curthread->t_cpu->cpu_seqid; */
	struct svm_cpu_data *sd = kvm_svm_cpu_data[cpu];

	if (!sd)
		return;

	kvm_svm_cpu_data[cpu] = NULL;
	kmem_cache_free(kvm_svm_savearea_cache, sd->save_area);
	kmem_cache_free(kvm_svm_cpudata_cache, sd);
}

static int
svm_cpu_init(int cpu)
{
	struct svm_cpu_data *sd;
	int r;

	sd = kmem_cache_alloc(kvm_svm_cpudata_cache, KM_SLEEP);
	if (!sd)
		return (ENOMEM);
	
	sd->cpu = cpu;
	sd->save_area = kmem_cache_alloc(kvm_svm_savearea_cache, KM_SLEEP);
	if (!sd->save_area) {
		kmem_cache_free(kvm_svm_cpudata_cache, sd);
		return (ENOMEM);
	}

	kvm_svm_cpu_data[cpu] = sd;

	return (0);
}

static void
set_msr_interception(uint32_t *msrpm, unsigned msr, int read, int write)
{
	int i;

	for (i = 0; i < NUM_MSR_MAPS; i++) {
		if (msr >= msrpm_ranges[i] &&
		    msr < msrpm_ranges[i] + MSRS_IN_RANGE) {
			uint32_t msr_offset = (i * MSRS_IN_RANGE + msr -
					  msrpm_ranges[i]) * 2;

			uint32_t *base = msrpm + (msr_offset / 32);
			uint32_t msr_shift = msr_offset % 32;
			uint32_t mask = ((write) ? 0 : 2) | ((read) ? 0 : 1);
			*base = (*base & ~(0x3 << msr_shift)) |
				(mask << msr_shift);
			return;
		}
	}
	cmn_err(CE_PANIC, "reached end of set_msr_interception()\n");
}

static void
svm_vcpu_init_msrpm(uint32_t *msrpm)
{
	memset(msrpm, 0xff, SVM_ALLOC_MSRPM_SIZE);

	set_msr_interception(msrpm, MSR_GS_BASE, 1, 1);
	set_msr_interception(msrpm, MSR_FS_BASE, 1, 1);
	set_msr_interception(msrpm, MSR_KERNEL_GS_BASE, 1, 1);
	set_msr_interception(msrpm, MSR_LSTAR, 1, 1);
	set_msr_interception(msrpm, MSR_CSTAR, 1, 1);
	set_msr_interception(msrpm, MSR_SYSCALL_MASK, 1, 1);
	set_msr_interception(msrpm, MSR_K6_STAR, 1, 1);
	set_msr_interception(msrpm, MSR_IA32_SYSENTER_CS, 1, 1);
}

static void
svm_enable_lbrv(struct vcpu_svm *svm)
{
	uint32_t *msrpm = svm->msrpm;

	svm->vmcb->control.lbr_ctl = 1;
	set_msr_interception(msrpm, MSR_IA32_LASTBRANCHFROMIP, 1, 1);
	set_msr_interception(msrpm, MSR_IA32_LASTBRANCHTOIP, 1, 1);
	set_msr_interception(msrpm, MSR_IA32_LASTINTFROMIP, 1, 1);
	set_msr_interception(msrpm, MSR_IA32_LASTINTTOIP, 1, 1);
}

static void
svm_disable_lbrv(struct vcpu_svm *svm)
{
	uint32_t *msrpm = svm->msrpm;

	svm->vmcb->control.lbr_ctl = 0;
	set_msr_interception(msrpm, MSR_IA32_LASTBRANCHFROMIP, 0, 0);
	set_msr_interception(msrpm, MSR_IA32_LASTBRANCHTOIP, 0, 0);
	set_msr_interception(msrpm, MSR_IA32_LASTINTFROMIP, 0, 0);
	set_msr_interception(msrpm, MSR_IA32_LASTINTTOIP, 0, 0);
}

static int
svm_hardware_setup(void)
{
	int cpu;
	int r, i;

	iopm_va = kmem_cache_alloc(kvm_svm_iopm_cache, KM_SLEEP);
	if (!iopm_va)
		return (ENOMEM);

	memset(iopm_va, 0xff, SVM_ALLOC_IOPM_SIZE);
	

	iopm_base = kvm_va2pa((caddr_t)iopm_va);

	if (is_x86_feature(x86_featureset, X86FSET_NX))
		kvm_enable_efer_bits(EFER_NX);

	/* XXX figure this shit out */
#if 0
	if (boot_cpu_has(X86_FEATURE_FXSR_OPT))
		kvm_enable_efer_bits(EFER_FFXSR);
#endif

	kvm_svm_cpu_data = kmem_alloc(ncpus * sizeof (struct svm_cpu_data *), KM_SLEEP);
	for (i = 0; i < ncpus; i++) {
		kvm_svm_cpu_data[i] = NULL;
	}

	for (i = 0; i < ncpus; i++) {
		r = svm_cpu_init(i);
		if (r) {
			kmem_cache_free(kvm_svm_iopm_cache, iopm_va);
			iopm_base = 0;
			iopm_va = NULL;
			return (r);
		}
	}

	svm_features = cpuid_edx(SVM_CPUID_FUNC);
	cmn_err(CE_NOTE, "kvm: svm_features = %x\n", svm_features);

	if (!svm_has(SVM_FEATURE_NPT))
		npt_enabled = 0;

	if (npt_enabled && !npt) {
		cmn_err(CE_NOTE, "Nested Paging disabled\n");
		npt_enabled = 0;
	}

	if (npt_enabled) {
		cmn_err(CE_NOTE, "Nested Paging enabled\n");
		kvm_enable_tdp();
	} else
		kvm_disable_tdp();

	return (0);
}

static void
svm_hardware_unsetup(void)
{
	int cpu;

	for (cpu = 0; cpu < ncpus; cpu++) {
		svm_cpu_uninit(cpu);
		if (kvm_svm_cpu_data[cpu] != NULL) {
			kmem_cache_free(kvm_svm_cpudata_cache,
			    kvm_svm_cpu_data[cpu]);
			kvm_svm_cpu_data[cpu] = NULL;
		} else {
			cmn_err(CE_NOTE, "kvm: cpu %d had null cpu_data\n", cpu);
		}
	}

	kmem_cache_free(kvm_svm_iopm_cache, iopm_va);
	iopm_base = 0;
	iopm_va = NULL;
}

static void
init_seg(struct vmcb_seg *seg)
{
	seg->selector = 0;
	seg->attrib = SVM_SELECTOR_P_MASK | SVM_SELECTOR_S_MASK |
		SVM_SELECTOR_WRITE_MASK; /* Read/Write Data Segment */
	seg->limit = 0xffff;
	seg->base = 0;
}

static void
init_sys_seg(struct vmcb_seg *seg, uint32_t type)
{
	seg->selector = 0;
	seg->attrib = SVM_SELECTOR_P_MASK | type;
	seg->limit = 0xffff;
	seg->base = 0;
}

static void
init_vmcb(struct vcpu_svm *svm)
{
	struct vmcb_control_area *control = &svm->vmcb->control;
	struct vmcb_save_area *save = &svm->vmcb->save;

	svm->vcpu.fpu_active = 1;

	control->intercept_cr_read = 	INTERCEPT_CR0_MASK |
					INTERCEPT_CR3_MASK |
					INTERCEPT_CR4_MASK;

	control->intercept_cr_write = 	INTERCEPT_CR0_MASK |
					INTERCEPT_CR3_MASK |
					INTERCEPT_CR4_MASK |
					INTERCEPT_CR8_MASK;

	control->intercept_dr_read = 	INTERCEPT_DR0_MASK |
					INTERCEPT_DR1_MASK |
					INTERCEPT_DR2_MASK |
					INTERCEPT_DR3_MASK |
					INTERCEPT_DR4_MASK |
					INTERCEPT_DR5_MASK |
					INTERCEPT_DR6_MASK |
					INTERCEPT_DR7_MASK;

	control->intercept_dr_write = 	INTERCEPT_DR0_MASK |
					INTERCEPT_DR1_MASK |
					INTERCEPT_DR2_MASK |
					INTERCEPT_DR3_MASK |
					INTERCEPT_DR4_MASK |
					INTERCEPT_DR5_MASK |
					INTERCEPT_DR6_MASK |
					INTERCEPT_DR7_MASK;

	control->intercept_exceptions = (1 << PF_VECTOR) |
					(1 << UD_VECTOR) |
					(1 << MC_VECTOR);


	control->intercept = 	(1ULL << INTERCEPT_INTR) |
				(1ULL << INTERCEPT_NMI) |
				(1ULL << INTERCEPT_SMI) |
				(1ULL << INTERCEPT_SELECTIVE_CR0) |
				(1ULL << INTERCEPT_CPUID) |
				(1ULL << INTERCEPT_INVD) |
				(1ULL << INTERCEPT_HLT) |
				(1ULL << INTERCEPT_INVLPG) |
				(1ULL << INTERCEPT_INVLPGA) |
				(1ULL << INTERCEPT_IOIO_PROT) |
				(1ULL << INTERCEPT_MSR_PROT) |
				(1ULL << INTERCEPT_TASK_SWITCH) |
				(1ULL << INTERCEPT_SHUTDOWN) |
				(1ULL << INTERCEPT_VMRUN) |
				(1ULL << INTERCEPT_VMMCALL) |
				(1ULL << INTERCEPT_VMLOAD) |
				(1ULL << INTERCEPT_VMSAVE) |
				(1ULL << INTERCEPT_STGI) |
				(1ULL << INTERCEPT_CLGI) |
				(1ULL << INTERCEPT_SKINIT) |
				(1ULL << INTERCEPT_WBINVD) |
				(1ULL << INTERCEPT_MONITOR) |
				(1ULL << INTERCEPT_MWAIT);

	control->iopm_base_pa = iopm_base;
	control->msrpm_base_pa = kvm_va2pa((caddr_t)svm->msrpm);
	control->tsc_offset = 0;
	control->int_ctl = V_INTR_MASKING_MASK;

	init_seg(&save->es);
	init_seg(&save->ss);
	init_seg(&save->ds);
	init_seg(&save->fs);
	init_seg(&save->gs);

	save->cs.selector = 0xf000;
	/* Executable/Readable Code Segment */
	save->cs.attrib = SVM_SELECTOR_READ_MASK | SVM_SELECTOR_P_MASK |
		SVM_SELECTOR_S_MASK | SVM_SELECTOR_CODE_MASK;
	save->cs.limit = 0xffff;
	/*
	 * cs.base should really be 0xffff0000, but vmx can't handle that, so
	 * be consistent with it.
	 *
	 * Replace when we have real mode working for vmx.
	 */
	save->cs.base = 0xf0000;

	save->gdtr.limit = 0xffff;
	save->idtr.limit = 0xffff;

	init_sys_seg(&save->ldtr, SEG_TYPE_LDT);
	init_sys_seg(&save->tr, SEG_TYPE_BUSY_TSS16);

	save->efer = EFER_SVME;
	save->dr6 = 0xffff0ff0;
	save->dr7 = 0x400;
	save->rflags = 2;
	save->rip = 0x0000fff0;
	svm->vcpu.arch.regs[VCPU_REGS_RIP] = save->rip;

	/* This is the guest-visible cr0 value.
	 * svm_set_cr0() sets PG and WP and clears NW and CD on save->cr0.
	 */
	svm->vcpu.arch.cr0 = X86_CR0_NW | X86_CR0_CD | X86_CR0_ET;
	kvm_set_cr0(&svm->vcpu, svm->vcpu.arch.cr0);

	save->cr4 = X86_CR4_PAE;
	/* rdx = ?? */

	if (npt_enabled) {
		/* Setup VMCB for Nested Paging */
		control->nested_ctl = 1;
		control->intercept &= ~((1ULL << INTERCEPT_TASK_SWITCH) |
					(1ULL << INTERCEPT_INVLPG));
		control->intercept_exceptions &= ~(1 << PF_VECTOR);
		control->intercept_cr_read &= ~INTERCEPT_CR3_MASK;
		control->intercept_cr_write &= ~INTERCEPT_CR3_MASK;
		save->g_pat = 0x0007040600070406ULL;
		save->cr3 = 0;
		save->cr4 = 0;
	}
	force_new_asid(&svm->vcpu);

	svm->vcpu.arch.hflags = 0;

	if (svm_has(SVM_FEATURE_PAUSE_FILTER)) {
		control->pause_filter_count = 3000;
		control->intercept |= (1ULL << INTERCEPT_PAUSE);
	}

	enable_gif(svm);
}

static int
svm_vcpu_reset(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	init_vmcb(svm);

	if (!kvm_vcpu_is_bsp(vcpu)) {
		kvm_rip_write(vcpu, 0);
		svm->vmcb->save.cs.base = svm->vcpu.arch.sipi_vector << 12;
		svm->vmcb->save.cs.selector = svm->vcpu.arch.sipi_vector << 8;
	}
	vcpu->arch.regs_avail = ~0;
	vcpu->arch.regs_dirty = ~0;

	return (0);
}

static struct kvm_vcpu *
svm_create_vcpu(struct kvm *kvm, unsigned int id)
{
	struct vcpu_svm *svm;
#if 0
	struct page *hsave_page;
	struct page *nested_msrpm_pages;
#endif
	int err;

	svm = kmem_cache_alloc(kvm_svm_vcpu_cache, KM_SLEEP);
	if (!svm) {
		return (NULL);
	}

	err = kvm_vcpu_init(&svm->vcpu, kvm, id);
	if (err) {
		kmem_cache_free(kvm_svm_vcpu_cache, svm);
		return (NULL);
	}

	/* VMCBs need to be aligned on 4k boundaries */
	svm->vmcb = kmem_cache_alloc(kvm_svm_vmcb_cache, KM_SLEEP);
	if (!svm->vmcb) {
		kvm_vcpu_uninit(&svm->vcpu);
		kmem_cache_free(kvm_svm_vcpu_cache, svm);
		return (NULL);
	}
	svm->vmcb_pa = kvm_va2pa((caddr_t)svm->vmcb);

	svm->msrpm = kmem_cache_alloc(kvm_svm_msrpm_cache, KM_SLEEP);
	if (!svm->msrpm) {
		kmem_cache_free(kvm_svm_vmcb_cache, svm->vmcb);
		kvm_vcpu_uninit(&svm->vcpu);
		kmem_cache_free(kvm_svm_vcpu_cache, svm);
		return (NULL);
	}

	svm_vcpu_init_msrpm(svm->msrpm);

	svm->asid_generation = 0;
	init_vmcb(svm);

	fx_init(&svm->vcpu);
	svm->vcpu.arch.apic_base = 0xfee00000 | MSR_IA32_APICBASE_ENABLE;
	if (kvm_vcpu_is_bsp(&svm->vcpu))
		svm->vcpu.arch.apic_base |= MSR_IA32_APICBASE_BSP;

	return (&svm->vcpu);
}

static void
svm_free_vcpu(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	kmem_cache_free(kvm_svm_vmcb_cache, svm->vmcb);
	kmem_cache_free(kvm_svm_msrpm_cache, svm->msrpm);

	kvm_vcpu_uninit(vcpu);
	kmem_cache_free(kvm_svm_vcpu_cache, svm);
}

static void
svm_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	int i;
	uint64_t tsc_this, delta, new_offset;

	if (cpu != vcpu->cpu) {
		vcpu->cpu = cpu;
		/* kvm_migrate_timers(vcpu); */
		svm->asid_generation = 0;

		/* XXX per-cpu TSS/GDT/IDT/GSBASE ? */

		/*
		 * Make sure the time stamp counter is monotonic.
		 */
		rdtscll(tsc_this);
		if (tsc_this < vcpu->arch.host_tsc) {
			delta = vcpu->arch.host_tsc - tsc_this;
			svm->vmcb->control.tsc_offset += delta;
		}
	}

	for (i = 0; i < NR_HOST_SAVE_USER_MSRS; i++) {
		rdmsrl(host_save_user_msrs[i], svm->host_user_msrs[i]);
	}
}

static void
svm_vcpu_put(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	int i;

	/* XXX: Where are the stats?
	    ++vcpu->stat.host_state_reload; */
	for (i = 0; i < NR_HOST_SAVE_USER_MSRS; i++) {
		wrmsrl(host_save_user_msrs[i], svm->host_user_msrs[i]);
	}

	rdtscll(vcpu->arch.host_tsc);
}

static unsigned long
svm_get_rflags(struct kvm_vcpu *vcpu)
{
	return (to_svm(vcpu)->vmcb->save.rflags);
}

static void
svm_set_rflags(struct kvm_vcpu *vcpu, unsigned long rflags)
{
	to_svm(vcpu)->vmcb->save.rflags = rflags;
}

static void
svm_cache_reg(struct kvm_vcpu *vcpu, enum kvm_reg reg)
{
	switch (reg) {
	case VCPU_EXREG_PDPTR:
		if (!npt_enabled)
			cmn_err(CE_PANIC, "had !npt_enabled in svm_cache_reg()\n");
		load_pdptrs(vcpu, vcpu->arch.cr3);
		break;
	default:
		cmn_err(CE_PANIC, "fell through switch in svm_cache_reg()\n");
	}
}

static void
svm_set_vintr(struct vcpu_svm *svm)
{
	svm->vmcb->control.intercept |= 1ULL << INTERCEPT_VINTR;
}

static void
svm_clear_vintr(struct vcpu_svm *svm)
{
	svm->vmcb->control.intercept &= ~(1ULL << INTERCEPT_VINTR);
}

static struct
vmcb_seg *svm_seg(struct kvm_vcpu *vcpu, int seg)
{
	struct vmcb_save_area *save = &to_svm(vcpu)->vmcb->save;

	switch (seg) {
	case VCPU_SREG_CS: return (&save->cs);
	case VCPU_SREG_DS: return (&save->ds);
	case VCPU_SREG_ES: return (&save->es);
	case VCPU_SREG_FS: return (&save->fs);
	case VCPU_SREG_GS: return (&save->gs);
	case VCPU_SREG_SS: return (&save->ss);
	case VCPU_SREG_TR: return (&save->tr);
	case VCPU_SREG_LDTR: return (&save->ldtr);
	}
	cmn_err(CE_PANIC, "fell through switch in svm_seg()\n");
	return (NULL);
}

static uint64_t
svm_get_segment_base(struct kvm_vcpu *vcpu, int seg)
{
	struct vmcb_seg *s = svm_seg(vcpu, seg);

	return (s->base);
}

static void
svm_get_segment(struct kvm_vcpu *vcpu, struct kvm_segment *var, int seg)
{
	struct vmcb_seg *s = svm_seg(vcpu, seg);

	var->base = s->base;
	var->limit = s->limit;
	var->selector = s->selector;
	var->type = s->attrib & SVM_SELECTOR_TYPE_MASK;
	var->s = (s->attrib >> SVM_SELECTOR_S_SHIFT) & 1;
	var->dpl = (s->attrib >> SVM_SELECTOR_DPL_SHIFT) & 3;
	var->present = (s->attrib >> SVM_SELECTOR_P_SHIFT) & 1;
	var->avl = (s->attrib >> SVM_SELECTOR_AVL_SHIFT) & 1;
	var->l = (s->attrib >> SVM_SELECTOR_L_SHIFT) & 1;
	var->db = (s->attrib >> SVM_SELECTOR_DB_SHIFT) & 1;
	var->g = (s->attrib >> SVM_SELECTOR_G_SHIFT) & 1;

	/* AMD's VMCB does not have an explicit unusable field, so emulate it
	 * for cross vendor migration purposes by "not present"
	 */
	var->unusable = !var->present || (var->type == 0);

	switch (seg) {
	case VCPU_SREG_CS:
		/*
		 * SVM always stores 0 for the 'G' bit in the CS selector in
		 * the VMCB on a VMEXIT. This hurts cross-vendor migration:
		 * Intel's VMENTRY has a check on the 'G' bit.
		 */
		var->g = s->limit > 0xfffff;
		break;
	case VCPU_SREG_TR:
		/*
		 * Work around a bug where the busy flag in the tr selector
		 * isn't exposed
		 */
		var->type |= 0x2;
		break;
	case VCPU_SREG_DS:
	case VCPU_SREG_ES:
	case VCPU_SREG_FS:
	case VCPU_SREG_GS:
		/*
		 * The accessed bit must always be set in the segment
		 * descriptor cache, although it can be cleared in the
		 * descriptor, the cached bit always remains at 1. Since
		 * Intel has a check on this, set it here to support
		 * cross-vendor migration.
		 */
		if (!var->unusable)
			var->type |= 0x1;
		break;
	case VCPU_SREG_SS:
		/* On AMD CPUs sometimes the DB bit in the segment
		 * descriptor is left as 1, although the whole segment has
		 * been made unusable. Clear it here to pass an Intel VMX
		 * entry check when cross vendor migrating.
		 */
		if (var->unusable)
			var->db = 0;
		break;
	}
}

static int
svm_get_cpl(struct kvm_vcpu *vcpu)
{
	struct vmcb_save_area *save = &to_svm(vcpu)->vmcb->save;

	return (save->cpl);
}

static void
svm_get_idt(struct kvm_vcpu *vcpu, struct descriptor_table *dt)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	dt->limit = svm->vmcb->save.idtr.limit;
	dt->base = svm->vmcb->save.idtr.base;
}

static void
svm_set_idt(struct kvm_vcpu *vcpu, struct descriptor_table *dt)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	svm->vmcb->save.idtr.limit = dt->limit;
	svm->vmcb->save.idtr.base = dt->base ;
}

static void
svm_get_gdt(struct kvm_vcpu *vcpu, struct descriptor_table *dt)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	dt->limit = svm->vmcb->save.gdtr.limit;
	dt->base = svm->vmcb->save.gdtr.base;
}

static void
svm_set_gdt(struct kvm_vcpu *vcpu, struct descriptor_table *dt)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	svm->vmcb->save.gdtr.limit = dt->limit;
	svm->vmcb->save.gdtr.base = dt->base ;
}

static void
svm_decache_cr0_guest_bits(struct kvm_vcpu *vcpu)
{
}

static void
svm_decache_cr4_guest_bits(struct kvm_vcpu *vcpu)
{
}

static void
update_cr0_intercept(struct vcpu_svm *svm)
{
	ulong gcr0 = svm->vcpu.arch.cr0;
	uint64_t *hcr0 = &svm->vmcb->save.cr0;

	if (!svm->vcpu.fpu_active)
		*hcr0 |= SVM_CR0_SELECTIVE_MASK;
	else
		*hcr0 = (*hcr0 & ~SVM_CR0_SELECTIVE_MASK)
			| (gcr0 & SVM_CR0_SELECTIVE_MASK);


	if (gcr0 == *hcr0 && svm->vcpu.fpu_active) {
		svm->vmcb->control.intercept_cr_read &= ~INTERCEPT_CR0_MASK;
		svm->vmcb->control.intercept_cr_write &= ~INTERCEPT_CR0_MASK;
	} else {
		svm->vmcb->control.intercept_cr_read |= INTERCEPT_CR0_MASK;
		svm->vmcb->control.intercept_cr_write |= INTERCEPT_CR0_MASK;
	}
}

static void
svm_set_cr0(struct kvm_vcpu *vcpu, unsigned long cr0)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	if (vcpu->arch.efer & EFER_LME) {
		if (!is_paging(vcpu) && (cr0 & X86_CR0_PG)) {
			vcpu->arch.efer |= EFER_LMA;
			svm->vmcb->save.efer |= EFER_LMA | EFER_LME;
		}

		if (is_paging(vcpu) && !(cr0 & X86_CR0_PG)) {
			vcpu->arch.efer &= ~EFER_LMA;
			svm->vmcb->save.efer &= ~(EFER_LMA | EFER_LME);
		}
	}
	vcpu->arch.cr0 = cr0;

	if (!npt_enabled)
		cr0 |= X86_CR0_PG | X86_CR0_WP;

	if (!vcpu->fpu_active)
		cr0 |= X86_CR0_TS;
	/*
	 * re-enable caching here because the QEMU bios
	 * does not do it - this results in some delay at
	 * reboot
	 */
	cr0 &= ~(X86_CR0_CD | X86_CR0_NW);
	svm->vmcb->save.cr0 = cr0;
	update_cr0_intercept(svm);
}

static void
svm_set_cr4(struct kvm_vcpu *vcpu, unsigned long cr4)
{
	unsigned long host_cr4_mce = read_cr4() & X86_CR4_MCE;
	unsigned long old_cr4 = to_svm(vcpu)->vmcb->save.cr4;

	if (npt_enabled && ((old_cr4 ^ cr4) & X86_CR4_PGE))
		force_new_asid(vcpu);

	vcpu->arch.cr4 = cr4;
	if (!npt_enabled)
		cr4 |= X86_CR4_PAE;
	cr4 |= host_cr4_mce;
	to_svm(vcpu)->vmcb->save.cr4 = cr4;
}

static void
svm_set_segment(struct kvm_vcpu *vcpu, struct kvm_segment *var, int seg)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	struct vmcb_seg *s = svm_seg(vcpu, seg);

	s->base = var->base;
	s->limit = var->limit;
	s->selector = var->selector;
	if (var->unusable)
		s->attrib = 0;
	else {
		s->attrib = (var->type & SVM_SELECTOR_TYPE_MASK);
		s->attrib |= (var->s & 1) << SVM_SELECTOR_S_SHIFT;
		s->attrib |= (var->dpl & 3) << SVM_SELECTOR_DPL_SHIFT;
		s->attrib |= (var->present & 1) << SVM_SELECTOR_P_SHIFT;
		s->attrib |= (var->avl & 1) << SVM_SELECTOR_AVL_SHIFT;
		s->attrib |= (var->l & 1) << SVM_SELECTOR_L_SHIFT;
		s->attrib |= (var->db & 1) << SVM_SELECTOR_DB_SHIFT;
		s->attrib |= (var->g & 1) << SVM_SELECTOR_G_SHIFT;
	}
	if (seg == VCPU_SREG_CS)
		svm->vmcb->save.cpl
			= (svm->vmcb->save.cs.attrib
			   >> SVM_SELECTOR_DPL_SHIFT) & 3;

}

static void
update_db_intercept(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	svm->vmcb->control.intercept_exceptions &=
		~((1 << DB_VECTOR) | (1 << BP_VECTOR));

	if (svm->nmi_singlestep)
		svm->vmcb->control.intercept_exceptions |= (1 << DB_VECTOR);

	if (vcpu->guest_debug & KVM_GUESTDBG_ENABLE) {
		if (vcpu->guest_debug &
		    (KVM_GUESTDBG_SINGLESTEP | KVM_GUESTDBG_USE_HW_BP))
			svm->vmcb->control.intercept_exceptions |=
				1 << DB_VECTOR;
		if (vcpu->guest_debug & KVM_GUESTDBG_USE_SW_BP)
			svm->vmcb->control.intercept_exceptions |=
				1 << BP_VECTOR;
	} else
		vcpu->guest_debug = 0;
}

static void
svm_guest_debug(struct kvm_vcpu *vcpu, struct kvm_guest_debug *dbg)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	if (vcpu->guest_debug & KVM_GUESTDBG_USE_HW_BP)
		svm->vmcb->save.dr7 = dbg->arch.debugreg[7];
	else
		svm->vmcb->save.dr7 = vcpu->arch.dr7;

	update_db_intercept(vcpu);
}

static void
load_host_msrs(struct kvm_vcpu *vcpu)
{
	wrmsrl(MSR_GS_BASE, to_svm(vcpu)->host_gs_base);
}

static void
save_host_msrs(struct kvm_vcpu *vcpu)
{
	rdmsrl(MSR_GS_BASE, to_svm(vcpu)->host_gs_base);
}

static void
new_asid(struct vcpu_svm *svm, struct svm_cpu_data *sd)
{
	/* XXX do we need some kind of locking here? */

	if (sd->next_asid > sd->max_asid) {
		++sd->asid_generation;
		sd->next_asid = 1;
		svm->vmcb->control.tlb_ctl = TLB_CONTROL_FLUSH_ALL_ASID;
	}

	svm->asid_generation = sd->asid_generation;
	svm->vmcb->control.asid = sd->next_asid++;
}

static int
svm_get_dr(struct kvm_vcpu *vcpu, int dr, unsigned long *dest)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	switch (dr) {
	case 0 ... 3:
		*dest = vcpu->arch.db[dr];
		break;
	case 4:
		if (kvm_read_cr4_bits(vcpu, X86_CR4_DE))
			return (EMULATE_FAIL); /* will re-inject UD */
		/* fall through */
	case 6:
		if (vcpu->guest_debug & KVM_GUESTDBG_USE_HW_BP)
			*dest = vcpu->arch.dr6;
		else
			*dest = svm->vmcb->save.dr6;
		break;
	case 5:
		if (kvm_read_cr4_bits(vcpu, X86_CR4_DE))
			return (EMULATE_FAIL); /* will re-inject UD */
		/* fall through */
	case 7:
		if (vcpu->guest_debug & KVM_GUESTDBG_USE_HW_BP)
			*dest = vcpu->arch.dr7;
		else
			*dest = svm->vmcb->save.dr7;
		break;
	}

	return (EMULATE_DONE);
}

static int
svm_set_dr(struct kvm_vcpu *vcpu, int dr, unsigned long value)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	switch (dr) {
	case 0 ... 3:
		vcpu->arch.db[dr] = value;
		if (!(vcpu->guest_debug & KVM_GUESTDBG_USE_HW_BP))
			vcpu->arch.eff_db[dr] = value;
		break;
	case 4:
		if (kvm_read_cr4_bits(vcpu, X86_CR4_DE))
			return (EMULATE_FAIL); /* will re-inject UD */
		/* fall through */
	case 6:
		vcpu->arch.dr6 = (value & DR6_VOLATILE) | DR6_FIXED_1;
		break;
	case 5:
		if (kvm_read_cr4_bits(vcpu, X86_CR4_DE))
			return (EMULATE_FAIL); /* will re-inject UD */
		/* fall through */
	case 7:
		vcpu->arch.dr7 = (value & DR7_VOLATILE) | DR7_FIXED_1;
		if (!(vcpu->guest_debug & KVM_GUESTDBG_USE_HW_BP)) {
			svm->vmcb->save.dr7 = vcpu->arch.dr7;
			vcpu->arch.switch_db_regs = (value & DR7_BP_EN_MASK);
		}
		break;
	}

	return (EMULATE_DONE);
}

static int
pf_interception(struct vcpu_svm *svm)
{
	uint64_t fault_address;
	uint32_t error_code;

	fault_address  = svm->vmcb->control.exit_info_2;
	error_code = svm->vmcb->control.exit_info_1;

	KVM_TRACE2(page__fault, uintptr_t, fault_address,
	    uint32_t, error_code);

	if (!npt_enabled && kvm_event_needs_reinjection(&svm->vcpu))
		kvm_mmu_unprotect_page_virt(&svm->vcpu, fault_address);
	return (kvm_mmu_page_fault(&svm->vcpu, fault_address, error_code));
}

static int
db_interception(struct vcpu_svm *svm)
{
	struct kvm_run *kvm_run = svm->vcpu.run;

	if (!(svm->vcpu.guest_debug &
	      (KVM_GUESTDBG_SINGLESTEP | KVM_GUESTDBG_USE_HW_BP)) &&
		!svm->nmi_singlestep) {
		kvm_queue_exception(&svm->vcpu, DB_VECTOR);
		return (1);
	}

	if (svm->nmi_singlestep) {
		svm->nmi_singlestep = 0;
		if (!(svm->vcpu.guest_debug & KVM_GUESTDBG_SINGLESTEP))
			svm->vmcb->save.rflags &=
				~(X86_EFLAGS_TF | X86_EFLAGS_RF);
		update_db_intercept(&svm->vcpu);
	}

	if (svm->vcpu.guest_debug &
	    (KVM_GUESTDBG_SINGLESTEP | KVM_GUESTDBG_USE_HW_BP)){
		kvm_run->exit_reason = KVM_EXIT_DEBUG;
		kvm_run->debug.arch.pc =
			svm->vmcb->save.cs.base + svm->vmcb->save.rip;
		kvm_run->debug.arch.exception = DB_VECTOR;
		return (0);
	}

	return (1);
}

static int
bp_interception(struct vcpu_svm *svm)
{
	struct kvm_run *kvm_run = svm->vcpu.run;

	kvm_run->exit_reason = KVM_EXIT_DEBUG;
	kvm_run->debug.arch.pc = svm->vmcb->save.cs.base + svm->vmcb->save.rip;
	kvm_run->debug.arch.exception = BP_VECTOR;
	return (0);
}

static int
ud_interception(struct vcpu_svm *svm)
{
	int er;

	er = emulate_instruction(&svm->vcpu, 0, 0, EMULTYPE_TRAP_UD);
	if (er != EMULATE_DONE)
		kvm_queue_exception(&svm->vcpu, UD_VECTOR);
	return (1);
}

static void
svm_fpu_activate(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	svm->vmcb->control.intercept_exceptions &= ~(1 << NM_VECTOR);
	svm->vcpu.fpu_active = 1;
	update_cr0_intercept(svm);
}

static int
nm_interception(struct vcpu_svm *svm)
{
	svm_fpu_activate(&svm->vcpu);
	return (1);
}

static int
mc_interception(struct vcpu_svm *svm)
{
	/*
	 * On an #MC intercept the MCE handler is not called automatically in
	 * the host. So do it by hand here.
	 */
	__asm__ volatile (
		"int $0x12\n");
	/* not sure if we ever come back to this point */

	return (1);
}

static int
shutdown_interception(struct vcpu_svm *svm)
{
	struct kvm_run *kvm_run = svm->vcpu.run;

	/*
	 * VMCB is undefined after a SHUTDOWN intercept
	 * so reinitialize it.
	 */
	bzero(svm->vmcb, sizeof (struct vmcb));
	init_vmcb(svm);

	kvm_run->exit_reason = KVM_EXIT_SHUTDOWN;
	return (0);
}

static int
io_interception(struct vcpu_svm *svm)
{
	uint32_t io_info = svm->vmcb->control.exit_info_1; /* address size bug? */
	int size, in, string;
	unsigned port;

	/* XXX: where are the stats?
	    ++svm->vcpu.stat.io_exits; */

	svm->next_rip = svm->vmcb->control.exit_info_2;

	string = (io_info & SVM_IOIO_STR_MASK) != 0;

	if (string) {
		if (emulate_instruction(&svm->vcpu,
					0, 0, 0) == EMULATE_DO_MMIO)
			return (0);
		return (1);
	}

	in = (io_info & SVM_IOIO_TYPE_MASK) != 0;
	port = io_info >> 16;
	size = (io_info & SVM_IOIO_SIZE_MASK) >> SVM_IOIO_SIZE_SHIFT;

	skip_emulated_instruction(&svm->vcpu);
	return (kvm_emulate_pio(&svm->vcpu, in, size, port));
}

static int
nmi_interception(struct vcpu_svm *svm)
{
	return (1);
}

static int
intr_interception(struct vcpu_svm *svm)
{
	/* XXX: stats
	    ++svm->vcpu.stat.irq_exits; */
	return (1);
}

static int
nop_on_interception(struct vcpu_svm *svm)
{
	return (1);
}

static int
halt_interception(struct vcpu_svm *svm)
{
	svm->next_rip = kvm_rip_read(&svm->vcpu) + 1;
	skip_emulated_instruction(&svm->vcpu);
	return (kvm_emulate_halt(&svm->vcpu));
}

static int
vmmcall_interception(struct vcpu_svm *svm)
{
	svm->next_rip = kvm_rip_read(&svm->vcpu) + 3;
	skip_emulated_instruction(&svm->vcpu);
	kvm_emulate_hypercall(&svm->vcpu);
	return (1);
}

static int
nested_svm_check_permissions(struct vcpu_svm *svm)
{
	kvm_queue_exception(&svm->vcpu, UD_VECTOR);
	return (1);
}

static void
copy_vmcb_control_area(struct vmcb *dst_vmcb, struct vmcb *from_vmcb)
{
	struct vmcb_control_area *dst  = &dst_vmcb->control;
	struct vmcb_control_area *from = &from_vmcb->control;

	dst->intercept_cr_read    = from->intercept_cr_read;
	dst->intercept_cr_write   = from->intercept_cr_write;
	dst->intercept_dr_read    = from->intercept_dr_read;
	dst->intercept_dr_write   = from->intercept_dr_write;
	dst->intercept_exceptions = from->intercept_exceptions;
	dst->intercept            = from->intercept;
	dst->iopm_base_pa         = from->iopm_base_pa;
	dst->msrpm_base_pa        = from->msrpm_base_pa;
	dst->tsc_offset           = from->tsc_offset;
	dst->asid                 = from->asid;
	dst->tlb_ctl              = from->tlb_ctl;
	dst->int_ctl              = from->int_ctl;
	dst->int_vector           = from->int_vector;
	dst->int_state            = from->int_state;
	dst->exit_code            = from->exit_code;
	dst->exit_code_hi         = from->exit_code_hi;
	dst->exit_info_1          = from->exit_info_1;
	dst->exit_info_2          = from->exit_info_2;
	dst->exit_int_info        = from->exit_int_info;
	dst->exit_int_info_err    = from->exit_int_info_err;
	dst->nested_ctl           = from->nested_ctl;
	dst->event_inj            = from->event_inj;
	dst->event_inj_err        = from->event_inj_err;
	dst->nested_cr3           = from->nested_cr3;
	dst->lbr_ctl              = from->lbr_ctl;
}

static void
nested_svm_vmloadsave(struct vmcb *from_vmcb, struct vmcb *to_vmcb)
{
	to_vmcb->save.fs = from_vmcb->save.fs;
	to_vmcb->save.gs = from_vmcb->save.gs;
	to_vmcb->save.tr = from_vmcb->save.tr;
	to_vmcb->save.ldtr = from_vmcb->save.ldtr;
	to_vmcb->save.kernel_gs_base = from_vmcb->save.kernel_gs_base;
	to_vmcb->save.star = from_vmcb->save.star;
	to_vmcb->save.lstar = from_vmcb->save.lstar;
	to_vmcb->save.cstar = from_vmcb->save.cstar;
	to_vmcb->save.sfmask = from_vmcb->save.sfmask;
	to_vmcb->save.sysenter_cs = from_vmcb->save.sysenter_cs;
	to_vmcb->save.sysenter_esp = from_vmcb->save.sysenter_esp;
	to_vmcb->save.sysenter_eip = from_vmcb->save.sysenter_eip;
}

static int
vmload_interception(struct vcpu_svm *svm)
{
	struct vmcb *nested_vmcb;

	if (nested_svm_check_permissions(svm))
		return (1);

	svm->next_rip = kvm_rip_read(&svm->vcpu) + 3;
	skip_emulated_instruction(&svm->vcpu);

	return (1);
}

static int
vmsave_interception(struct vcpu_svm *svm)
{
	struct vmcb *nested_vmcb;

	if (nested_svm_check_permissions(svm))
		return (1);

	svm->next_rip = kvm_rip_read(&svm->vcpu) + 3;
	skip_emulated_instruction(&svm->vcpu);

	return (1);
}

static int
vmrun_interception(struct vcpu_svm *svm)
{
	nested_svm_check_permissions(svm);
	return (1);
}

static int
stgi_interception(struct vcpu_svm *svm)
{
	if (nested_svm_check_permissions(svm))
		return (1);

	svm->next_rip = kvm_rip_read(&svm->vcpu) + 3;
	skip_emulated_instruction(&svm->vcpu);

	enable_gif(svm);

	return (1);
}

static int
clgi_interception(struct vcpu_svm *svm)
{
	if (nested_svm_check_permissions(svm))
		return (1);

	svm->next_rip = kvm_rip_read(&svm->vcpu) + 3;
	skip_emulated_instruction(&svm->vcpu);

	disable_gif(svm);

	/* After a CLGI no interrupts should come */
	svm_clear_vintr(svm);
	svm->vmcb->control.int_ctl &= ~V_IRQ_MASK;

	return (1);
}

static int
invlpga_interception(struct vcpu_svm *svm)
{
	struct kvm_vcpu *vcpu = &svm->vcpu;

	KVM_TRACE3(svm__invlpga, uint64_t, svm->vmcb->save.rip,
	    uint64_t, vcpu->arch.regs[VCPU_REGS_RCX],
	    uint64_t, vcpu->arch.regs[VCPU_REGS_RAX]);

	/* Let's treat INVLPGA the same as INVLPG (can be optimized!) */
	kvm_mmu_invlpg(vcpu, vcpu->arch.regs[VCPU_REGS_RAX]);

	svm->next_rip = kvm_rip_read(&svm->vcpu) + 3;
	skip_emulated_instruction(&svm->vcpu);
	return (1);
}

static int
skinit_interception(struct vcpu_svm *svm)
{
	KVM_TRACE2(svm__skinit, uint64_t, svm->vmcb->save.rip,
	    uint64_t, svm->vcpu.arch.regs[VCPU_REGS_RAX]);

	kvm_queue_exception(&svm->vcpu, UD_VECTOR);
	return (1);
}

static int
invalid_op_interception(struct vcpu_svm *svm)
{
	kvm_queue_exception(&svm->vcpu, UD_VECTOR);
	return (1);
}

static int
task_switch_interception(struct vcpu_svm *svm)
{
	uint16_t tss_selector;
	int reason;
	int int_type = svm->vmcb->control.exit_int_info &
		SVM_EXITINTINFO_TYPE_MASK;
	int int_vec = svm->vmcb->control.exit_int_info & SVM_EVTINJ_VEC_MASK;
	uint32_t type =
		svm->vmcb->control.exit_int_info & SVM_EXITINTINFO_TYPE_MASK;
	uint32_t idt_v =
		svm->vmcb->control.exit_int_info & SVM_EXITINTINFO_VALID;

	tss_selector = (uint16_t)svm->vmcb->control.exit_info_1;

	if (svm->vmcb->control.exit_info_2 &
	    (1ULL << SVM_EXITINFOSHIFT_TS_REASON_IRET))
		reason = TASK_SWITCH_IRET;
	else if (svm->vmcb->control.exit_info_2 &
		 (1ULL << SVM_EXITINFOSHIFT_TS_REASON_JMP))
		reason = TASK_SWITCH_JMP;
	else if (idt_v)
		reason = TASK_SWITCH_GATE;
	else
		reason = TASK_SWITCH_CALL;

	if (reason == TASK_SWITCH_GATE) {
		switch (type) {
		case SVM_EXITINTINFO_TYPE_NMI:
			svm->vcpu.arch.nmi_injected = 0;
			break;
		case SVM_EXITINTINFO_TYPE_EXEPT:
			kvm_clear_exception_queue(&svm->vcpu);
			break;
		case SVM_EXITINTINFO_TYPE_INTR:
			kvm_clear_interrupt_queue(&svm->vcpu);
			break;
		default:
			break;
		}
	}

	if (reason != TASK_SWITCH_GATE ||
	    int_type == SVM_EXITINTINFO_TYPE_SOFT ||
	    (int_type == SVM_EXITINTINFO_TYPE_EXEPT &&
	     (int_vec == OF_VECTOR || int_vec == BP_VECTOR)))
		skip_emulated_instruction(&svm->vcpu);

	return (kvm_task_switch(&svm->vcpu, tss_selector, reason));
}

static int
cpuid_interception(struct vcpu_svm *svm)
{
	svm->next_rip = kvm_rip_read(&svm->vcpu) + 2;
	kvm_emulate_cpuid(&svm->vcpu);
	return (1);
}

static int
iret_interception(struct vcpu_svm *svm)
{
	/* XXX: stats
	    ++svm->vcpu.stat.nmi_window_exits; */
	svm->vmcb->control.intercept &= ~(1ULL << INTERCEPT_IRET);
	svm->vcpu.arch.hflags |= HF_IRET_MASK;
	return (1);
}

static int
invlpg_interception(struct vcpu_svm *svm)
{
	if (emulate_instruction(&svm->vcpu, 0, 0, 0) != EMULATE_DONE)
		cmn_err(CE_WARN, "%s: failed\n", __func__);
	return (1);
}

static int emulate_on_interception(struct vcpu_svm *svm)
{
	if (emulate_instruction(&svm->vcpu, 0, 0, 0) != EMULATE_DONE)
		cmn_err(CE_WARN, "%s: failed\n", __func__);
	return (1);
}

static int
cr8_write_interception(struct vcpu_svm *svm)
{
	struct kvm_run *kvm_run = svm->vcpu.run;

	uint8_t cr8_prev = kvm_get_cr8(&svm->vcpu);
	/* instruction emulation calls kvm_set_cr8() */
	emulate_instruction(&svm->vcpu, 0, 0, 0);
	if (irqchip_in_kernel(svm->vcpu.kvm)) {
		svm->vmcb->control.intercept_cr_write &= ~INTERCEPT_CR8_MASK;
		return (1);
	}
	if (cr8_prev <= kvm_get_cr8(&svm->vcpu))
		return (1);
	kvm_run->exit_reason = KVM_EXIT_SET_TPR;
	return (0);
}

static int
svm_get_msr(struct kvm_vcpu *vcpu, unsigned ecx, uint64_t *data)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	uint64_t tsc_this;

	switch (ecx) {
	case MSR_IA32_TSC: {
		uint64_t tsc_offset;

		tsc_offset = svm->vmcb->control.tsc_offset;

		rdtscll(tsc_this);
		*data = tsc_offset + tsc_this;
		break;
	}
	case MSR_K6_STAR:
		*data = svm->vmcb->save.star;
		break;
	case MSR_LSTAR:
		*data = svm->vmcb->save.lstar;
		break;
	case MSR_CSTAR:
		*data = svm->vmcb->save.cstar;
		break;
	case MSR_KERNEL_GS_BASE:
		*data = svm->vmcb->save.kernel_gs_base;
		break;
	case MSR_SYSCALL_MASK:
		*data = svm->vmcb->save.sfmask;
		break;
	case MSR_IA32_SYSENTER_CS:
		*data = svm->vmcb->save.sysenter_cs;
		break;
	case MSR_IA32_SYSENTER_EIP:
		*data = svm->sysenter_eip;
		break;
	case MSR_IA32_SYSENTER_ESP:
		*data = svm->sysenter_esp;
		break;
	/* Nobody will change the following 5 values in the VMCB so
	   we can safely return them on rdmsr. They will always be 0
	   until LBRV is implemented. */
	case MSR_IA32_DEBUGCTLMSR:
		*data = svm->vmcb->save.dbgctl;
		break;
	case MSR_IA32_LASTBRANCHFROMIP:
		*data = svm->vmcb->save.br_from;
		break;
	case MSR_IA32_LASTBRANCHTOIP:
		*data = svm->vmcb->save.br_to;
		break;
	case MSR_IA32_LASTINTFROMIP:
		*data = svm->vmcb->save.last_excp_from;
		break;
	case MSR_IA32_LASTINTTOIP:
		*data = svm->vmcb->save.last_excp_to;
		break;
	case MSR_VM_CR:
		*data = 0;
		break;
	case MSR_IA32_UCODE_REV:
		*data = 0x01000065;
		break;
	default:
		return (kvm_get_msr_common(vcpu, ecx, data));
	}
	return (0);
}

static int
rdmsr_interception(struct vcpu_svm *svm)
{
	uint32_t ecx = svm->vcpu.arch.regs[VCPU_REGS_RCX];
	uint64_t data;

	if (svm_get_msr(&svm->vcpu, ecx, &data)) {
		KVM_TRACE1(msr__read__ex, uint32_t, ecx);

		kvm_inject_gp(&svm->vcpu, 0);
	} else {
		KVM_TRACE2(msr__read, uint32_t, ecx, uint64_t, data);

		svm->vcpu.arch.regs[VCPU_REGS_RAX] = data & 0xffffffff;
		svm->vcpu.arch.regs[VCPU_REGS_RDX] = data >> 32;
		svm->next_rip = kvm_rip_read(&svm->vcpu) + 2;
		skip_emulated_instruction(&svm->vcpu);
	}
	return (1);
}

static int
svm_set_msr(struct kvm_vcpu *vcpu, unsigned ecx, uint64_t data)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	switch (ecx) {
	case MSR_IA32_TSC: {
		uint64_t tsc_this, tsc_offset;
		uint64_t g_tsc_offset = 0;
		rdtscll(tsc_this);
		tsc_offset = data - tsc_this;

		svm->vmcb->control.tsc_offset = tsc_offset + g_tsc_offset;

		break;
	}
	case MSR_K6_STAR:
		svm->vmcb->save.star = data;
		break;
	case MSR_LSTAR:
		svm->vmcb->save.lstar = data;
		break;
	case MSR_CSTAR:
		svm->vmcb->save.cstar = data;
		break;
	case MSR_KERNEL_GS_BASE:
		svm->vmcb->save.kernel_gs_base = data;
		break;
	case MSR_SYSCALL_MASK:
		svm->vmcb->save.sfmask = data;
		break;
	case MSR_IA32_SYSENTER_CS:
		svm->vmcb->save.sysenter_cs = data;
		break;
	case MSR_IA32_SYSENTER_EIP:
		svm->sysenter_eip = data;
		svm->vmcb->save.sysenter_eip = data;
		break;
	case MSR_IA32_SYSENTER_ESP:
		svm->sysenter_esp = data;
		svm->vmcb->save.sysenter_esp = data;
		break;
	case MSR_IA32_DEBUGCTLMSR:
		if (!svm_has(SVM_FEATURE_LBRV)) {
			cmn_err(CE_WARN,
			    "%s: MSR_IA32_DEBUGCTL 0x%llx, nop\n",
			    __func__, (long long unsigned)data);
			break;
		}
		if (data & DEBUGCTL_RESERVED_BITS)
			return (1);

		svm->vmcb->save.dbgctl = data;
		if (data & (1ULL<<0))
			svm_enable_lbrv(svm);
		else
			svm_disable_lbrv(svm);
		break;
	case MSR_VM_CR:
	case MSR_VM_IGNNE:
		cmn_err(CE_WARN, "unimplemented wrmsr: 0x%x data 0x%llx\n", ecx,
		    (long long unsigned)data);
		break;
	default:
		return (kvm_set_msr_common(vcpu, ecx, data));
	}
	return (0);
}

static int
wrmsr_interception(struct vcpu_svm *svm)
{
	uint32_t ecx = svm->vcpu.arch.regs[VCPU_REGS_RCX];
	uint64_t data = (svm->vcpu.arch.regs[VCPU_REGS_RAX] & -1u)
		| ((uint64_t)(svm->vcpu.arch.regs[VCPU_REGS_RDX] & -1u) << 32);

	svm->next_rip = kvm_rip_read(&svm->vcpu) + 2;
	if (svm_set_msr(&svm->vcpu, ecx, data)) {
		KVM_TRACE2(msr__write__ex, uint32_t, ecx, uint64_t, data);

		kvm_inject_gp(&svm->vcpu, 0);
	} else {
		KVM_TRACE2(msr__write, uint32_t, ecx, uint64_t, data);

		skip_emulated_instruction(&svm->vcpu);
	}
	return (1);
}

static int
msr_interception(struct vcpu_svm *svm)
{
	if (svm->vmcb->control.exit_info_1)
		return (wrmsr_interception(svm));
	else
		return (rdmsr_interception(svm));
}

static int
interrupt_window_interception(struct vcpu_svm *svm)
{
	struct kvm_run *kvm_run = svm->vcpu.run;

	svm_clear_vintr(svm);
	svm->vmcb->control.int_ctl &= ~V_IRQ_MASK;
	/*
	 * If the user space waits to inject interrupts, exit as soon as
	 * possible
	 */
	if (!irqchip_in_kernel(svm->vcpu.kvm) &&
	    kvm_run->request_interrupt_window &&
	    !kvm_cpu_has_interrupt(&svm->vcpu)) {
		/* XXX: stats
		    ++svm->vcpu.stat.irq_window_exits; */
		kvm_run->exit_reason = KVM_EXIT_IRQ_WINDOW_OPEN;
		return (0);
	}

	return (1);
}

static int
pause_interception(struct vcpu_svm *svm)
{
#ifdef XXX
	kvm_vcpu_on_spin(&(svm->vcpu));
#endif
	return (1);
}

static int (*svm_exit_handlers[])(struct vcpu_svm *svm) = {
	[SVM_EXIT_READ_CR0]           		= emulate_on_interception,
	[SVM_EXIT_READ_CR3]           		= emulate_on_interception,
	[SVM_EXIT_READ_CR4]           		= emulate_on_interception,
	[SVM_EXIT_READ_CR8]           		= emulate_on_interception,
	[SVM_EXIT_CR0_SEL_WRITE]		= emulate_on_interception,
	[SVM_EXIT_WRITE_CR0]          		= emulate_on_interception,
	[SVM_EXIT_WRITE_CR3]          		= emulate_on_interception,
	[SVM_EXIT_WRITE_CR4]          		= emulate_on_interception,
	[SVM_EXIT_WRITE_CR8]          		= cr8_write_interception,
	[SVM_EXIT_READ_DR0] 			= emulate_on_interception,
	[SVM_EXIT_READ_DR1]			= emulate_on_interception,
	[SVM_EXIT_READ_DR2]			= emulate_on_interception,
	[SVM_EXIT_READ_DR3]			= emulate_on_interception,
	[SVM_EXIT_READ_DR4]			= emulate_on_interception,
	[SVM_EXIT_READ_DR5]			= emulate_on_interception,
	[SVM_EXIT_READ_DR6]			= emulate_on_interception,
	[SVM_EXIT_READ_DR7]			= emulate_on_interception,
	[SVM_EXIT_WRITE_DR0]			= emulate_on_interception,
	[SVM_EXIT_WRITE_DR1]			= emulate_on_interception,
	[SVM_EXIT_WRITE_DR2]			= emulate_on_interception,
	[SVM_EXIT_WRITE_DR3]			= emulate_on_interception,
	[SVM_EXIT_WRITE_DR4]			= emulate_on_interception,
	[SVM_EXIT_WRITE_DR5]			= emulate_on_interception,
	[SVM_EXIT_WRITE_DR6]			= emulate_on_interception,
	[SVM_EXIT_WRITE_DR7]			= emulate_on_interception,
	[SVM_EXIT_EXCP_BASE + DB_VECTOR]	= db_interception,
	[SVM_EXIT_EXCP_BASE + BP_VECTOR]	= bp_interception,
	[SVM_EXIT_EXCP_BASE + UD_VECTOR]	= ud_interception,
	[SVM_EXIT_EXCP_BASE + PF_VECTOR] 	= pf_interception,
	[SVM_EXIT_EXCP_BASE + NM_VECTOR] 	= nm_interception,
	[SVM_EXIT_EXCP_BASE + MC_VECTOR] 	= mc_interception,
	[SVM_EXIT_INTR] 			= intr_interception,
	[SVM_EXIT_NMI]				= nmi_interception,
	[SVM_EXIT_SMI]				= nop_on_interception,
	[SVM_EXIT_INIT]				= nop_on_interception,
	[SVM_EXIT_VINTR]			= interrupt_window_interception,
	/* [SVM_EXIT_CR0_SEL_WRITE]		= emulate_on_interception, */
	[SVM_EXIT_CPUID]			= cpuid_interception,
	[SVM_EXIT_IRET]                         = iret_interception,
	[SVM_EXIT_INVD]                         = emulate_on_interception,
	[SVM_EXIT_PAUSE]			= pause_interception,
	[SVM_EXIT_HLT]				= halt_interception,
	[SVM_EXIT_INVLPG]			= invlpg_interception,
	[SVM_EXIT_INVLPGA]			= invlpga_interception,
	[SVM_EXIT_IOIO] 		  	= io_interception,
	[SVM_EXIT_MSR]				= msr_interception,
	[SVM_EXIT_TASK_SWITCH]			= task_switch_interception,
	[SVM_EXIT_SHUTDOWN]			= shutdown_interception,
	[SVM_EXIT_VMRUN]			= vmrun_interception,
	[SVM_EXIT_VMMCALL]			= vmmcall_interception,
	[SVM_EXIT_VMLOAD]			= vmload_interception,
	[SVM_EXIT_VMSAVE]			= vmsave_interception,
	[SVM_EXIT_STGI]				= stgi_interception,
	[SVM_EXIT_CLGI]				= clgi_interception,
	[SVM_EXIT_SKINIT]			= skinit_interception,
	[SVM_EXIT_WBINVD]                       = emulate_on_interception,
	[SVM_EXIT_MONITOR]			= invalid_op_interception,
	[SVM_EXIT_MWAIT]			= invalid_op_interception,
	[SVM_EXIT_NPF]				= pf_interception,
};

struct trace_print_flags {
        unsigned long           mask;
        const char              *name;
};

static const struct trace_print_flags svm_exit_reasons_str[] = {
	{ SVM_EXIT_READ_CR0,           		"read_cr0" },
	{ SVM_EXIT_READ_CR3,	      		"read_cr3" },
	{ SVM_EXIT_READ_CR4,	      		"read_cr4" },
	{ SVM_EXIT_READ_CR8,  	      		"read_cr8" },
	{ SVM_EXIT_WRITE_CR0,          		"write_cr0" },
	{ SVM_EXIT_WRITE_CR3,	      		"write_cr3" },
	{ SVM_EXIT_WRITE_CR4,          		"write_cr4" },
	{ SVM_EXIT_WRITE_CR8, 	      		"write_cr8" },
	{ SVM_EXIT_READ_DR0, 	      		"read_dr0" },
	{ SVM_EXIT_READ_DR1,	      		"read_dr1" },
	{ SVM_EXIT_READ_DR2,	      		"read_dr2" },
	{ SVM_EXIT_READ_DR3,	      		"read_dr3" },
	{ SVM_EXIT_WRITE_DR0,	      		"write_dr0" },
	{ SVM_EXIT_WRITE_DR1,	      		"write_dr1" },
	{ SVM_EXIT_WRITE_DR2,	      		"write_dr2" },
	{ SVM_EXIT_WRITE_DR3,	      		"write_dr3" },
	{ SVM_EXIT_WRITE_DR5,	      		"write_dr5" },
	{ SVM_EXIT_WRITE_DR7,	      		"write_dr7" },
	{ SVM_EXIT_EXCP_BASE + DB_VECTOR,	"DB excp" },
	{ SVM_EXIT_EXCP_BASE + BP_VECTOR,	"BP excp" },
	{ SVM_EXIT_EXCP_BASE + UD_VECTOR,	"UD excp" },
	{ SVM_EXIT_EXCP_BASE + PF_VECTOR,	"PF excp" },
	{ SVM_EXIT_EXCP_BASE + NM_VECTOR,	"NM excp" },
	{ SVM_EXIT_EXCP_BASE + MC_VECTOR,	"MC excp" },
	{ SVM_EXIT_INTR,			"interrupt" },
	{ SVM_EXIT_NMI,				"nmi" },
	{ SVM_EXIT_SMI,				"smi" },
	{ SVM_EXIT_INIT,			"init" },
	{ SVM_EXIT_VINTR,			"vintr" },
	{ SVM_EXIT_CPUID,			"cpuid" },
	{ SVM_EXIT_INVD,			"invd" },
	{ SVM_EXIT_HLT,				"hlt" },
	{ SVM_EXIT_INVLPG,			"invlpg" },
	{ SVM_EXIT_INVLPGA,			"invlpga" },
	{ SVM_EXIT_IOIO,			"io" },
	{ SVM_EXIT_MSR,				"msr" },
	{ SVM_EXIT_TASK_SWITCH,			"task_switch" },
	{ SVM_EXIT_SHUTDOWN,			"shutdown" },
	{ SVM_EXIT_VMRUN,			"vmrun" },
	{ SVM_EXIT_VMMCALL,			"hypercall" },
	{ SVM_EXIT_VMLOAD,			"vmload" },
	{ SVM_EXIT_VMSAVE,			"vmsave" },
	{ SVM_EXIT_STGI,			"stgi" },
	{ SVM_EXIT_CLGI,			"clgi" },
	{ SVM_EXIT_SKINIT,			"skinit" },
	{ SVM_EXIT_WBINVD,			"wbinvd" },
	{ SVM_EXIT_MONITOR,			"monitor" },
	{ SVM_EXIT_MWAIT,			"mwait" },
	{ SVM_EXIT_NPF,				"npf" },
	{ -1, NULL }
};

static int
handle_exit(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	struct kvm_run *kvm_run = vcpu->run;
	uint32_t exit_code = svm->vmcb->control.exit_code;
	int i = 0;
	const char *xx = NULL;

/* ROGER */

	/* XXX is "svm->vmcb->save.rip" the GUEST RIP?  If not...o
	    replace it with something that is, a la
	    vmcs_readl(GUEST_RIP). */
	KVM_TRACE2(vexit, unsigned long, svm->vmcb->save.rip,
	    uint32_t, exit_code);

	svm_complete_interrupts(svm);

	if (!(svm->vmcb->control.intercept_cr_write & INTERCEPT_CR0_MASK))
		vcpu->arch.cr0 = svm->vmcb->save.cr0;
	if (npt_enabled)
		vcpu->arch.cr3 = svm->vmcb->save.cr3;

	if (svm->vmcb->control.exit_code == SVM_EXIT_ERR) {
		kvm_run->exit_reason = KVM_EXIT_FAIL_ENTRY;
		kvm_run->fail_entry.hardware_entry_failure_reason
			= svm->vmcb->control.exit_code;
		return (0);
	}

	if (is_external_interrupt(svm->vmcb->control.exit_int_info) &&
	    exit_code != SVM_EXIT_EXCP_BASE + PF_VECTOR &&
	    exit_code != SVM_EXIT_NPF && exit_code != SVM_EXIT_TASK_SWITCH)
		cmn_err(CE_WARN, "%s: unexpected exit_ini_info 0x%x "
		       "exit_code 0x%x\n",
		       __func__, svm->vmcb->control.exit_int_info,
		       exit_code);

	if (exit_code >= ARRAY_SIZE(svm_exit_handlers)
	    || !svm_exit_handlers[exit_code]) {
		kvm_run->exit_reason = KVM_EXIT_UNKNOWN;
		kvm_run->hw.hardware_exit_reason = exit_code;
		return (0);
	}

	return (svm_exit_handlers[exit_code](svm));
}

static void
native_load_tr_desc(void)
{
	__asm__ volatile("ltr %w0"::"q" (KTSS_SEL));
}
#define load_TR_desc() native_load_tr_desc()

static void
reload_tss(/*struct kvm_vcpu *vcpu*/void)
{
	struct descriptor_table gdt;
	struct desc_struct *descs;

	kvm_get_gdt(&gdt);
	descs = (void *)gdt.base;
	descs[GDT_KTSS].c.b.type = 9; /* available 32/64-bit TSS */
	load_TR_desc();
}

static void
pre_svm_run(struct vcpu_svm *svm)
{
	int cpu = curthread->t_cpu->cpu_seqid;

	struct svm_cpu_data *sd = kvm_svm_cpu_data[cpu];

	svm->vmcb->control.tlb_ctl = TLB_CONTROL_DO_NOTHING;
	/* FIXME: handle wraparound of asid_generation */
	if (svm->asid_generation != sd->asid_generation)
		new_asid(svm, sd);
}

static void
svm_inject_nmi(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	svm->vmcb->control.event_inj = SVM_EVTINJ_VALID | SVM_EVTINJ_TYPE_NMI;
	vcpu->arch.hflags |= HF_NMI_MASK;
	svm->vmcb->control.intercept |= (1ULL << INTERCEPT_IRET);
	/* XXX FIND: ++vcpu->stat.nmi_injections; */
}

static void
svm_inject_irq(struct vcpu_svm *svm, int irq)
{
	struct vmcb_control_area *control;

	KVM_TRACE1(inj__virq, int, irq);

	/* XXX: stats
	    ++svm->vcpu.stat.irq_injections; */
	control = &svm->vmcb->control;
	control->int_vector = irq;
	control->int_ctl &= ~V_INTR_PRIO_MASK;
	control->int_ctl |= V_IRQ_MASK |
		((/*control->int_vector >> 4*/ 0xf) << V_INTR_PRIO_SHIFT);
}

static void
svm_set_irq(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	if (!gif_set(svm)) {
		cmn_err(CE_PANIC, "svm_set_irq() with !gif_set()\n");
	}

	svm->vmcb->control.event_inj = vcpu->arch.interrupt.nr |
		SVM_EVTINJ_VALID | SVM_EVTINJ_TYPE_INTR;
}

static void
update_cr8_intercept(struct kvm_vcpu *vcpu, int tpr, int irr)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	if (irr == -1)
		return;

	if (tpr >= irr)
		svm->vmcb->control.intercept_cr_write |= INTERCEPT_CR8_MASK;
}

static int
svm_nmi_allowed(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	struct vmcb *vmcb = svm->vmcb;
	return (!(vmcb->control.int_state & SVM_INTERRUPT_SHADOW_MASK) &&
		!(svm->vcpu.arch.hflags & HF_NMI_MASK));
}

static int
svm_get_nmi_mask(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	return (!!(svm->vcpu.arch.hflags & HF_NMI_MASK));
}

static void
svm_set_nmi_mask(struct kvm_vcpu *vcpu, int masked)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	if (masked) {
		svm->vcpu.arch.hflags |= HF_NMI_MASK;
		svm->vmcb->control.intercept |= (1ULL << INTERCEPT_IRET);
	} else {
		svm->vcpu.arch.hflags &= ~HF_NMI_MASK;
		svm->vmcb->control.intercept &= ~(1ULL << INTERCEPT_IRET);
	}
}

static int
svm_interrupt_allowed(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	struct vmcb *vmcb = svm->vmcb;
	int ret;

	if (!gif_set(svm) ||
	     (vmcb->control.int_state & SVM_INTERRUPT_SHADOW_MASK))
		return (0);

	ret = !!(vmcb->save.rflags & X86_EFLAGS_IF);

	return (ret);
}

static void
enable_irq_window(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);

#if 0
	nested_svm_intr(svm);
#endif

	/* In case GIF=0 we can't rely on the CPU to tell us when
	 * GIF becomes 1, because that's a separate STGI/VMRUN intercept.
	 * The next time we get that intercept, this function will be
	 * called again though and we'll get the vintr intercept. */
	if (gif_set(svm)) {
		svm_set_vintr(svm);
		svm_inject_irq(svm, 0x0);
	}
}

static void
enable_nmi_window(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	if ((svm->vcpu.arch.hflags & (HF_NMI_MASK | HF_IRET_MASK))
	    == HF_NMI_MASK)
		return; /* IRET will cause a vm exit */

	/* Something prevents NMI from been injected. Single step over
	   possible problem (IRET or exception injection or interrupt
	   shadow) */
	svm->nmi_singlestep = 1;
	svm->vmcb->save.rflags |= (X86_EFLAGS_TF | X86_EFLAGS_RF);
	update_db_intercept(vcpu);
}

static int
svm_set_tss_addr(struct kvm *kvm, uintptr_t addr)
{
	return 0;
}

static void
svm_flush_tlb(struct kvm_vcpu *vcpu)
{
	force_new_asid(vcpu);
}

static void
svm_prepare_guest_switch(struct kvm_vcpu *vcpu)
{
	/* XXX empty?? */
}

static void
sync_cr8_to_lapic(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	if (!(svm->vmcb->control.intercept_cr_write & INTERCEPT_CR8_MASK)) {
		int cr8 = svm->vmcb->control.int_ctl & V_TPR_MASK;
		kvm_set_cr8(vcpu, cr8);
	}
}

static void
sync_lapic_to_cr8(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	uint64_t cr8;

	cr8 = kvm_get_cr8(vcpu);
	svm->vmcb->control.int_ctl &= ~V_TPR_MASK;
	svm->vmcb->control.int_ctl |= cr8 & V_TPR_MASK;
}

static void
svm_complete_interrupts(struct vcpu_svm *svm)
{
	uint8_t vector;
	int type;
	uint32_t exitintinfo = svm->vmcb->control.exit_int_info;

	if (svm->vcpu.arch.hflags & HF_IRET_MASK)
		svm->vcpu.arch.hflags &= ~(HF_NMI_MASK | HF_IRET_MASK);

	svm->vcpu.arch.nmi_injected = 0;
	kvm_clear_exception_queue(&svm->vcpu);
	kvm_clear_interrupt_queue(&svm->vcpu);

	if (!(exitintinfo & SVM_EXITINTINFO_VALID))
		return;

	vector = exitintinfo & SVM_EXITINTINFO_VEC_MASK;
	type = exitintinfo & SVM_EXITINTINFO_TYPE_MASK;

	switch (type) {
	case SVM_EXITINTINFO_TYPE_NMI:
		svm->vcpu.arch.nmi_injected = 1;
		break;
	case SVM_EXITINTINFO_TYPE_EXEPT:
		/* In case of software exception do not reinject an exception
		   vector, but re-execute and instruction instead */
		if (kvm_exception_is_soft(vector))
			break;
		if (exitintinfo & SVM_EXITINTINFO_VALID_ERR) {
			uint32_t err = svm->vmcb->control.exit_int_info_err;
			kvm_queue_exception_e(&svm->vcpu, vector, err);

		} else
			kvm_queue_exception(&svm->vcpu, vector);
		break;
	case SVM_EXITINTINFO_TYPE_INTR:
		kvm_queue_interrupt(&svm->vcpu, vector, 0);
		break;
	default:
		break;
	}
}

extern int tdebug;

static unsigned long __force_order;

unsigned long
native_read_cr2(void)
{
        unsigned long val;
        __asm__ volatile("mov %%cr2,%0\n\t" : "=r" (val), "=m" (__force_order));
        return (val);
}

unsigned long
native_read_cr8(void)
{
        unsigned long val;
        __asm__ volatile("mov %%cr8,%0\n\t" : "=r" (val), "=m" (__force_order));
        return (val);
}

static void
svm_vcpu_run(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);
	uint16_t fs_selector;
	uint16_t gs_selector;
	uint16_t ldt_selector;

	KVM_TRACE1(vrun, unsigned long, vcpu->arch.regs[VCPU_REGS_RIP]);

	svm->vmcb->save.rax = vcpu->arch.regs[VCPU_REGS_RAX];
	svm->vmcb->save.rsp = vcpu->arch.regs[VCPU_REGS_RSP];
	svm->vmcb->save.rip = vcpu->arch.regs[VCPU_REGS_RIP];

	pre_svm_run(svm);

	sync_lapic_to_cr8(vcpu);

	save_host_msrs(vcpu);
	fs_selector = kvm_read_fs();
	gs_selector = kvm_read_gs();
	ldt_selector = kvm_read_ldt();
	svm->vmcb->save.cr2 = vcpu->arch.cr2;
	/* required for live migration with NPT */
	if (npt_enabled)
		svm->vmcb->save.cr3 = vcpu->arch.cr3;

	clgi();

	/* XXX what is this for
	   local_irq_enable(); */
	/* maybe sti() would work instead? */

	__asm__ volatile (
		"push %%rcx; \n\t"
		"mov  %%cr2,%%rcx; \n\t"
		"push %%rcx; \n\t"
		"push %%rbp; \n\t"
		"mov %c[rbx](%[svm]), %%rbx \n\t"
		"mov %c[rcx](%[svm]), %%rcx \n\t"
		"mov %c[rdx](%[svm]), %%rdx \n\t"
		"mov %c[rsi](%[svm]), %%rsi \n\t"
		"mov %c[rdi](%[svm]), %%rdi \n\t"
		"mov %c[rbp](%[svm]), %%rbp \n\t"
		"mov %c[r8](%[svm]),  %%r8  \n\t"
		"mov %c[r9](%[svm]),  %%r9  \n\t"
		"mov %c[r10](%[svm]), %%r10 \n\t"
		"mov %c[r11](%[svm]), %%r11 \n\t"
		"mov %c[r12](%[svm]), %%r12 \n\t"
		"mov %c[r13](%[svm]), %%r13 \n\t"
		"mov %c[r14](%[svm]), %%r14 \n\t"
		"mov %c[r15](%[svm]), %%r15 \n\t"

		/* Enter guest mode */
		"push %%rax \n\t"
		"mov %c[vmcb](%[svm]), %%rax \n\t"
		__ex(SVM_VMLOAD) "\n\t"
		__ex(SVM_VMRUN) "\n\t"
		__ex(SVM_VMSAVE) "\n\t"
		"pop %%rax \n\t"

		/* Save guest registers, load host registers */
		"mov %%rbx, %c[rbx](%[svm]) \n\t"
		"mov %%rcx, %c[rcx](%[svm]) \n\t"
		"mov %%rdx, %c[rdx](%[svm]) \n\t"
		"mov %%rsi, %c[rsi](%[svm]) \n\t"
		"mov %%rdi, %c[rdi](%[svm]) \n\t"
		"mov %%rbp, %c[rbp](%[svm]) \n\t"
		"mov %%r8,  %c[r8](%[svm]) \n\t"
		"mov %%r9,  %c[r9](%[svm]) \n\t"
		"mov %%r10, %c[r10](%[svm]) \n\t"
		"mov %%r11, %c[r11](%[svm]) \n\t"
		"mov %%r12, %c[r12](%[svm]) \n\t"
		"mov %%r13, %c[r13](%[svm]) \n\t"
		"mov %%r14, %c[r14](%[svm]) \n\t"
		"mov %%r15, %c[r15](%[svm]) \n\t"
		"pop %%rbp \n\t"
		"pop %%rcx \n\t"
		"mov %%rcx,%%cr2; \n\t"
		"pop %%rcx \n\t"
		:
		: [svm]"a"(svm),
		  [vmcb]"i"(offsetof(struct vcpu_svm, vmcb_pa)),
		  [rbx]"i"(offsetof(struct vcpu_svm, vcpu.arch.regs[VCPU_REGS_RBX])),
		  [rcx]"i"(offsetof(struct vcpu_svm, vcpu.arch.regs[VCPU_REGS_RCX])),
		  [rdx]"i"(offsetof(struct vcpu_svm, vcpu.arch.regs[VCPU_REGS_RDX])),
		  [rsi]"i"(offsetof(struct vcpu_svm, vcpu.arch.regs[VCPU_REGS_RSI])),
		  [rdi]"i"(offsetof(struct vcpu_svm, vcpu.arch.regs[VCPU_REGS_RDI])),
		  [rbp]"i"(offsetof(struct vcpu_svm, vcpu.arch.regs[VCPU_REGS_RBP]))
		  , [r8]"i"(offsetof(struct vcpu_svm, vcpu.arch.regs[VCPU_REGS_R8])),
		  [r9]"i"(offsetof(struct vcpu_svm, vcpu.arch.regs[VCPU_REGS_R9])),
		  [r10]"i"(offsetof(struct vcpu_svm, vcpu.arch.regs[VCPU_REGS_R10])),
		  [r11]"i"(offsetof(struct vcpu_svm, vcpu.arch.regs[VCPU_REGS_R11])),
		  [r12]"i"(offsetof(struct vcpu_svm, vcpu.arch.regs[VCPU_REGS_R12])),
		  [r13]"i"(offsetof(struct vcpu_svm, vcpu.arch.regs[VCPU_REGS_R13])),
		  [r14]"i"(offsetof(struct vcpu_svm, vcpu.arch.regs[VCPU_REGS_R14])),
		  [r15]"i"(offsetof(struct vcpu_svm, vcpu.arch.regs[VCPU_REGS_R15]))
		: "cc", "memory"
		, "rbx", "rcx", "rdx", "rsi", "rdi"
		, "r8", "r9", "r10", "r11" , "r12", "r13", "r14", "r15"
	);

	vcpu->arch.cr2 = svm->vmcb->save.cr2;
	vcpu->arch.regs[VCPU_REGS_RAX] = svm->vmcb->save.rax;
	vcpu->arch.regs[VCPU_REGS_RSP] = svm->vmcb->save.rsp;
	vcpu->arch.regs[VCPU_REGS_RIP] = svm->vmcb->save.rip;

	kvm_load_fs(fs_selector);
	kvm_load_gs(gs_selector);
	kvm_load_ldt(ldt_selector);
	load_host_msrs(vcpu);

	reload_tss(/*vcpu*/);

	/* XXX what is this for
	    local_irq_disable(); */
	/* maybe cli() would work instead? */

	stgi();

	sync_cr8_to_lapic(vcpu);

	svm->next_rip = 0;

	if (npt_enabled) {
		vcpu->arch.regs_avail &= ~(1 << VCPU_EXREG_PDPTR);
		vcpu->arch.regs_dirty &= ~(1 << VCPU_EXREG_PDPTR);
	}

}

static void
svm_set_cr3(struct kvm_vcpu *vcpu, unsigned long root)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	if (npt_enabled) {
		svm->vmcb->control.nested_cr3 = root;
		force_new_asid(vcpu);
		return;
	}

	svm->vmcb->save.cr3 = root;
	force_new_asid(vcpu);
}

static int
is_disabled(void)
{
	uint64_t vm_cr;

	rdmsrl(MSR_VM_CR, vm_cr);
	if (vm_cr & (1 << SVM_VM_CR_SVM_DISABLE))
		return (1);

	return (0);
}

static void
svm_patch_hypercall(struct kvm_vcpu *vcpu, unsigned char *hypercall)
{
	/*
	 * Patch in the VMMCALL instruction:
	 */
	hypercall[0] = 0x0f;
	hypercall[1] = 0x01;
	hypercall[2] = 0xd9;
}

static void
svm_check_processor_compat(void *rtn)
{
	*(int *)rtn = 0;
}

static int
svm_cpu_has_accelerated_tpr(void)
{
	return (0);
}

static int
get_npt_level(void)
{
	return PT64_ROOT_LEVEL;
}

static uint64_t
svm_get_mt_mask(struct kvm_vcpu *vcpu, gfn_t gfn, int is_mmio)
{
	return 0;
}

static void
svm_cpuid_update(struct kvm_vcpu *vcpu)
{
}

static int
svm_get_lpage_level(void)
{
	return PT_PDPE_LEVEL;
}

static int
svm_rdtscp_supported(void)
{
	return 0;
}

static void
svm_fpu_deactivate(struct kvm_vcpu *vcpu)
{
	struct vcpu_svm *svm = to_svm(vcpu);

	update_cr0_intercept(svm);
	svm->vmcb->control.intercept_exceptions |= 1 << NM_VECTOR;
}

static void
kvm_get_cs_db_l_bits(struct kvm_vcpu *vcpu, int *db, int *l)
{
        struct kvm_segment cs;

        kvm_get_segment(vcpu, &cs, VCPU_SREG_CS);
        *db = cs.db;
        *l = cs.l;
}

static struct kvm_x86_ops svm_x86_ops = {
	.cpu_has_kvm_support = has_svm,
	.disabled_by_bios = is_disabled,

	.hardware_enable = svm_hardware_enable,
	.hardware_disable = svm_hardware_disable,

	.check_processor_compatibility = svm_check_processor_compat,

	.hardware_setup = svm_hardware_setup,

	.hardware_unsetup = svm_hardware_unsetup,

	.cpu_has_accelerated_tpr = svm_cpu_has_accelerated_tpr,
	.vcpu_create = svm_create_vcpu,
	.vcpu_free = svm_free_vcpu,
	.vcpu_reset = svm_vcpu_reset,

	.prepare_guest_switch = svm_prepare_guest_switch,
	.vcpu_load = svm_vcpu_load,
	.vcpu_put = svm_vcpu_put,

	.set_guest_debug = svm_guest_debug,
	.get_msr = svm_get_msr,
	.set_msr = svm_set_msr,
	.get_segment_base = svm_get_segment_base,
	.get_segment = svm_get_segment,
	.set_segment = svm_set_segment,
	.get_cpl = svm_get_cpl,
	.get_cs_db_l_bits = kvm_get_cs_db_l_bits,
	.decache_cr0_guest_bits = svm_decache_cr0_guest_bits,
	.decache_cr4_guest_bits = svm_decache_cr4_guest_bits,
	.set_cr0 = svm_set_cr0,
	.set_cr3 = svm_set_cr3,
	.set_cr4 = svm_set_cr4,
	.set_efer = svm_set_efer,
	.get_idt = svm_get_idt,
	.set_idt = svm_set_idt,
	.get_gdt = svm_get_gdt,
	.set_gdt = svm_set_gdt,
	.cache_reg = svm_cache_reg,
	.get_rflags = svm_get_rflags,
	.set_rflags = svm_set_rflags,
	.fpu_activate = svm_fpu_activate,
	.fpu_deactivate = svm_fpu_deactivate,

	.tlb_flush = svm_flush_tlb,

	.run = svm_vcpu_run,
	.handle_exit = handle_exit,
	.skip_emulated_instruction = skip_emulated_instruction,
	.set_interrupt_shadow = svm_set_interrupt_shadow,
	.get_interrupt_shadow = svm_get_interrupt_shadow,
	.patch_hypercall = svm_patch_hypercall,
	.set_irq = svm_set_irq,
	.set_nmi = svm_inject_nmi,
	.queue_exception = svm_queue_exception,
	.interrupt_allowed = svm_interrupt_allowed,
	.nmi_allowed = svm_nmi_allowed,
	.get_nmi_mask = svm_get_nmi_mask,
	.set_nmi_mask = svm_set_nmi_mask,
	.enable_nmi_window = enable_nmi_window,
	.enable_irq_window = enable_irq_window,
	.update_cr8_intercept = update_cr8_intercept,

	.set_tss_addr = svm_set_tss_addr,
	.get_tdp_level = get_npt_level,
	.get_mt_mask = svm_get_mt_mask,

	.exit_reasons_str = svm_exit_reasons_str,

	.get_lpage_level = svm_get_lpage_level,

	.cpuid_update = svm_cpuid_update,

	.rdtscp_supported = svm_rdtscp_supported,

/* --- these arent in vmx:  --- */
	.get_dr = svm_get_dr,
	.set_dr = svm_set_dr,
};

int
kvm_svm_init(void)
{
	int r;
	
	kvm_svm_vcpu_cache = kmem_cache_create("kvm_svm_vcpu",
	    sizeof (struct vcpu_svm), PAGESIZE, zero_constructor,
	    NULL, NULL, (void *)(sizeof (struct vcpu_svm)),
	    NULL, 0);
	/* JMC: NB: VMRUN requires VMCBs (which are 4K)
	    to be aligned on 4kb boundaries */
	kvm_svm_vmcb_cache = kmem_cache_create("kvm_svm_vmcb",
	    sizeof (struct vmcb), SVM_ALLOC_VMCB_ALIGN,
	    zero_constructor, NULL, NULL,
	    (void *)(sizeof (struct vmcb)), NULL, 0);
	kvm_svm_msrpm_cache = kmem_cache_create("kvm_svm_msrpm",
	    SVM_ALLOC_MSRPM_SIZE, SVM_ALLOC_MSRPM_ALIGN,
	    zero_constructor, NULL, NULL,
	    (void *)SVM_ALLOC_MSRPM_SIZE, NULL, 0);
	kvm_svm_iopm_cache = kmem_cache_create("kvm_svm_iopm",
	    SVM_ALLOC_IOPM_SIZE, SVM_ALLOC_IOPM_ALIGN,
	    zero_constructor, NULL, NULL,
	    (void *)SVM_ALLOC_IOPM_SIZE, NULL, 0);
	kvm_svm_savearea_cache = kmem_cache_create("kvm_svm_savearea",
	    sizeof (struct svm_cpu_data), PAGESIZE,
	    zero_constructor, NULL, NULL,
	    (void *)(sizeof (struct svm_cpu_data)), NULL, 0);
	kvm_svm_cpudata_cache = kmem_cache_create("kvm_svm_cpudata",
	    PAGESIZE, PAGESIZE,
	    zero_constructor, NULL, NULL,
	    (void *)PAGESIZE, NULL, 0);

	/* XXX should really check all of the above for NULL */
	if (kvm_svm_vcpu_cache == NULL) {
		return (ENOMEM);
	}

	r = kvm_init(&svm_x86_ops);
	if (r) {
		kmem_cache_destroy(kvm_svm_savearea_cache);
		kmem_cache_destroy(kvm_svm_cpudata_cache);
		kmem_cache_destroy(kvm_svm_iopm_cache);
		kmem_cache_destroy(kvm_svm_vmcb_cache);
		kmem_cache_destroy(kvm_svm_msrpm_cache);
		kmem_cache_destroy(kvm_svm_vcpu_cache);
	}
	return (r);
}

void
kvm_svm_fini(void)
{
	kmem_cache_destroy(kvm_svm_savearea_cache);
	kmem_cache_destroy(kvm_svm_cpudata_cache);
	kmem_cache_destroy(kvm_svm_iopm_cache);
	kmem_cache_destroy(kvm_svm_vmcb_cache);
	kmem_cache_destroy(kvm_svm_msrpm_cache);
	kmem_cache_destroy(kvm_svm_vcpu_cache);
}

