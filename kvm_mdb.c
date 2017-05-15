/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2011 Joyent Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <mdb/mdb_param.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/uio.h>
#include <sys/buf.h>
#include <sys/modctl.h>
#include <sys/open.h>
#include <sys/kmem.h>
#include <sys/poll.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/atomic.h>
#include <sys/spl.h>
#include <sys/cpuvar.h>
#include <sys/segments.h>
#include <sys/mdb_modapi.h>
#include <sys/avl.h>

#include "kvm_msr.h"
#include "kvm_vmx.h"
#include "kvm_iodev.h"
#include "kvm_host.h"
#include "kvm_x86host.h"
#include "kvm.h"

int
kvm_mdb_memory_slot_init(mdb_walk_state_t *wsp)
{
	struct kvm_memslots *memslots;
	struct kvm kvm;
	uintptr_t addr;

	if (wsp->walk_addr == NULL) {
		mdb_warn("kvm_memory_slot does not support global walks");
		return (WALK_ERR);
	}

	if (mdb_vread(&kvm, sizeof (kvm), wsp->walk_addr) == -1) {
		mdb_warn("couldn't read kvm at %p", wsp->walk_addr);
		return (DCMD_ERR);
	}

	addr = (uintptr_t)kvm.memslots;
	memslots = mdb_alloc(sizeof (struct kvm_memslots), UM_SLEEP | UM_GC);

	if (mdb_vread(memslots, sizeof (struct kvm_memslots), addr) == -1) {
		mdb_warn("couldn't read memslots at %p", addr);
		return (DCMD_ERR);
	}

	wsp->walk_addr = addr + offsetof(struct kvm_memslots, memslots);
	wsp->walk_arg = 0;
	wsp->walk_data = memslots;

	return (WALK_NEXT);
}

int
kvm_mdb_memory_slot_step(mdb_walk_state_t *wsp)
{
	struct kvm_memslots *memslots = wsp->walk_data;
	uintptr_t ndx = (uintptr_t)wsp->walk_arg;

	if (ndx >= KVM_MEMORY_SLOTS)
		return (WALK_DONE);

	wsp->walk_arg = (void *)(ndx + 1);

	return (wsp->walk_callback(wsp->walk_addr +
	    ndx * sizeof (struct kvm_memory_slot), &memslots->memslots[ndx],
	    wsp->walk_cbdata));
}

int
kvm_mdb_mem_alias_init(mdb_walk_state_t *wsp)
{
	struct kvm_mem_aliases *aliases;
	struct kvm kvm;
	uintptr_t addr;

	if (wsp->walk_addr == NULL) {
		mdb_warn("kvm_mem_alias does not support global walks");
		return (WALK_ERR);
	}

	if (mdb_vread(&kvm, sizeof (kvm), wsp->walk_addr) == -1) {
		mdb_warn("couldn't read kvm at %p", wsp->walk_addr);
		return (DCMD_ERR);
	}

	addr = (uintptr_t)kvm.arch.aliases;
	aliases = mdb_alloc(sizeof (struct kvm_mem_aliases), UM_SLEEP | UM_GC);

	if (mdb_vread(aliases, sizeof (struct kvm_mem_aliases), addr) == -1) {
		mdb_warn("couldn't read aliases at %p", addr);
		return (DCMD_ERR);
	}

	wsp->walk_addr = addr + offsetof(struct kvm_mem_aliases, aliases);
	wsp->walk_arg = 0;
	wsp->walk_data = aliases;

	return (WALK_NEXT);
}

int
kvm_mdb_mem_alias_step(mdb_walk_state_t *wsp)
{
	struct kvm_mem_aliases *aliases = wsp->walk_data;
	uintptr_t ndx = (uintptr_t)wsp->walk_arg;

	if (ndx >= aliases->naliases)
		return (WALK_DONE);

	wsp->walk_arg = (void *)(ndx + 1);

	return (wsp->walk_callback(wsp->walk_addr +
	    ndx * sizeof (struct kvm_mem_alias), &aliases->aliases[ndx],
	    wsp->walk_cbdata));
}

static int
kvm_mdb_gpa2qva_walk_alias(uintptr_t addr,
    const struct kvm_mem_alias *alias, uintptr_t *gfn)
{
	if (alias->flags & KVM_ALIAS_INVALID)
		return (WALK_NEXT);

	if (*gfn < alias->base_gfn || *gfn >= alias->base_gfn + alias->npages)
		return (WALK_NEXT);

	*gfn = alias->target_gfn + *gfn - alias->base_gfn;

	return (WALK_DONE);
}

static int
kvm_mdb_gpa2qva_walk_slot(uintptr_t addr,
    const struct kvm_memory_slot *memslot, uintptr_t *gpa)
{
	uintptr_t gfn = *gpa >> PAGESHIFT;

	if (gfn < memslot->base_gfn)
		return (WALK_NEXT);

	if (gfn >= memslot->base_gfn + memslot->npages)
		return (WALK_NEXT);

	mdb_printf("%p\n", memslot->userspace_addr +
	    ((gfn - memslot->base_gfn) << PAGESHIFT) + (*gpa & PAGEOFFSET));

	*gpa = -1;

	return (WALK_DONE);
}

static int
kvm_mdb_gpa2qva(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct kvm kvm;
	uintptr_t gpa = addr, gfn, kaddr;
	int i;

	if (!(flags & DCMD_ADDRSPEC) || argc < 1)
		return (DCMD_USAGE);

	switch (argv[0].a_type) {
	case MDB_TYPE_STRING:
		kaddr = mdb_strtoull(argv[0].a_un.a_str);
		break;

	case MDB_TYPE_IMMEDIATE:
		kaddr = argv[0].a_un.a_val;
		break;

	default:
		return (DCMD_USAGE);
	}

	if (mdb_vread(&kvm, sizeof (kvm), kaddr) == -1) {
		mdb_warn("couldn't read kvm at %p", kaddr);
		return (DCMD_ERR);
	}

	gfn = gpa >> PAGESHIFT;

	/*
	 * First unalias our guest PFN...
	 */
	if (mdb_pwalk("kvm_mem_alias",
	    (mdb_walk_cb_t)kvm_mdb_gpa2qva_walk_alias, &gfn, kaddr) == -1) {
		mdb_warn("failed to walk 'kvm_memory_slot' for %p", kaddr);
		return (DCMD_ERR);
	}

	gpa = (gfn << PAGESHIFT) | (gpa & PAGEOFFSET);

	/*
	 * Now walk memory slots looking for a match.
	 */
	if (mdb_pwalk("kvm_memory_slot",
	    (mdb_walk_cb_t)kvm_mdb_gpa2qva_walk_slot, &gpa, kaddr) == -1) {
		mdb_warn("failed to walk 'kvm_memory_slot' for %p", kaddr);
		return (DCMD_ERR);
	}

	if (gpa != -1) {
		mdb_warn("0x%p is unknown for kvm 0x%p", addr, kaddr);
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}



#define	PT64_BASE_ADDR_MASK (((1ULL << 52) - 1) & ~(uint64_t)(PAGESIZE-1))

struct kvm_ph_cb_arg {
	uintptr_t mmu_page_addr;
	uintptr_t page_addr;
};

static int
kvm_ph_cb(uintptr_t addr, const void *a, void *b)
{
	struct kvm_ph_cb_arg *arg = b;
	struct kvm_mmu_page page;

	if (mdb_vread(&page, sizeof (page), addr) == -1) {
		mdb_printf("FAILED TO READ KVM_MMU_PAGE\n");
		return (DCMD_ERR);
	}

	/* mdb_printf("    unsync: 0x%d\n", page.unsync);*/
	if (page.kmp_avlspt == arg->page_addr) {
		arg->mmu_page_addr = addr;
		/*mdb_printf("...found avl entry %p for spt page %p\n", addr, arg->page_addr);*/
	}
	return (DCMD_OK);
}

extern uintptr_t mdb_pfn2page(pfn_t pfn); /* XXX */

/*
 * mimic page_header() in kvm_mmu.c
 */
static uintptr_t
kvm_mdb_page_header(uintptr_t kvmaddr, hpa_t shadow_page)
{
	struct kvm_ph_cb_arg arg;
	uintptr_t pfn;

	arg.mmu_page_addr = 0;

	/* translate hpa to pfn */
	pfn = shadow_page >> PAGESHIFT;
	//mdb_printf(" # # # pfn: 0x%p\n", pfn);

	/* translate pfn to *page_t */
	if ((arg.page_addr = mdb_pfn2page(pfn)) == 0) {
		//mdb_printf("COULD NOT FIND PAGE_T FOR PFN %p\n", pfn);
		return (DCMD_ERR);
	}

	if (mdb_pwalk("avl", kvm_ph_cb, &arg,
	    (uintptr_t) kvmaddr + offsetof(struct kvm, kvm_avlmp)) == -1) {
		mdb_printf("   could not! error from mdb_pwalk\n");
	}
	if (arg.mmu_page_addr == 0) {
		//mdb_printf("DID NOT FIND PRIVATE DATA FOR SHADOW PAGE %p\n", shadow_page);
		return (0);
	}

	return (arg.mmu_page_addr);
}

static struct kvm_mmu_page*
kvm_mdb_see_kvm_mmu_page(uintptr_t addr)
{
	static uintptr_t lastaddr = 0;
	static struct kvm_mmu_page page;

	if (lastaddr != addr) {
		//mdb_printf(" * * * seeing page: 0x%p\n", addr);
		mdb_vread(&page, sizeof (page), addr);
	}
	lastaddr = addr;

	return &page;
}

static void
kvm_mdb_examine_spt_ent(uintptr_t kvmaddr, uintptr_t sptkma, int indent)
{
	int i;
	uint64_t pte[PAGESIZE / sizeof(uint64_t)];
	char ind[40];

	if (mdb_vread(&pte, sizeof(pte), sptkma) == -1) {
		mdb_printf("ERROR: could not read SPT PTE\n");
		return;
	}

	for (i = 0; i < indent && i < 39; i++) {
		ind[i] = ' ';
	}
	ind[i] = '\0';

	for (i = 0; i < PAGESIZE / sizeof(uint64_t); i++) {
		if ((pte[i] & 0x27) == 0x27) {
			uintptr_t pagehdr = kvm_mdb_page_header(kvmaddr,
			    (pte[i] & PT64_BASE_ADDR_MASK));
			uintptr_t sptkma;

			mdb_printf("%s[%d]  0x%p  (hpa 0x%p)\n", ind, i, pte[i],
			    (pte[i] & PT64_BASE_ADDR_MASK) >> PAGESHIFT);
			if (pagehdr) {
				sptkma = (uintptr_t)kvm_mdb_see_kvm_mmu_page(pagehdr)->sptkma;
				kvm_mdb_examine_spt_ent(kvmaddr, sptkma, indent + 4);
			} else {
				mdb_printf("%s          ^^-- ERROR: no private data in avltree\n", ind);
			}
		}
	}
	mdb_printf("\n");
}

static int
kvm_mdb_mmuinfo(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct kvm kvm;
	struct kvm_vcpu *vcpu;
	struct kvm_mmu *mmu;
	int i;
	uintptr_t ptr;

	if (argc > 1)
		return (DCMD_USAGE);

	if (mdb_vread(&kvm, sizeof (struct kvm), addr) == -1) {
		mdb_warn("couldn't read kvm at %p", addr);
		return (DCMD_ERR);
	}

	/* XXX assume, for now, that we're interested in the first VCPU */
	vcpu = mdb_alloc(sizeof (struct kvm_vcpu), UM_SLEEP | UM_GC);

	if (mdb_vread(vcpu, sizeof (struct kvm_vcpu),
	    (uintptr_t)kvm.vcpus[0]) == -1) {
		mdb_warn("couldn't read kvm_vcpu at %p",
		    kvm.vcpus[0]);
		return (DCMD_ERR);
	}

/*
	if (DCMD_HDRSPEC(flags))
		mdb_printf("%s %7s %5s\n", "CHIP", "PORT", "GSI");*/


	mmu = &vcpu->arch.mmu;
	mdb_printf("\nMMU Info -- mmu: 0x%p\n", mmu);
	mdb_printf("root_hpa: 0x%p (%s)\n", mmu->root_hpa,
	    mmu->root_hpa == INVALID_PAGE ? "INVALID" : "valid");
	mdb_printf("root_level: %s\n",
	    mmu->root_level == 0x1 ? "PAGE_TABLE (0x1)" :
	    mmu->root_level == 0x2 ? "PAGE_DIR (0x2)" :
	    mmu->root_level == 0x3 ? "PDPE (0x3)" :
	    mmu->root_level == 0x4 ? "PT64_ROOT (0x4)" : "?");
	mdb_printf("pae_root... 0x%p\n", (uintptr_t) mmu->pae_root);
	for (i = 0; i < 4; i++) {
		hpa_t root;
		if (mdb_vread(&root, sizeof(root), (uintptr_t)(mmu->pae_root + i)) == -1) {
			mdb_printf("  pae_root[%d]: could not read!\n", i);
		} else {
			mdb_printf("  pae_root[%d]: 0x%p (%s)\n", i,
			    root & PT64_BASE_ADDR_MASK,
			    root == INVALID_PAGE ? "INVALID" : "valid");
		}
	}
	mdb_printf("\n");

	mdb_printf("\nPage Private for MMU Root:\n");
	ptr = kvm_mdb_page_header(addr, mmu->root_hpa);
	if (ptr == 0) {
		mdb_printf("ERROR: could not find page private for MMU Root\n\n");
		return (DCMD_ERR);
	}
	mdb_printf("  page_private  0x%p  sptkma 0x%p\n", ptr,
	    kvm_mdb_see_kvm_mmu_page(ptr)->sptkma);

	kvm_mdb_examine_spt_ent(addr, (uintptr_t)kvm_mdb_see_kvm_mmu_page(ptr)->sptkma, 4);

	/* kvm_mmu_page *sp = page_header() ? */
	/* mmu_sync_children(vcpu, sp) */

	mdb_printf("\n");
	return (DCMD_OK);
}

static int
kvm_mdb_gsiroutes(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct kvm kvm;
	struct kvm_irq_routing_table *table;
	int ii, jj;

	if (argc > 1)
		return (DCMD_USAGE);

	if (mdb_vread(&kvm, sizeof (struct kvm), addr) == -1) {
		mdb_warn("couldn't read kvm at %p", addr);
		return (DCMD_ERR);
	}

	table = mdb_alloc(sizeof (struct kvm_irq_routing_table),
	    UM_SLEEP | UM_GC);

	if (mdb_vread(table, sizeof (struct kvm_irq_routing_table),
	    (uintptr_t)kvm.irq_routing) == -1) {
		mdb_warn("couldn't read kvm irq routing table at %p",
		    kvm.irq_routing);
		return (DCMD_ERR);
	}

	if (DCMD_HDRSPEC(flags))
		mdb_printf("%s %7s %5s\n", "CHIP", "PORT", "GSI");

	for (ii = 0; ii < KVM_NR_IRQCHIPS; ii++) {
		for (jj = 0; jj < KVM_IOAPIC_NUM_PINS; jj++)
			mdb_printf("%3d %7d    0x%x\n", ii, jj,
			    table->chip[ii][jj]);
	}

	return (DCMD_OK);
}

int
kvm_mdb_ringbuf_entry_init(mdb_walk_state_t *wsp)
{
	kvm_ringbuf_t *buf;
	uintptr_t addr;

	if (wsp->walk_addr == NULL) {
		mdb_warn("kvm_ringbuf_entry does not support global walks\n");
		return (WALK_ERR);
	}

	buf = mdb_alloc(sizeof (kvm_ringbuf_t), UM_SLEEP | UM_GC);

	if (mdb_vread(buf, sizeof (kvm_ringbuf_t), wsp->walk_addr) == -1) {
		mdb_warn("couldn't read kvm_ringbuf_t at %p", wsp->walk_addr);
		return (DCMD_ERR);
	}

	wsp->walk_addr += offsetof(kvm_ringbuf_t, kvmr_buf);
	wsp->walk_data = buf;
	wsp->walk_arg = (void *)(uintptr_t)(buf->kvmr_ent >
	    KVM_RINGBUF_NENTRIES ? buf->kvmr_ent - KVM_RINGBUF_NENTRIES : 0);

	return (WALK_NEXT);
}

int
kvm_mdb_ringbuf_entry_step(mdb_walk_state_t *wsp)
{
	kvm_ringbuf_t *buf = wsp->walk_data;
	uintptr_t ndx = (uintptr_t)wsp->walk_arg;

	if (ndx == buf->kvmr_ent)
		return (WALK_DONE);

	wsp->walk_arg = (void *)(ndx + 1);
	ndx &= KVM_RINGBUF_NENTRIES - 1;

	return (wsp->walk_callback(wsp->walk_addr +
	    ndx * sizeof (kvm_ringbuf_entry_t), &buf->kvmr_buf[ndx],
	    wsp->walk_cbdata));
}

int
kvm_mdb_ringbuf_entry(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	kvm_ringbuf_entry_t ent;

	if (!(flags & DCMD_ADDRSPEC))
		return (DCMD_USAGE);

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%16s %17s %3s %16s %-7s %16s\n", "ADDR",
		    "TIMESTAMP", "CPU", "THREAD", "TAG", "PAYLOAD");
	}

	if (mdb_vread(&ent, sizeof (ent), addr) == -1) {
		mdb_warn("couldn't read entry at %p", addr);
		return (DCMD_ERR);
	}

	mdb_printf("%16p %17lld %3d %16p %-7s %16p\n", addr, ent.kvmre_tsc,
	    ent.kvmre_cpuid, ent.kvmre_thread,
	    ent.kvmre_tag == KVM_RINGBUF_TAG_CTXSAVE ? "save" :
	    ent.kvmre_tag == KVM_RINGBUF_TAG_CTXRESTORE ? "restore" :
	    ent.kvmre_tag == KVM_RINGBUF_TAG_VMPTRLD ? "vmptrld" :
	    ent.kvmre_tag == KVM_RINGBUF_TAG_VCPUMIGRATE ? "migrate" :
	    ent.kvmre_tag == KVM_RINGBUF_TAG_VCPUCLEAR ? "clear" :
	    ent.kvmre_tag == KVM_RINGBUF_TAG_VCPULOAD ? "load" :
	    ent.kvmre_tag == KVM_RINGBUF_TAG_VCPUPUT ? "put" :
	    ent.kvmre_tag == KVM_RINGBUF_TAG_RELOAD ? "reload" :
	    ent.kvmre_tag == KVM_RINGBUF_TAG_EMUFAIL0 ? "efail-0" :
	    ent.kvmre_tag == KVM_RINGBUF_TAG_EMUFAIL1 ? "efail-1" :
	    ent.kvmre_tag == KVM_RINGBUF_TAG_EMUFAIL2 ? "efail-2" : "????",
	    ent.kvmre_payload);

	return (DCMD_OK);
}

static int
kvm_mdb_kvm_walk_init(mdb_walk_state_t *wsp)
{
	list_t list;
	GElf_Sym sym;
	if (wsp->walk_addr != NULL) {
		mdb_warn("kvm does not support non-global walks\n");
		return (WALK_ERR);
	}

	if (mdb_lookup_by_name("vm_list", &sym) != 0) {
		mdb_warn("unable to locate vm_list\n");
		return (WALK_ERR);
	}

	wsp->walk_addr = sym.st_value;

	if (mdb_vread(&list, sizeof (list_t), wsp->walk_addr) == -1) {
		mdb_warn("failed to read vm_list\n");
		return (WALK_ERR);
	}

	if (mdb_layered_walk("list", wsp) == -1) {
		mdb_warn("failed to walk 'list'\n");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

static int
kvm_mdb_kvm_walk_step(mdb_walk_state_t *wsp)
{
	return (wsp->walk_callback(wsp->walk_addr, wsp->walk_layer,
	    wsp->walk_cbdata));
}

static const mdb_dcmd_t dcmds[] = {
	{ "kvm_gpa2qva", "?[address of kvm]", "translate a guest physical "
	    "to a QEMU virtual address", kvm_mdb_gpa2qva },
	{ "kvm_gsiroutes", NULL, "print out the global system "
	    "interrupt (GSI) routing table", kvm_mdb_gsiroutes },
	{ "kvm_mmuinfo", NULL, "print info about the mmu for a kvm",
	    kvm_mdb_mmuinfo },
	{ "kvm_ringbuf_entry", NULL, "print out a kvm ring buffer entry",
	    kvm_mdb_ringbuf_entry },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "kvm_memory_slot", "walk kvm_memory_slot structures for a given kvm",
	    kvm_mdb_memory_slot_init, kvm_mdb_memory_slot_step },
	{ "kvm_mem_alias", "walk kvm_mem_alias structures for a given kvm",
	    kvm_mdb_mem_alias_init, kvm_mdb_mem_alias_step },
	{ "kvm_ringbuf_entry", "given a kvm_ringbuf_t, walk its entries",
	    kvm_mdb_ringbuf_entry_init, kvm_mdb_ringbuf_entry_step },
	{ "kvm", "walk all the kvm structures",
	    kvm_mdb_kvm_walk_init, kvm_mdb_kvm_walk_step },
	{ NULL }
};

static const mdb_modinfo_t modinfo = { MDB_API_VERSION, dcmds, walkers };

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
