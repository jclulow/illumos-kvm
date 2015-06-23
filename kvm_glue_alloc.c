/*
 * Kernel-based Virtual Machine driver for Linux
 *
 * illumos memory allocation glue
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Copyright 2011 Joshua M. Clulow <josh@sysmgr.org>
 */

#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include "kvm_glue_alloc.h"

/*
 * XXX: Using contig_alloc directly is a mess, and should likely be replaced
 *      with i_ddi_mem_alloc() or ddi_dma_mem_alloc() to the same end.
 */
extern void *contig_alloc(size_t, ddi_dma_attr_t *, uintptr_t, int);
extern void contig_free(void *, size_t);

void *
kvm_glue_alloc(size_t size, uintptr_t align, int flags)
{
	void *ret;
	int sleep = 1;
	/* XXX: Lies */
	static ddi_dma_attr_t dma_attr = {
		DMA_ATTR_V0,		/* version of this structure */
		0,			/* lowest usable address */
		0xffffffffffffffffULL,	/* highest usable address */
		0x7fffffff,		/* maximum DMAable byte count */
		0,			/* alignment in bytes */
		0x7ff,			/* burst sizes (any?) */
		1,			/* minimum transfer */
		0xffffffffU,		/* maximum transfer */
		0xffffffffffffffffULL,	/* maximum segment length */
		1,			/* maximum number of segments */
		1,			/* granularity */
		DDI_DMA_FLAGERR		/* dma_attr_flags */
	};
	dma_attr.dma_attr_align = align;
	if (flags & KVM_ALLOC_LOW4GB)
		dma_attr.dma_attr_addr_hi = 0x100000000ULL;
	if (flags & KVM_ALLOC_NOSLEEP)
		sleep = 0;

	ret = contig_alloc(size, &dma_attr, align, sleep);
	if (ret == NULL)
		cmn_err(CE_WARN, "%s: Failed to allocate contiguous memory"
		    " (sz 0x%lx align 0x%lx)", __func__, size, align);
	return (ret);
}

void
kvm_glue_free(void *buf, size_t size)
{
	contig_free(buf, size);
}
