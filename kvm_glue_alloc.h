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

#ifndef __KVM_ALLOC_H
#define	__KVM_ALLOC_H

#include <sys/types.h>

#define	KVM_ALLOC_LOW4GB	0x0001
#define	KVM_ALLOC_NOSLEEP	0x0002

extern void *kvm_glue_alloc(size_t, uintptr_t, int);
extern void kvm_glue_free(void *, size_t);

#endif /* __KVM_ALLOC_H */
