#!/usr/sbin/dtrace -Zs

#pragma D option quiet

kvm-mmu-update-pte
{
	printf("[%d] %s | sp 0x%lx  gpte 0x%lx  spte 0x%lx\n",
	    arg0, probename, arg1, arg2, arg3);
}

kvm-mmu-fetch-spte
{
	printf("[%d] %s | gva 0x%lx  userfault %d  writefault %d  hlevel %d  pfn 0x%lx\n",
	    arg0, probename, arg1, arg2, arg3, arg4, arg5);
}

kvm-mmu-page-fault
{
	printf("[%d] %s | gva 0x%lx  err 0x%x\n",
	    arg0, probename, arg1, arg2);
}

kvm-mmu-page-fault-topup
{
	printf("[%d] %s | r 0x%x\n",
	    arg0, probename, arg1);
}

kvm-mmu-page-fault-guest
{
	printf("[%d] %s | gva 0x%lx  werr 0x%x\n",
	    arg0, probename, arg1, arg2);
}

kvm-mmu-page-fault-mmio
{
	printf("[%d] %s | waddr 0x%lx pfn 0x%lx\n",
	    arg0, probename, arg1, arg2);
}

kvm-mmu-page-fault-fetch
{
	printf("[%d] %s | sptep 0x%lx  *sptep 0x%lx  %d write_pt\n",
	    arg0, probename, arg1, arg2, arg3);
}

kvm-mmu-invalidate-page
{
	printf("[%d] %s | gva 0x%lx\n",
	    arg0, probename, arg1);
}

kvm-mmu-prefetch-page
{
	printf("[%d] %s | sp 0x%lx\n",
	    arg0, probename, arg1);
}

kvm-mmu-sync-page
{
	printf("[%d] %s | sp 0x%lx\n",
	    arg0, probename, arg1);
}

kvm-mmu-gva-to-gpa
{
	printf("[%d] %s | gva 0x%lx  access %x  werr %x  gpa %lx\n",
	    arg0, probename, arg1, arg2, arg3, arg4);
}

kvm-mmu-paging-element
{
	printf("[%d] %s | gpte 0x%lx  level %x\n",
	    arg0, probename, arg1, arg2);
}

kvm-mmu-set-accessed-bit
{
	printf("[%d] %s | table_gfn 0x%lx  index %d  what 0x%lx\n",
	    arg0, probename, arg1, arg2, arg3);
}

kvm-mmu-set-dirty-bit
{
	printf("[%d] %s | table_gfn 0x%lx  index %d  what 0x%lx\n",
	    arg0, probename, arg1, arg2, arg3);
}

kvm-mmu-page-table-walk
{
	printf("[%d] %s | gva 0x%lx  userfault %d  writefault %d  fetchfault %d\n",
	    arg0, probename, arg1, arg3, arg2, arg4);
}

kvm-mmu-page-table-walk-error
{
	printf("[%d] %s | error 0x%x\n",
	    arg0, probename, arg1);
}

kvm-mmu-paging-new-cr3
{
	printf("\n===================================================\n");
	printf(  "= PAGING NEW CR3: 0x%lx\n", arg0);
	printf(  "===================================================\n\n");
}

