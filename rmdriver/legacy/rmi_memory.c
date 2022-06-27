/******************************************************************************
 * Aerolock whitelisting reference code for industiral control systems (ICS)
 * Copyright (c) 2012-2022, by Resilient Machines, LLC and Sand Drft Software, LLC, and Peter H. Jenney
 * (r) All rights reserved. 
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 *****************************************************************************/

#include <linux/kernel_stat.h>
#include <linux/mm.h>
#include <linux/hugetlb.h>
#include <linux/mman.h>
#include <linux/swap.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/ksm.h>
#include <linux/rmap.h>
#include <linux/export.h>
#include <linux/delayacct.h>
#include <linux/init.h>
#include <linux/writeback.h>
#include <linux/memcontrol.h>
#include <linux/mmu_notifier.h>
#include <linux/kallsyms.h>
#include <linux/swapops.h>
#include <linux/elf.h>
#include <linux/gfp.h>

#include <asm/io.h>
#include <asm/pgalloc.h>
#include <asm/uaccess.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>
#include <asm/pgtable.h>

#ifdef __ARM__
#if 0
static void flush_ptrace_access_other(void *args)
{
	__flush_icache_all();
}

static
void flush_ptrace_access(struct vm_area_struct *vma, struct page *page,
			 unsigned long uaddr, void *kaddr, unsigned long len)
{
	if (cache_is_vivt()) {
		if (cpumask_test_cpu(smp_processor_id(), mm_cpumask(vma->vm_mm))) {
			unsigned long addr = (unsigned long)kaddr;
			__cpuc_coherent_kern_range(addr, addr + len);
		}
		return;
	}

	if (cache_is_vipt_aliasing()) {
		flush_pfn_alias(page_to_pfn(page), uaddr);
		__flush_icache_all();
		return;
	}

	/* VIPT non-aliasing D-cache */
	if (vma->vm_flags & VM_EXEC) {
		unsigned long addr = (unsigned long)kaddr;
		if (icache_is_vipt_aliasing())
			flush_icache_alias(page_to_pfn(page), uaddr, len);
		else
			__cpuc_coherent_kern_range(addr, addr + len);
		if (cache_ops_need_broadcast())
			smp_call_function(flush_ptrace_access_other,
					  NULL, 1);
	}
}
#endif
/*
 * Copy user data from/to a page which is mapped into a different
 * processes address space.  Really, we want to allow our "user
 * space" model to handle this.
 *
 * Note that this code needs to run on the current CPU.
 */
void copy_to_user_page(struct vm_area_struct *vma, struct page *page,
		       unsigned long uaddr, void *dst, const void *src,
		       unsigned long len)
{
#ifdef CONFIG_SMP
	preempt_disable();
#endif
	memcpy(dst, src, len);
	//flush_ptrace_access(vma, page, uaddr, dst, len);
#ifdef CONFIG_SMP
	preempt_enable();
#endif
}

void __bad_udelay(void)
{
    int i = 0;
}
#endif

/*
 * Access another process' address space as given in mm.  If non-NULL, use the
 * given task for page fault accounting.
 */
static int __rmi_access_remote_vm(struct task_struct *tsk, struct mm_struct *mm,
		unsigned long addr, void *buf, int len, int write)
{
	struct vm_area_struct *vma;
	void *old_buf = buf;

	down_read(&mm->mmap_sem);
	/* ignore errors, just check how much was successfully transferred */
	while (len) {
		int bytes, ret, offset;
		void *maddr;
		struct page *page = NULL;

		ret = get_user_pages(tsk, mm, addr, 1,
				write, 1, &page, &vma);
		if (ret <= 0) {
			/*
			 * Check if this is a VM_IO | VM_PFNMAP VMA, which
			 * we can access using slightly different code.
			 */
#ifdef CONFIG_HAVE_IOREMAP_PROT
			vma = find_vma(mm, addr);
			if (!vma || vma->vm_start > addr)
				break;
			if (vma->vm_ops && vma->vm_ops->access)
				ret = vma->vm_ops->access(vma, addr, buf,
							  len, write);
			if (ret <= 0)
#endif
				break;
			bytes = ret;
		} else {
			bytes = len;
			offset = addr & (PAGE_SIZE-1);
			if (bytes > PAGE_SIZE-offset)
				bytes = PAGE_SIZE-offset;

			maddr = kmap(page);
			if (write) {
				copy_to_user_page(vma, page, addr,
						  maddr + offset, buf, bytes);
				set_page_dirty_lock(page);
			} else {
				copy_from_user_page(vma, page, addr,
						    buf, maddr + offset, bytes);
			}
			kunmap(page);
			page_cache_release(page);
		}
		len -= bytes;
		buf += bytes;
		addr += bytes;
	}
	up_read(&mm->mmap_sem);

	return buf - old_buf;
}

/**
 * access_remote_vm - access another process' address space
 * @mm:		the mm_struct of the target address space
 * @addr:	start address to access
 * @buf:	source or destination buffer
 * @len:	number of bytes to transfer
 * @write:	whether the access is a write
 *
 * The caller must hold a reference on @mm.
 */
int rmi_access_remote_vm(struct mm_struct *mm, unsigned long addr,
		void *buf, int len, int write)
{
	return __rmi_access_remote_vm(NULL, mm, addr, buf, len, write);
}

/*
 * Access another process' address space.
 * Source/target buffer must be kernel space,
 * Do not walk the page table directly, use get_user_pages
 */
int rmi_access_process_vm(struct task_struct *tsk, unsigned long addr,
		void *buf, int len, int write)
{
	struct mm_struct *mm;
	int ret;

	mm = get_task_mm(tsk);
	if (!mm)
		return 0;

	ret = __rmi_access_remote_vm(tsk, mm, addr, buf, len, write);
	mmput(mm);

	return ret;
}
