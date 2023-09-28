// SPDX-License-Identifier: GPL-2.0-only
/*
 *  Copyright (C) 2023  Red Hat, Inc.
 */

static inline bool bpf_can_prefault(struct mm_struct *mm, unsigned long addr,
				   bool write)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	rcu_read_lock();
	pgd = pgd_offset(mm, addr);
	if (pgd_none(*pgd))
		goto prefault;
	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d))
		goto prefault;
	pud = pud_offset(p4d, addr);
	if (pud_none(*pud))
		goto prefault;
	if (pud_trans_huge(*pud) || pud_devmap(*pud)) {
		if (write && !pud_write(*pud))
			goto prefault;
		goto out_unlock;
	}
	VM_WARN_ON_ONCE(!pud_present(*pud));
	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd))
		goto prefault;
	if (pmd_trans_huge(*pmd) || pmd_devmap(*pmd)) {
		if (write && !pmd_write(*pmd))
			goto prefault;
		goto out_unlock;
	}
	if (!pmd_present(*pmd))
		goto out_unlock;
	pte = pte_offset_map(pmd, addr);
	if (pte_none(*pte))
		goto unmap_prefault;
	if (!pte_present(*pte))
		goto out_unmap_unlock;
	if (!write || pte_write(*pte))
		goto out_unmap_unlock;
unmap_prefault:
	pte_unmap(pte);
prefault:
	rcu_read_unlock();
	return true;

out_unmap_unlock:
	pte_unmap(pte);
out_unlock:
	rcu_read_unlock();
	return false;
}

static inline void bpf_prefault(struct vm_area_struct *vma,
			       unsigned long addr,
			       unsigned int flags)
{
#ifdef CONFIG_BPF_EVENTS
	unsigned int nr;
	unsigned long start, end;
	vm_fault_t err;
	struct mm_struct *mm;
	struct bpf_prefault_data pfd;
	bool write;

	if ((flags & (FAULT_FLAG_MKWRITE|
		      FAULT_FLAG_REMOTE|FAULT_FLAG_KILLABLE|
		      FAULT_FLAG_ALLOW_RETRY)) !=
	    (FAULT_FLAG_KILLABLE|FAULT_FLAG_ALLOW_RETRY))
		return;

	addr = untagged_addr(addr);
	pfd.pfd_addr = addr;
	pfd.pfd_write = !!(flags & FAULT_FLAG_WRITE);
	pfd.pfd_flags = 0;
	pfd.pfd_nr_pages = 0;
	pfd.pfd_nr = 0;
	mm = vma->vm_mm;
	pfd.pfd_mm = mm;
	pfd.pfd_vma = vma;
	start = pfd.pfd_vm_start = vma->vm_start;
	end = pfd.pfd_vm_end = vma->vm_end;
	pfd.pfd_vm_flags = vma->vm_flags;
	pfd.pfd_mm_code_size = mm->end_code - mm->start_code;
	trace_bpf_prefault(&pfd, BPF_PREFAULT_VERSION);
	if (pfd.pfd_addr == addr)
		return;

	if (unlikely(mmap_lock_is_contended(mm) ||
		     signal_pending(current)))
		return;

	cond_resched();

	write = pfd.pfd_write;

	flags &= ~(FAULT_FLAG_USER|FAULT_FLAG_TRIED|
		   FAULT_FLAG_WRITE|FAULT_FLAG_INSTRUCTION);
	flags |= FAULT_FLAG_RETRY_NOWAIT;
	flags |= write ? FAULT_FLAG_WRITE : 0;

	pfd.pfd_flags = BPF_PREFAULT_FLAG_INFER_MODE;

	nr = min((unsigned int) BPF_PREFAULT_NR_MAX, (unsigned int) pfd.pfd_nr);
	for (;;) {
		addr = pfd.pfd_addr;

		for (;;) {
			if (addr < start || addr >= end)
				goto out;
			if (!vma_permits_fault(vma, flags))
				goto out;
			if (!bpf_can_prefault(mm, addr, write))
				goto out;

			err = __handle_mm_fault(vma, addr, flags);
			/*
			 * mmap_lock is still hold thanks to
			 * FAULT_FLAG_RETRY_NOWAIT
			 */

			cond_resched();

			if (unlikely(err & (VM_FAULT_RETRY|VM_FAULT_ERROR)))
				goto out;
			if (unlikely(nr-- <= 1))
				goto out;
			if (pfd.pfd_nr_pages <= 1)
				break;
			pfd.pfd_nr_pages--;
			addr += PAGE_SIZE;
		}

		pfd.pfd_addr = addr;
		trace_bpf_prefault(&pfd, BPF_PREFAULT_VERSION);
		if (addr == pfd.pfd_addr)
			break;

		if (unlikely(mmap_lock_is_contended(mm) ||
			     signal_pending(current)))
			break;

		if (unlikely(write != pfd.pfd_write)) {
			write = pfd.pfd_write;
			if (write)
				flags |= FAULT_FLAG_WRITE;
			else
				flags &= ~FAULT_FLAG_WRITE;
		}
	}
out:
#endif
}
