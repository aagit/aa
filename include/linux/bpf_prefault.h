/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _LINUX_BPF_PREFAULT_H
#define _LINUX_BPF_PREFAULT_H

enum bpf_prefault_version {
	BPF_PREFAULT_VERSION = 0,
};

enum bpf_prefault_nr_max {
	BPF_PREFAULT_NR_MAX = 512,
};

enum bpf_prefault_bpf_flag {
       BPF_PREFAULT_FLAG_INFER_MODE = 1 << 0,
};

struct bpf_prefault_data {
	unsigned long pfd_addr;
	unsigned short pfd_nr;
	unsigned short pfd_nr_pages;
	unsigned short pfd_flags;
	bool pfd_write;
	struct mm_struct *pfd_mm;
	struct vm_area_struct *pfd_vma;
	unsigned long pfd_vm_start;
	unsigned long pfd_vm_end;
	unsigned long pfd_vm_flags;
	unsigned long pfd_mm_code_size;
};

#endif /* _LINUX_BPF_PREFAULT_H */
