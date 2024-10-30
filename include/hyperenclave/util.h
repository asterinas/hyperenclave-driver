/* SPDX-License-Identifier: GPL-2.0 */
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#ifndef _HYPERENCLAVE_UTIL_H_
#define _HYPERENCLAVE_UTIL_H_

#include <linux/io.h>
#include <linux/mutex.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/sched/mm.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
#include <linux/mmap_lock.h>
#endif

#include <asm/tlbflush.h>

#include <hyperenclave/system_config.h>

extern int len_memmap_paras;
extern char *str_memmap[2];

extern struct mutex he_lock;
extern int hyper_enclave_enabled;
extern void *hypervisor_mem;
extern struct memory_range hv_range;
extern unsigned long hv_core_and_percpu_size;

extern void (*mmput_async_sym)(struct mm_struct *mm);
extern typeof(ioremap_page_range) *ioremap_page_range_sym;
#ifdef CONFIG_X86
extern void (*flush_tlb_kernel_range_sym)(unsigned long start,
					  unsigned long end);
#endif

void he_ipi_cb(void *info);
int he_cmd_disable(void);
int he_cmd_enable(void);

static inline void he_mmap_read_lock(struct mm_struct *mm)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
	mmap_read_lock(mm);
#else
	down_read(&mm->mmap_sem);
#endif
}

static inline void he_mmap_read_unlock(struct mm_struct *mm)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
	mmap_read_unlock(mm);
#else
	up_read(&mm->mmap_sem);
#endif
}

int he_kallsyms_init(void);

#ifdef MSR_IA32_FEAT_CTL
#define HE_RDMSRL_IA32_FEATURE_CONTROL(features)     \
	do {                                         \
		rdmsrl(MSR_IA32_FEAT_CTL, features); \
	} while (0)
#else
#define HE_RDMSRL_IA32_FEATURE_CONTROL(features)            \
	do {                                                \
		rdmsrl(MSR_IA32_FEATURE_CONTROL, features); \
	} while (0)
#endif

/* The evidence of abbreviation holy-war. */
#ifdef FEAT_CTL_VMX_ENABLED_OUTSIDE_SMX
#define HE_ENABLE_VMX_FLAG FEAT_CTL_VMX_ENABLED_OUTSIDE_SMX
#else
#define HE_ENABLE_VMX_FLAG FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX
#endif

static inline struct vm_struct *he_get_vm_area(unsigned long size,
					       unsigned long flags,
					       unsigned long start,
					       unsigned long end)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
	extern struct vm_struct *(*__get_vm_area_caller_sym)(
		unsigned long, unsigned long, unsigned long, unsigned long,
		void *);
	return __get_vm_area_caller_sym(size, flags, start, end,
					__builtin_return_address(0));
#else
	extern struct vm_struct *(*__get_vm_area_sym)(
		unsigned long, unsigned long, unsigned long, unsigned long);
	return __get_vm_area_sym(size, flags, start, end);
#endif
}

static inline void he_cr4_clear_vmxe(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 5, 0)
	cr4_clear_bits_irqsoff(X86_CR4_VMXE);
#else
	cr4_clear_bits(X86_CR4_VMXE);
#endif
}

/* Directly forward log generated in hyperenclave to the kernel log buffer. */
/* #define CONFIG_DIRECT_KERN_LOGGING */

#endif /*_HYPERENCLAVE_UTIL_H_ */
