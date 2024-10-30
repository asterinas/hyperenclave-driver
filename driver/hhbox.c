// SPDX-License-Identifier: GPL-2.0
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#include <linux/slab.h>

#include <hyperenclave/hypercall.h>
#include <hyperenclave/util.h>
#include <hyperenclave/log.h>

#include "feature.h"
#include "hhbox.h"

#ifndef DISABLE_LOGGING
static ulong he_log_flush_freq = HHBOX_LOG_HEARTBEAT_MS_DEFAULT;
module_param(he_log_flush_freq, ulong, S_IRUGO);
MODULE_PARM_DESC(he_log_flush_freq, "Maximum interval (in ms) in which "
		"Hyperenclave log is flushed.");

/* All init to zeros. Set to 1 to indicate a CPU is panic in Hyperenclave. */
static cpumask_t *vmm_anomaly_cpus;

static struct workqueue_struct *vmm_check_wq;
DEFINE_PER_CPU(struct delayed_work, vmm_check_work);

static struct delayed_work flush_hv_log_work;

static void flush_hv_log_work_func(struct work_struct *work);
static void vmm_check_work_func(struct work_struct *work)
{
	unsigned int cpu;

	cpu = smp_processor_id();
	if (hyper_enclave_enabled && !cpumask_empty(vmm_anomaly_cpus)) {
		he_flush_log();
		if (cpumask_test_cpu(cpu, vmm_anomaly_cpus)) {
			hypercall_ret_1(HC_DISABLE, 0);
		}
		panic("VMM abnormal");
	}

	queue_delayed_work_on(cpu, vmm_check_wq, this_cpu_ptr(&vmm_check_work),
			      msecs_to_jiffies(HHBOX_CRASH_HEARTBEAT_MS));
}

static bool alloc_vmm_check_wq(void)
{
	if (!hhbox_crash_enabled)
		return false;

	vmm_check_wq = alloc_workqueue("vmm_check_wq", 0, 0);

	return true;
}

static void dealloc_vmm_check_wq(void)
{
	if (!hhbox_crash_enabled)
		return;

	destroy_workqueue(vmm_check_wq);
}

static void register_vmm_check_wq(void)
{
	int cpu;

	if (!hhbox_crash_enabled)
		return;

	for_each_online_cpu(cpu) {
		struct delayed_work *dw = &per_cpu(vmm_check_work, cpu);

		INIT_DELAYED_WORK(dw, vmm_check_work_func);
		queue_delayed_work_on(
			cpu, vmm_check_wq, dw,
			msecs_to_jiffies(HHBOX_CRASH_HEARTBEAT_MS));
	}
}

static void deregister_vmm_check_wq(void)
{
	int cpu;

	if (!hhbox_crash_enabled)
		return;

	for_each_online_cpu(cpu) {
		cancel_delayed_work_sync(&per_cpu(vmm_check_work, cpu));
	}
}

/*
 * Called by workqueue: work is not null.
 * Called by panic handler: work is NULL and flush all the log.
 */
static void flush_hv_log_work_func(struct work_struct *work)
{
	extern typeof(printk_safe_flush) *printk_safe_flush_sym;
	printk_safe_flush_sym();

	if (work)
		schedule_delayed_work(&flush_hv_log_work,
			msecs_to_jiffies(he_log_flush_freq));
}

static void register_flush_hv_log_work(void)
{
	if (!hhbox_log_enabled)
		return;

	INIT_DELAYED_WORK(&flush_hv_log_work, flush_hv_log_work_func);
	schedule_delayed_work(&flush_hv_log_work,
			      msecs_to_jiffies(he_log_flush_freq));
}

static void deregister_flush_hv_log_work(void)
{
	if (!hhbox_log_enabled)
		return;

	cancel_delayed_work_sync(&flush_hv_log_work);
}
#endif /* DISABLE_LOGGING */

void he_flush_log(void)
{
#ifndef DISABLE_LOGGING
	return flush_hv_log_work_func(NULL);
#endif /* DISABLE_LOGGING */
}

int he_init_log(struct hyper_header *header)
{
    int r = 0;
#ifndef DISABLE_LOGGING

	if (alloc_vmm_check_wq()) {
		if (!vmm_check_wq) {
			he_err("alloc_workqueue failed\n");
			r = -ENOMEM;
            goto out;
		}
	}

	{
		unsigned long long safe_print_seq_start_va, safe_print_seq_start_pa;
		unsigned long long percpu_offset_pa;
		extern void *safe_print_seq_sym;
		/* Get percpu buffer safe_print_seq info */
		percpu_offset_pa = __pa_symbol(__per_cpu_offset);
		safe_print_seq_start_va = (u64)safe_print_seq_sym + __per_cpu_offset[0];
		safe_print_seq_start_pa = virt_to_phys((void *)safe_print_seq_start_va);

		header->safe_print_seq_start_pa = safe_print_seq_start_pa;
		header->percpu_offset_pa = percpu_offset_pa;
	}
	/* Vmm stats info */
	vmm_anomaly_cpus = kzalloc(sizeof(*vmm_anomaly_cpus), GFP_KERNEL);
	if (!vmm_anomaly_cpus) {
		r = -ENOMEM;
		goto out;
	}
	he_debug("vmm_anomaly_cpus pa: %llx\n", virt_to_phys(vmm_anomaly_cpus));
	header->vmm_anomaly_cpus_pa = virt_to_phys(vmm_anomaly_cpus);

	register_vmm_check_wq();
	register_flush_hv_log_work();

out:
#endif /* DISABLE_LOGGING */
	return r;
}

int he_deinit_log(void)
{
#ifndef DISABLE_LOGGING
	deregister_vmm_check_wq();
	dealloc_vmm_check_wq();
	deregister_flush_hv_log_work();

	kfree(vmm_anomaly_cpus);
	vmm_anomaly_cpus = NULL;
#endif /* DISABLE_LOGGING */
	return 0;
}
