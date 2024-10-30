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

/*
 * A ring buffer where hyperenclave writes logs. C-driver then periodically
 * forwards them to the kernel by printk.
 */
static struct he_log *he_log;

static ulong he_log_num = LOG_SIZE_DEFAULT;
module_param(he_log_num, ulong, S_IRUGO);
MODULE_PARM_DESC(he_log_num, "Number of Hyperenclave log buffer entry. "
			      "Range: [64, 2048]");

static ulong he_log_flush_freq = HHBOX_LOG_HEARTBEAT_MS_DEFAULT;
module_param(he_log_flush_freq, ulong, S_IRUGO | S_IWUSR);
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
	if (!hhbox_crash_enabled || !vmm_check_wq)
		return;

	destroy_workqueue(vmm_check_wq);
	vmm_check_wq = NULL;
}

static void register_vmm_check_wq(void)
{
	int cpu;

	if (!hhbox_crash_enabled)
		return;

	for_each_online_cpu (cpu) {
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

	for_each_online_cpu (cpu) {
		cancel_delayed_work_sync(&per_cpu(vmm_check_work, cpu));
	}
}

/*
 * Called by workqueue: work is not null.
 * Called by panic handler: work is NULL and flush all the log.
 */
static void flush_hv_log_work_func(struct work_struct *work)
{
	char *s;
	int i, j;
	struct he_logentry *hl;
	static unsigned long long he_log_index;

	if (he_log->log_lost > 0) {
		he_warn("Hyperenclave lost %u logs. Enlarge log buffer or increase log "
			"refreshing frequency.",
			he_log->log_lost);
		he_log->log_lost = 0;
	}

	for (j = 0; j < he_log->num; j++) {
		i = he_log_index;
		hl = &(he_log->log[i]);
		if (!hl->used)
			break;
		he_log_index = (he_log_index + 1) % he_log->num;
		s = hl->buf;

		/*
		 * Despite hyperenclave should pass a string ending with '\0', we
		 * add a final guard.
		 */
		s[LOGENTRY_SIZE - 1] = '\0';

		/*
		 * API since v0.0.1, 1991
		 * Note that this may overrun kernel's log buffer. Traling spaces for flushing.
		 */
		printk("%s", s);

		/* Make sure load to s is done. */
		WRITE_ONCE(hl->used, false);
	}

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

void he_flush_log(void)
{
	return flush_hv_log_work_func(NULL);
}

int he_init_log(struct hyper_header *header)
{
	int r = 0;

	if (alloc_vmm_check_wq()) {
		if (!vmm_check_wq) {
			he_err("alloc_workqueue failed\n");
			r = -ENOMEM;
			goto out;
		}
	}

	he_log_num = min(max(he_log_num, 64UL), 2048UL);
	he_log = kzalloc(sizeof(struct he_log) +
				 he_log_num * sizeof(struct he_logentry),
			 GFP_KERNEL);
	if (!he_log) {
		r = -ENOMEM;
		goto out;
	}
	he_log->num = he_log_num;
	header->he_log_pa = virt_to_phys(he_log);
	he_info("log buffer size %luKB",
		sizeof(struct he_log) +
			he_log_num * sizeof(struct he_logentry) / 1024);
	/* Vmm stats info */
	vmm_anomaly_cpus = kzalloc(sizeof(*vmm_anomaly_cpus), GFP_KERNEL);
	if (!vmm_anomaly_cpus) {
		r = -ENOMEM;
		goto err;
	}
	he_debug("vmm_anomaly_cpus pa: %llx\n", virt_to_phys(vmm_anomaly_cpus));
	header->vmm_anomaly_cpus_pa = virt_to_phys(vmm_anomaly_cpus);

	register_vmm_check_wq();
	register_flush_hv_log_work();

out:
	return r;

err:
	kfree(he_log);
	return r;
}

int he_deinit_log(void)
{
	deregister_vmm_check_wq();
	dealloc_vmm_check_wq();
	deregister_flush_hv_log_work();

	kfree(vmm_anomaly_cpus);
	vmm_anomaly_cpus = NULL;
	kfree(he_log);
	he_log = NULL;
	return 0;
}
