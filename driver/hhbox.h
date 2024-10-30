/* SPDX-License-Identifier: GPL-2.0 */
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#ifndef _DRIVER_HHBOX_H
#define _DRIVER_HHBOX_H

#include <linux/cpumask.h>
#include <linux/workqueue.h>

#include <hyperenclave/header.h>

#define HHBOX_LOG_HEARTBEAT_MS_DEFAULT 10
#define HHBOX_CRASH_HEARTBEAT_MS 1000

void he_flush_log(void);
int he_init_log(struct hyper_header *header);
int he_deinit_log(void);

#define LOGENTRY_SIZE 160
#define LOG_SIZE_DEFAULT 512

struct he_logentry {
	char buf[LOGENTRY_SIZE];
	bool used;
};

struct he_log {
	uint32_t log_lost;
	ulong num;
	struct he_logentry log[0];
};

#endif
