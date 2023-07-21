/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Linux Security Module interface to other subsystems.
 * The secmark is a u32 value.
 */
#ifndef __LINUX_LSM_SECMARK_H
#define __LINUX_LSM_SECMARK_H
#include <linux/types.h>

struct lsmblob_secmark {
#ifdef CONFIG_SECURITY_NETWORK
	u32 secid;
#endif
};

#endif /* ! __LINUX_LSM_SECMARK_H */
