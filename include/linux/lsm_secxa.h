/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (C) 2026 Casey Schaufler <casey@schaufler-ca.com>
 */

#ifndef __LINUX_LSM_SECXA_H
#define __LINUX_LSM_SECXA_H

#ifdef CONFIG_SECURITY

#include <linux/security.h>

struct sk_buff;

int secxa_from_lsmprop(struct lsm_prop *prop);
int secxa_get_lsmprop(struct lsm_prop **pro, u32 secxa);
void secxa_set_secmark(struct sk_buff *skb, u32 secxa);

#endif /* CONFIG_SECURITY */

#endif  /* __LINUX_LSM_SECXA_H */
