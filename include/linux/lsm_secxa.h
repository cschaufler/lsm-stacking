/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (C) 2026 Casey Schaufler <casey@schaufler-ca.com>
 */

#ifndef __LINUX_LSM_SECXA_H
#define __LINUX_LSM_SECXA_H

#ifdef CONFIG_SECURITY

struct lsm_prop;

int secxa_from_lsmprop(struct lsm_prop *prop, u32 *secxa);
int secxa_get_lsmprop(struct lsm_prop **pro, u32 secxa);

#endif /* CONFIG_SECURITY */

#ifdef CONFIG_NETWORK_SECMARK

struct sk_buff;

void secxa_set_secmark(struct sk_buff *skb, u32 secxa);
#else /* CONFIG_NETWORK_SECMARK */

static inline void secxa_set_secmark(struct sk_buff *skb, u32 secxa)
{
}
#endif /* CONFIG_NETWORK_SECMARK */

#endif  /* __LINUX_LSM_SECXA_H */
