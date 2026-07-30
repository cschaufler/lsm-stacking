// SPDX-License-Identifier: GPL-2.0-or-later

/*
 * Implement functions supporting an x array for LSM properties.
 *
 * Copyright (C) 2026 Casey Schaufler <casey@schaufler-ca.com>
 */
#define pr_fmt(fmt) "secxa: "fmt

#include <linux/xarray.h>
#include <linux/export.h>
#include <linux/security.h>
#include <linux/lsm_secxa.h>
#include <linux/skbuff.h>

/*
 * An Xarray of lsm_prop structures.
 */
struct xarray secxa_xa;

/**
 * secxa_init - initialize the xarry of lsm_prop structures.
 */
static int __init secxa_init(void)
{
	xa_init_flags(&secxa_xa, XA_FLAGS_ALLOC1);

	return 0;
}
core_initcall(secxa_init);

/**
 * secxa_get_lsmprop - get the lsm_prop associated with a secxa
 * @pro: destination for the lsm_prop pointer
 * @secxa: index to look up
 *
 * Find the lsm_prop associated with @secxa and place a pointer
 * to it in @pro.
 *
 * Returns 0, or -EINVAL if the mapping can't be found.
 */
int secxa_get_lsmprop(struct lsm_prop **pro, u32 secxa)
{
	struct lsm_prop *lp;

	if (!secxa)
		return -EINVAL;

	lp = xa_load(&secxa_xa, secxa);
	if (!lp)
		return -EINVAL;

	*pro = lp;
	return 0;
}
EXPORT_SYMBOL(secxa_get_lsmprop);

/**
 * secxa_from_lsmprop - get the secxa associated with a lsm_prop
 * @prop: lsm_prop pointer
 *
 * Find the secxa associated with @prop. If there is none, create it.
 *
 * Returns 0, or an error if the mapping cannot be created
 */
int secxa_from_lsmprop(struct lsm_prop *prop)
{
	struct lsm_prop *lp;
	unsigned long il;
	unsigned int index = 0;
	int rc;

	xa_for_each(&secxa_xa, il, lp) {
		if (!memcmp(prop, lp, sizeof(*prop)))
			pr_info("%s found at index %lu\n", __func__, il);
		if (!memcmp(prop, lp, sizeof(*prop)))
			return il;
	}

	lp = kzalloc(sizeof(*lp), GFP_ATOMIC);
	if (!lp)
		return -ENOMEM;

	rc = xa_alloc(&secxa_xa, &index, lp, xa_limit_32b, GFP_ATOMIC);
	if (rc) {
		kfree(lp);
		return -EINVAL;
	}
	*lp = *prop;

	return index;
}
EXPORT_SYMBOL(secxa_from_lsmprop);

/**
 * secxa_set_secmark - add LSM information to a secmark
 * @skb: buffer with the secmark
 * @secxa: index of the information to add
 *
 * If the secmark in @skb is not set, set it to @secxa.
 */
void secxa_set_secmark(struct sk_buff *skb, u32 secxa)
{
	if (!skb->secmark)
		skb->secmark = secxa;
}
EXPORT_SYMBOL(secxa_set_secmark);
