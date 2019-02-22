/*
 *  Simplified MAC Kernel (smack) security module
 *
 *  This file contains the Smack netfilter implementation
 *
 *  Author:
 *	Casey Schaufler <casey@schaufler-ca.com>
 *
 *  Copyright (C) 2014 Casey Schaufler <casey@schaufler-ca.com>
 *  Copyright (C) 2014 Intel Corporation.
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License version 2,
 *	as published by the Free Software Foundation.
 */

#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/netdevice.h>
#include <net/inet_sock.h>
#include <net/net_namespace.h>
#include "smack.h"

bool smack_use_secmark;
static bool smack_checked_secmark;

void smack_secmark_refcount_inc(void)
{
	smack_use_secmark = true;
	pr_info("Smack: Using network secmarks.\n");
}

static void smack_own_secmark(void)
{
	if (!smack_checked_secmark) {
		security_secmark_refcount_inc();
		security_secmark_refcount_dec();
		smack_checked_secmark = true;
	}
}

#if IS_ENABLED(CONFIG_IPV6)

static unsigned int smack_ipv6_output(void *priv,
					struct sk_buff *skb,
					const struct nf_hook_state *state)
{
	struct sock *sk = skb_to_full_sk(skb);
	struct socket_smack *ssp;
	struct smack_known *skp;

	smack_own_secmark();

	if (smack_use_secmark && sk && smack_sock(sk)) {
		ssp = smack_sock(sk);
		skp = ssp->smk_out;
		skb->secmark = skp->smk_secid;
	}

	return NF_ACCEPT;
}
#endif	/* IPV6 */

static unsigned int smack_ipv4_output(void *priv,
					struct sk_buff *skb,
					const struct nf_hook_state *state)
{
	struct sock *sk = skb_to_full_sk(skb);
	struct socket_smack *ssp;
	struct smack_known *skp;
	int rc = 0;

	smack_own_secmark();

	if (sk == NULL)
		return NF_ACCEPT;

	ssp = smack_sock(sk);
	if (ssp == NULL)
		return NF_ACCEPT;

	skp = ssp->smk_out;
	if (smack_use_secmark)
		skb->secmark = skp->smk_secid;

	if (ssp->smk_set == NETLBL_NLTYPE_ADDRSELECT) {
		rc = netlbl_skbuff_setattr(skb, PF_INET, &skp->smk_netlabel);
		if (rc < 0)
			return NF_DROP;
		ssp->smk_set = rc;
	}

	return NF_ACCEPT;
}

static const struct nf_hook_ops smack_nf_ops[] = {
	{
		.hook =		smack_ipv4_output,
		.pf =		NFPROTO_IPV4,
		.hooknum =	NF_INET_LOCAL_OUT,
		.priority =	NF_IP_PRI_SELINUX_FIRST,
	},
#if IS_ENABLED(CONFIG_IPV6)
	{
		.hook =		smack_ipv6_output,
		.pf =		NFPROTO_IPV6,
		.hooknum =	NF_INET_LOCAL_OUT,
		.priority =	NF_IP6_PRI_SELINUX_FIRST,
	},
#endif	/* IPV6 */
};

static int __net_init smack_nf_register(struct net *net)
{
	return nf_register_net_hooks(net, smack_nf_ops,
				     ARRAY_SIZE(smack_nf_ops));
}

static void __net_exit smack_nf_unregister(struct net *net)
{
	nf_unregister_net_hooks(net, smack_nf_ops, ARRAY_SIZE(smack_nf_ops));
}

static struct pernet_operations smack_net_ops = {
	.init = smack_nf_register,
	.exit = smack_nf_unregister,
};

static int __init smack_nf_ip_init(void)
{
	if (smack_enabled == 0)
		return 0;

	printk(KERN_DEBUG "Smack: Registering netfilter hooks\n");
	return register_pernet_subsys(&smack_net_ops);
}

__initcall(smack_nf_ip_init);
