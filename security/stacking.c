/*
 * Security secid functions
 *
 * Copyright (C) 2018 Casey Schaufler <casey@schaufler-ca.com>
 * Copyright (C) 2018 Intel
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 */
#include <linux/security.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/mutex.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/netlabel.h>

#define	SECMARK_BIT		0x80000000

static LIST_HEAD(secids_list);
u32 next_secid;
struct secids null_secids;
static DEFINE_MUTEX(secids_lock);

bool stacking_inited;

struct secids_entry {
	struct list_head	list;
	struct secids		secids;
};

/*
 * A secids structure contains all of the modules specific
 * secids and the secmark used to represent the combination
 * of module specific secids. Code that uses secmarks won't
 * know or care about module specific secids, and won't have
 * set them in the secids nor will it look at the module specific
 * values. Modules won't care about the secmark. If there's only
 * one module that uses secids the mapping is one-to-one. The
 * general case is not so simple.
 */

void secid_from_skb(struct secids *secid, const struct sk_buff *skb)
{
	struct secids *se;

	if (skb && skb->sk && skb->sk->sk_security) {
		se = skb->sk->sk_security;
		*secid = *se;
	} else {
		*secid = null_secids;
		secid->secmark = skb->secmark;
	}
}
EXPORT_SYMBOL(secid_from_skb);

void secid_to_skb(struct secids *secid, struct sk_buff *skb)
{
	struct secids *se;

	if (skb && skb->sk && skb->sk->sk_security) {
		se = skb->sk->sk_security;
		*se = *secid;
	} else
		skb->secmark = secid->secmark;
}
EXPORT_SYMBOL(secid_to_skb);

void secid_set(struct secids *secid, u32 mark)
{
	struct secids_entry *se;

	if (mark == 0) {
		*secid = null_secids;
		return;
	}
	WARN_ON(!(mark & SECMARK_BIT));
	if (!(mark & SECMARK_BIT))
		pr_info("%s secmark=%d lacking bit\n", __func__, mark);

	list_for_each_entry(se, &secids_list, list)
		if (se->secids.secmark == mark) {
			*secid = se->secids;
			return;
		}

	se = kzalloc(sizeof(*se), GFP_KERNEL);
	if (se == NULL) {
		*secid = null_secids;
		return;
	}

	mutex_lock(&secids_lock);
	se->secids = *secid;
	se->secids.secmark = ++next_secid;

	list_add(&se->list, &secids_list);
	mutex_unlock(&secids_lock);

#ifdef CONFIG_SECURITY_LSM_DEBUG
	pr_info("%s new secmark %08x selinux=%u smack=%u\n", __func__,
		se->secids.secmark, se->secids.selinux, se->secids.smack);
#endif
}

void secid_update_secmark(struct secids *secid)
{
	struct secids_entry *se;

	list_for_each_entry(se, &secids_list, list) {
#ifdef CONFIG_SECURITY_SELINUX
		if (se->secids.selinux != secid->selinux)
			continue;
#endif
#ifdef CONFIG_SECURITY_SMACK
		if (se->secids.smack != secid->smack)
			continue;
#endif
		secid->secmark = se->secids.secmark;
		return;
	}

	se = kzalloc(sizeof(*se), GFP_KERNEL);
	if (se == NULL) {
		secid->secmark = 0;
		return;
	}

	mutex_lock(&secids_lock);
	se->secids = *secid;
	se->secids.secmark = ++next_secid | SECMARK_BIT;
	secid->secmark = se->secids.secmark;

	list_add(&se->list, &secids_list);
	mutex_unlock(&secids_lock);

#ifdef CONFIG_SECURITY_LSM_DEBUG
	pr_info("%s new secmark %08x selinux=%u smack=%u\n", __func__,
		se->secids.secmark, se->secids.selinux, se->secids.smack);
#endif
}

void secid_once_common(struct secids *secid)
{
	struct secids_entry *se;

	list_for_each_entry(se, &secids_list, list) {
#ifdef CONFIG_SECURITY_SELINUX
		if (se->secids.selinux != secid->selinux)
			continue;
#endif
#ifdef CONFIG_SECURITY_SMACK
		if (se->secids.smack != secid->smack)
			continue;
#endif
		secid->secmark = se->secids.secmark;
		return;
	}

	mutex_lock(&secids_lock);
	secid->secmark = ++next_secid | SECMARK_BIT;
	mutex_unlock(&secids_lock);

#ifdef CONFIG_SECURITY_LSM_DEBUG
	pr_info("%s new secmark %08x selinux=%u smack=%u\n", __func__,
		se->secids.secmark, se->secids.selinux, se->secids.smack);
#endif
}

bool secid_valid(const struct secids *secid)
{
#ifdef CONFIG_SECURITY_SELINUX
	if (secid->selinux)
		return true;
#endif
#ifdef CONFIG_SECURITY_SMACK
	if (secid->smack)
		return true;
#endif
	return false;
}

#ifdef CONFIG_NETLABEL
/**
 * lsm_sock_vet_attr - does the netlabel agree with what other LSMs want
 * @sk: the socket in question
 * @secattr: the desired netlabel security attributes
 * @flags: which LSM is making the request
 *
 * Determine whether the calling LSM can set the security attributes
 * on the socket without interferring with what has already been set
 * by other LSMs. The first LSM calling will always be allowed. An
 * LSM that resets itself will also be allowed. It will require careful
 * configuration for any other case to succeed.
 *
 * If @secattr is NULL the check is for deleting the attribute.
 *
 * Returns 0 if there is agreement, -EACCES if there is conflict,
 * and any error from the netlabel system.
 */
int lsm_sock_vet_attr(struct sock *sk, struct netlbl_lsm_secattr *secattr,
		      u32 flags)
{
	struct secids *se = sk->sk_security;
	struct netlbl_lsm_secattr asis;
	int rc;

	/*
	 * First in always shows as allowed.
	 * Changing what this module has set is OK, too.
	 */
	if (se->flags == 0 || se->flags == flags) {
		se->flags = flags;
		return 0;
	}

	netlbl_secattr_init(&asis);
	rc = netlbl_sock_getattr(sk, &asis);

	switch (rc) {
	case 0:
		/*
		 * Can't delete another modules's attributes or
		 * change them if they don't match well enough.
		 */
		if (secattr == NULL || !netlbl_secattr_equal(secattr, &asis))
			rc = -EACCES;
		else
			se->flags = flags;
		break;
	case -ENOMSG:
		se->flags = flags;
		rc = 0;
		break;
	default:
		break;
	}
	netlbl_secattr_destroy(&asis);
	return rc;
}
#endif /* CONFIG_NETLABEL */
