// SPDX-License-Identifier: GPL-2.0-only
/*
 * System calls implementing the Linux Security Module API.
 *
 *  Copyright (C) 2022 Casey Schaufler <casey@schaufler-ca.com>
 *  Copyright (C) 2022 Intel Corporation
 */

#include <asm/current.h>
#include <linux/compiler_types.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/security.h>
#include <linux/stddef.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/lsm_hooks.h>
#include <uapi/linux/lsm.h>

struct feature_map {
	char *name;
	int feature;
};

static const struct feature_map lsm_attr_names[] = {
	{ .name = "current",	.feature = LSM_ATTR_CURRENT, },
	{ .name = "exec",	.feature = LSM_ATTR_EXEC, },
	{ .name = "fscreate",	.feature = LSM_ATTR_FSCREATE, },
	{ .name = "keycreate",	.feature = LSM_ATTR_KEYCREATE, },
	{ .name = "prev",	.feature = LSM_ATTR_PREV, },
	{ .name = "sockcreate",	.feature = LSM_ATTR_SOCKCREATE, },
};

/**
 * sys_lsm_self_attr - Return current task's security module attributes
 * @ctx: the LSM contexts
 * @size: size of @ctx, updated on return
 * @flags: reserved for future use, must be zero
 *
 * Returns the calling task's LSM contexts. On success this
 * function returns the number of @ctx array elements. This value
 * may be zero if there are no LSM contexts assigned. If @size is
 * insufficient to contain the return data -E2BIG is returned and
 * @size is set to the minimum required size. In all other cases
 * a negative value indicating the error is returned.
 */
SYSCALL_DEFINE3(lsm_self_attr,
		struct lsm_ctx __user *, ctx,
		size_t __user *, size,
		int, flags)
{
	struct lsm_ctx *final = NULL;
	struct lsm_ctx *interum;
	struct lsm_ctx *ip;
	void *curr;
	char **interum_ctx;
	char *cp;
	size_t total_size = 0;
	int count = 0;
	int attr;
	int len;
	int rc = 0;
	int i;

	interum = kzalloc(ARRAY_SIZE(lsm_attr_names) * lsm_active_cnt *
			  sizeof(*interum), GFP_KERNEL);
	if (interum == NULL)
		return -ENOMEM;
	ip = interum;

	interum_ctx = kzalloc(ARRAY_SIZE(lsm_attr_names) * lsm_active_cnt *
			      sizeof(*interum_ctx), GFP_KERNEL);
	if (interum_ctx == NULL) {
		kfree(interum);
		return -ENOMEM;
	}

	for (attr = 0; attr < ARRAY_SIZE(lsm_attr_names); attr++) {
		for (i = 0; i < lsm_active_cnt; i++) {
			if ((lsm_idlist[i]->features &
			     lsm_attr_names[attr].feature) == 0)
				continue;

			len = security_getprocattr(current, lsm_idlist[i]->id,
						   lsm_attr_names[attr].name,
						   &cp);
			if (len <= 0)
				continue;

			ip->id = lsm_idlist[i]->id;
			ip->flags = lsm_attr_names[attr].feature;
			/* space for terminating \0 is allocated below */
			ip->ctx_len = len + 1;
			interum_ctx[count] = cp;
			/*
			 * Security modules have been inconsistent about
			 * including the \0 terminator in the size. The
			 * context len has been adjusted to ensure there
			 * is one.
			 * At least one security module adds a \n at the
			 * end of a context to make it look nicer. Change
			 * that to a \0 so that user space doesn't have to
			 * work around it. Because of this meddling it is
			 * safe to assume that lsm_ctx.name is terminated
			 * and that strlen(lsm_ctx.name) < lsm.ctx_len.
			 */
			total_size += sizeof(*interum) + ip->ctx_len;
			cp = strnchr(cp, len, '\n');
			if (cp != NULL)
				*cp = '\0';
			ip++;
			count++;
		}
	}

	if (count == 0)
		goto free_out;

	final = kzalloc(total_size, GFP_KERNEL);
	if (final == NULL) {
		rc = -ENOMEM;
		goto free_out;
	}

	curr = final;
	ip = interum;
	for (i = 0; i < count; i++) {
		memcpy(curr, ip, sizeof(*interum));
		curr += sizeof(*interum);
		memcpy(curr, interum_ctx[i], ip->ctx_len);
		curr += ip->ctx_len;
		ip++;
	}

	if (get_user(len, size)) {
		rc = -EFAULT;
		goto free_out;
	}
	if (total_size > len) {
		rc = -ERANGE;
		goto free_out;
	}
	if (copy_to_user(ctx, final, total_size) != 0 ||
	    put_user(total_size, size) != 0)
		rc = -EFAULT;
	else
		rc = count;

free_out:
	for (i = 0; i < count; i++)
		kfree(interum_ctx[i]);
	kfree(interum_ctx);
	kfree(interum);
	kfree(final);
	return rc;
}
