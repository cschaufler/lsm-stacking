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

struct attrs_used_map {
	char *name;
	int attrs_used;
};

static const struct attrs_used_map lsm_attr_names[] = {
	{ .name = "current",	.attrs_used = LSM_ATTR_CURRENT, },
	{ .name = "exec",	.attrs_used = LSM_ATTR_EXEC, },
	{ .name = "fscreate",	.attrs_used = LSM_ATTR_FSCREATE, },
	{ .name = "keycreate",	.attrs_used = LSM_ATTR_KEYCREATE, },
	{ .name = "prev",	.attrs_used = LSM_ATTR_PREV, },
	{ .name = "sockcreate",	.attrs_used = LSM_ATTR_SOCKCREATE, },
};

static int attr_used_index(u32 flags)
{
	int i;

	if (flags == 0)
		return -EINVAL;

	for (i = 0; i < ARRAY_SIZE(lsm_attr_names); i++)
		if ((lsm_attr_names[i].attrs_used & flags) == flags)
			return i;

	return -EINVAL;
}

/**
 * sys_lsm_get_self_attr - Return current task's security module attributes
 * @ctx: the LSM contexts
 * @size: size of @ctx, updated on return
 * @flags: which attribute to return
 *
 * Returns the calling task's LSM contexts. On success this
 * function returns the number of @ctx array elements. This value
 * may be zero if there are no LSM contexts assigned. If @size is
 * insufficient to contain the return data -E2BIG is returned and
 * @size is set to the minimum required size. In all other cases
 * a negative value indicating the error is returned.
 */
SYSCALL_DEFINE3(lsm_get_self_attr,
		struct lsm_ctx __user *, ctx,
		size_t __user *, size,
		u32, flags)
{
	int i;
	int rc = 0;
	int len;
	int attr;
	int count = 0;
	void *curr;
	char *cp;
	char *np;
	char **interum_ctx;
	size_t total_size = 0;
	struct lsm_ctx *ip;
	struct lsm_ctx *interum;
	struct lsm_ctx *final = NULL;

	attr = attr_used_index(flags);
	if (attr < 0)
		return attr;

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

	for (i = 0; i < lsm_active_cnt; i++) {
		if ((lsm_idlist[i]->attrs_used &
		     lsm_attr_names[attr].attrs_used) == 0)
			continue;

		len = security_getprocattr(current, lsm_idlist[i]->id,
					   lsm_attr_names[attr].name,
					   &cp);
		if (len <= 0)
			continue;

		ip->id = lsm_idlist[i]->id;
		ip->flags = lsm_attr_names[attr].attrs_used;
		interum_ctx[count] = cp;

		/*
		 * A security module that returns a binary attribute
		 * will need to identify itself to prevent string
		 * processing.
		 *
		 * At least one security module adds a \n at the
		 * end of a context to make it look nicer. Change
		 * that to a \0 so that user space doesn't have to
		 * work around it.
		 *
		 * Security modules have been inconsistent about
		 * including the \0 terminator in the size. If it's
		 * not there make space for it.
		 *
		 * The length returned will reflect the length of
		 * the string provided by the security module, which
		 * may not match what getprocattr returned.
		 */
		np = strnchr(cp, len, '\n');
		if (np != NULL)
			*np = '\0';
		ip->ctx_len = strnlen(cp, len) + 1;
		total_size += sizeof(*interum) + ip->ctx_len;
		ip++;
		count++;
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
		if (ip->ctx_len > 1)
			memcpy(curr, interum_ctx[i], ip->ctx_len - 1);
		curr += ip->ctx_len;
		ip++;
	}

	if (get_user(len, size)) {
		rc = -EFAULT;
		goto free_out;
	}
	if (total_size > len) {
		rc = -ERANGE;
		if (put_user(total_size, size) != 0)
			rc = -EFAULT;
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

/**
 * sys_lsm_module_list - Return a list of the active security modules
 * @ids: the LSM module ids
 * @size: size of @ids, updated on return
 * @flags: reserved for future use, must be zero
 *
 * Returns a list of the active LSM ids. On success this function
 * returns the number of @ids array elements. This value may be zero
 * if there are no LSMs active. If @size is insufficient to contain
 * the return data -E2BIG is returned and @size is set to the minimum
 * required size. In all other cases a negative value indicating the
 * error is returned.
 */
SYSCALL_DEFINE3(lsm_module_list,
		u32 __user *, ids,
		size_t __user *, size,
		u64, flags)
{
	size_t total_size = lsm_active_cnt * sizeof(*ids);
	size_t usize;
	int i;

	if (flags)
		return -EINVAL;

	if (get_user(usize, size))
		return -EFAULT;

	if (put_user(total_size, size) != 0)
		return -EFAULT;

	if (usize < total_size)
		return -E2BIG;

	for (i = 0; i < lsm_active_cnt; i++)
		if (put_user(lsm_idlist[i]->id, ids++))
			return -EFAULT;

	return lsm_active_cnt;
}
