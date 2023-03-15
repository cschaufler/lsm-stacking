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

struct attr_map {
	char *name;
	u64 attr;
};

static const struct attr_map lsm_attr_names[] = {
	{
		.name = "current",
		.attr = LSM_ATTR_CURRENT,
	},
	{
		.name = "exec",
		.attr = LSM_ATTR_EXEC,
	},
	{
		.name = "fscreate",
		.attr = LSM_ATTR_FSCREATE,
	},
	{
		.name = "keycreate",
		.attr = LSM_ATTR_KEYCREATE,
	},
	{
		.name = "prev",
		.attr = LSM_ATTR_PREV,
	},
	{
		.name = "sockcreate",
		.attr = LSM_ATTR_SOCKCREATE,
	},
};

/**
 * lsm_name_to_attr - map an LSM attribute name to its ID
 * @name: name of the attribute
 *
 * Look the given @name up in the table of know attribute names.
 *
 * Returns the LSM attribute value associated with @name, or 0 if
 * there is no mapping.
 */
u64 lsm_name_to_attr(const char *name)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(lsm_attr_names); i++)
		if (!strcmp(name, lsm_attr_names[i].name))
			return lsm_attr_names[i].attr;
	return 0;
}

/**
 * sys_lsm_set_self_attr - Set current task's security module attribute
 * @attr: which attribute to set
 * @ctx: the LSM contexts
 * @size: size of @ctx
 * @flags: reserved for future use
 *
 * Sets the calling task's LSM context. On success this function
 * returns 0. If the attribute specified cannot be set a negative
 * value indicating the reason for the error is returned.
 */
SYSCALL_DEFINE4(lsm_set_self_attr, unsigned int, attr, struct lsm_ctx __user *,
		ctx, size_t __user, size, u32, flags)
{
	return security_setselfattr(attr, ctx, size, flags);
}

/**
 * sys_lsm_get_self_attr - Return current task's security module attributes
 * @attr: which attribute to set
 * @ctx: the LSM contexts
 * @size: size of @ctx, updated on return
 * @flags: reserved for future use
 *
 * Returns the calling task's LSM contexts. On success this
 * function returns the number of @ctx array elements. This value
 * may be zero if there are no LSM contexts assigned. If @size is
 * insufficient to contain the return data -E2BIG is returned and
 * @size is set to the minimum required size. In all other cases
 * a negative value indicating the error is returned.
 */
SYSCALL_DEFINE4(lsm_get_self_attr, unsigned int, attr, struct lsm_ctx __user *,
		ctx, size_t __user *, size, u32, flags)
{
	return security_getselfattr(attr, ctx, size, flags);
}

/**
 * sys_lsm_list_modules - Return a list of the active security modules
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
SYSCALL_DEFINE3(lsm_list_modules, u64 __user *, ids, size_t __user *, size,
		u32, flags)
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
