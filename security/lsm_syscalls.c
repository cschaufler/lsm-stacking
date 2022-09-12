// SPDX-License-Identifier: GPL-2.0-only
/*
 * System calls implementing the Linux Security Module API.
 *
 *  Copyright (C) 2022 Casey Schaufler <casey@schaufler-ca.com>
 *  Copyright (C) Intel Corporation
 */

#include <asm/current.h>
#include <linux/compiler_types.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/security.h>
#include <linux/stddef.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <uapi/linux/lsm.h>

struct id_map {
	char *name;
	int id;
};

static const struct id_map lsm_attr_names[] = {
	{ "current",	LSM_ATTR_CURRENT, },
	{ "exec",	LSM_ATTR_EXEC, },
	{ "fscreate",	LSM_ATTR_FSCREATE, },
	{ "keycreate",	LSM_ATTR_KEYCREATE, },
	{ "prev",	LSM_ATTR_PREV, },
	{ "sockcreate",	LSM_ATTR_SOCKCREATE, },
};

static const struct id_map lsm_names[] = {
	{ "selinux",	LSM_ID_SELINUX, },
	{ "smack",	LSM_ID_SMACK, },
	{ "tomoyo",	LSM_ID_TOMOYO, },
	{ "ima",	LSM_ID_IMA, },
	{ "apparmor",	LSM_ID_APPARMOR, },
	{ "yama",	LSM_ID_YAMA, },
	{ "loadpin",	LSM_ID_LOADPIN, },
	{ "safesetid",	LSM_ID_SAFESETID, },
	{ "lockdown",	LSM_ID_LOCKDOWN, },
	{ "bpf",	LSM_ID_BPF, },
	{ "landlock",	LSM_ID_LANDLOCK, },
};

/**
 * lsm_self_attr - Return current task's security module attributes
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
	int lsm;
	int len;
	int rc = 0;
	int i;

	interum = kzalloc(ARRAY_SIZE(lsm_attr_names) * ARRAY_SIZE(lsm_names) *
			  sizeof(*interum), GFP_KERNEL);
	if (interum == NULL)
		return -ENOMEM;
	ip = interum;

	interum_ctx = kzalloc(ARRAY_SIZE(lsm_attr_names) *
			      ARRAY_SIZE(lsm_names) * sizeof(*interum_ctx),
			      GFP_KERNEL);
	if (interum_ctx == NULL) {
		kfree(interum);
		return -ENOMEM;
	}

	for (attr = 0; attr < ARRAY_SIZE(lsm_attr_names); attr++) {
		for (lsm = 0; lsm < ARRAY_SIZE(lsm_names); lsm++) {
			len = security_getprocattr(current,
						   lsm_names[lsm].name,
						   lsm_attr_names[attr].name,
						   &cp);
			if (len <= 0)
				continue;

			ip->id = lsm_names[lsm].id;
			ip->flags = lsm_attr_names[attr].id;
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
			 * that to a \0 so that user space does't have to
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
