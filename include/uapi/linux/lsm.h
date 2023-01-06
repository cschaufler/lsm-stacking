/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Linux Security Modules (LSM) - User space API
 *
 * Copyright (C) 2022 Casey Schaufler <casey@schaufler-ca.com>
 * Copyright (C) 2022 Intel Corporation
 */

#ifndef _UAPI_LINUX_LSM_H
#define _UAPI_LINUX_LSM_H

#include <linux/types.h>
#include <linux/unistd.h>

/**
 * struct lsm_ctx - LSM context
 * @id: the LSM id number, see LSM_ID_XXX
 * @flags: context specifier and LSM specific flags
 * @ctx_len: the size of @ctx
 * @ctx: the LSM context, a nul terminated string
 *
 * @ctx in a nul terminated string.
 *	(strlen(@ctx) < @ctx_len) is always true.
 *	(strlen(@ctx) == @ctx_len + 1) is not guaranteed.
 */
struct lsm_ctx {
	__u32		id;
	__u64		flags;
	__kernel_size_t	ctx_len;
	__u8		ctx[];
};

/*
 * ID values to identify security modules.
 * A system may use more than one security module.
 *
 * A value of 0 is considered invalid.
 * Values 1-99 are reserved for future use.
 * The interface is designed to extend to attributes beyond those which
 * are active today. Currently all the attributes are specific to the
 * individual modules. The LSM infrastructure itself has no variable state,
 * but that may change. One proposal would allow loadable modules, in which
 * case an attribute such as LSM_IS_LOADABLE might identify the dynamic
 * modules. Another potential attribute could be which security modules is
 * associated withnetwork labeling using netlabel. Another possible attribute
 * could be related to stacking behavior in a namespaced environment.
 * While it would be possible to intermingle the LSM infrastructure attribute
 * values with the security module provided values, keeping them separate
 * provides a clearer distinction.
 */
#define LSM_ID_CAPABILITY	100
#define LSM_ID_SELINUX		101
#define LSM_ID_SMACK		102
#define LSM_ID_TOMOYO		103
#define LSM_ID_IMA		104
#define LSM_ID_APPARMOR		105
#define LSM_ID_YAMA		106
#define LSM_ID_LOADPIN		107
#define LSM_ID_SAFESETID	108
#define LSM_ID_LOCKDOWN		109
#define LSM_ID_BPF		110
#define LSM_ID_LANDLOCK		111

/*
 * LSM_ATTR_XXX values identify the /proc/.../attr entry that the
 * context represents. Not all security modules provide all of these
 * values. Some security modules provide none of them.
 */
#define LSM_ATTR_CURRENT	0x0001
#define LSM_ATTR_EXEC		0x0002
#define LSM_ATTR_FSCREATE	0x0004
#define LSM_ATTR_KEYCREATE	0x0008
#define LSM_ATTR_PREV		0x0010
#define LSM_ATTR_SOCKCREATE	0x0020

#endif /* _UAPI_LINUX_LSM_H */
