/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Linux Security Modules (LSM) - User space API
 *
 * Copyright (C) 2022 Casey Schaufler <casey@schaufler-ca.com>
 * Copyright (C) 2022 Intel Corporation
 */

#ifndef _UAPI_LINUX_LSM_H
#define _UAPI_LINUX_LSM_H

/*
 * ID tokens to identify Linux Security Modules (LSMs)
 *
 * These token values are used to uniquely identify specific LSMs
 * in the kernel as well as in the kernel's LSM userspace API.
 *
 * A value of zero/0 is considered undefined and should not be used
 * outside the kernel. Values 1-99 are reserved for potential
 * future use.
 */
#define LSM_ID_UNDEF		0
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
 * LSM_ATTR_XXX definitions identify different LSM attributes
 * which are used in the kernel's LSM userspace API. Support
 * for these attributes vary across the different LSMs. None
 * are required.
 */
#define LSM_ATTR_CURRENT	0x0001
#define LSM_ATTR_EXEC		0x0002
#define LSM_ATTR_FSCREATE	0x0004
#define LSM_ATTR_KEYCREATE	0x0008
#define LSM_ATTR_PREV		0x0010
#define LSM_ATTR_SOCKCREATE	0x0020

#endif /* _UAPI_LINUX_LSM_H */
