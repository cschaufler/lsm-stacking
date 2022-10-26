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
 * ID values to identify security modules.
 * A system may use more than one security module.
 */
#define LSM_ID_INVALID		0
#define LSM_ID_CAPABILITY	1
#define LSM_ID_SELINUX		2
#define LSM_ID_SMACK		3
#define LSM_ID_TOMOYO		4
#define LSM_ID_IMA		5
#define LSM_ID_APPARMOR		6
#define LSM_ID_YAMA		7
#define LSM_ID_LOADPIN		8
#define LSM_ID_SAFESETID	9
#define LSM_ID_LOCKDOWN		10
#define LSM_ID_BPF		11
#define LSM_ID_LANDLOCK		12

#endif /* _UAPI_LINUX_LSM_H */
