// SPDX-License-Identifier: GPL-2.0
/*
 * Linux Security Module infrastructure tests
 * Tests for the lsm_module_list system call
 *
 * Copyright © 2022 Casey Schaufler <casey@schaufler-ca.com>
 * Copyright © 2022 Intel Corporation
 */

#define _GNU_SOURCE
#include <linux/lsm.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include "../kselftest_harness.h"

static int read_sysfs_lsms(char *lsms, __kernel_size_t size)
{
	FILE *fp;

	fp = fopen("/sys/kernel/security/lsm", "r");
	if (fp == NULL)
		return -1;
	if (fread(lsms, 1, size, fp) <= 0)
		return -1;
	fclose(fp);
	return 0;
}

TEST(size_null_lsm_module_list)
{
	const long page_size = sysconf(_SC_PAGESIZE);
	char *syscall_lsms = calloc(page_size, 1);

	ASSERT_NE(NULL, syscall_lsms);
	ASSERT_EQ(-1, syscall(__NR_lsm_module_list, syscall_lsms, NULL, 0));
	ASSERT_EQ(EFAULT, errno);

	free(syscall_lsms);
}

TEST(ids_null_lsm_module_list)
{
	const long page_size = sysconf(_SC_PAGESIZE);
	__kernel_size_t size = page_size;

	ASSERT_EQ(-1, syscall(__NR_lsm_module_list, NULL, &size, 0));
	ASSERT_EQ(EFAULT, errno);
	ASSERT_NE(1, size);
}

TEST(size_too_small_lsm_module_list)
{
	const long page_size = sysconf(_SC_PAGESIZE);
	char *syscall_lsms = calloc(page_size, 1);
	__kernel_size_t size = 1;

	ASSERT_NE(NULL, syscall_lsms);
	ASSERT_EQ(-1, syscall(__NR_lsm_module_list, syscall_lsms, &size, 0));
	ASSERT_EQ(E2BIG, errno);
	ASSERT_NE(1, size);

	free(syscall_lsms);
}

TEST(flags_set_lsm_module_list)
{
	const long page_size = sysconf(_SC_PAGESIZE);
	char *syscall_lsms = calloc(page_size, 1);
	__kernel_size_t size = page_size;

	ASSERT_NE(NULL, syscall_lsms);
	ASSERT_EQ(-1, syscall(__NR_lsm_module_list, syscall_lsms, &size, 7));
	ASSERT_EQ(EINVAL, errno);
	ASSERT_EQ(page_size, size);

	free(syscall_lsms);
}

TEST(correct_lsm_module_list)
{
	const long page_size = sysconf(_SC_PAGESIZE);
	__kernel_size_t size = page_size;
	__u32 *syscall_lsms = calloc(page_size, 1);
	char *sysfs_lsms = calloc(page_size, 1);
	char *name;
	char *cp;
	int count;
	int i;

	ASSERT_NE(NULL, sysfs_lsms);
	ASSERT_NE(NULL, syscall_lsms);
	ASSERT_EQ(0, read_sysfs_lsms(sysfs_lsms, page_size));

	count = syscall(__NR_lsm_module_list, syscall_lsms, &size, 0);
	ASSERT_LE(1, count);
	cp = sysfs_lsms;
	for (i = 0; i < count; i++) {
		switch (syscall_lsms[i]) {
		case LSM_ID_CAPABILITY:
			name = "capability";
			break;
		case LSM_ID_SELINUX:
			name = "selinux";
			break;
		case LSM_ID_SMACK:
			name = "smack";
			break;
		case LSM_ID_TOMOYO:
			name = "tomoyo";
			break;
		case LSM_ID_IMA:
			name = "ima";
			break;
		case LSM_ID_APPARMOR:
			name = "apparmor";
			break;
		case LSM_ID_YAMA:
			name = "yama";
			break;
		case LSM_ID_LOADPIN:
			name = "loadpin";
			break;
		case LSM_ID_SAFESETID:
			name = "safesetid";
			break;
		case LSM_ID_LOCKDOWN:
			name = "lockdown";
			break;
		case LSM_ID_BPF:
			name = "bpf";
			break;
		case LSM_ID_LANDLOCK:
			name = "landlock";
			break;
		default:
			name = "INVALID";
			break;
		}
		ASSERT_EQ(0, strncmp(cp, name, strlen(name)));
		cp += strlen(name) + 1;
	}

	free(sysfs_lsms);
	free(syscall_lsms);
}

TEST_HARNESS_MAIN
