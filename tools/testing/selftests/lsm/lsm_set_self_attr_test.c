// SPDX-License-Identifier: GPL-2.0
/*
 * Linux Security Module infrastructure tests
 * Tests for the lsm_set_self_attr system call
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

TEST(ctx_null_lsm_set_self_attr)
{
	ASSERT_EQ(-1, syscall(__NR_lsm_set_self_attr, NULL,
			      sizeof(struct lsm_ctx), LSM_ATTR_CURRENT));
}

TEST(size_too_small_lsm_set_self_attr)
{
	const long page_size = sysconf(_SC_PAGESIZE);
	struct lsm_ctx *ctx = calloc(page_size, 1);
	__kernel_size_t size = page_size;

	ASSERT_NE(NULL, ctx);
	ASSERT_GE(1, syscall(__NR_lsm_get_self_attr, ctx, &size,
			     LSM_ATTR_CURRENT));
	ASSERT_EQ(-1, syscall(__NR_lsm_set_self_attr, ctx, 1,
			      LSM_ATTR_CURRENT));

	free(ctx);
}

TEST(flags_zero_lsm_set_self_attr)
{
	const long page_size = sysconf(_SC_PAGESIZE);
	char *ctx = calloc(page_size, 1);
	__kernel_size_t size = page_size;

	ASSERT_NE(NULL, ctx);
	ASSERT_GE(1, syscall(__NR_lsm_get_self_attr, ctx, &size,
			     LSM_ATTR_CURRENT));
	ASSERT_EQ(-1, syscall(__NR_lsm_set_self_attr, ctx, size, 0));

	free(ctx);
}

TEST(flags_overset_lsm_set_self_attr)
{
	const long page_size = sysconf(_SC_PAGESIZE);
	char *ctx = calloc(page_size, 1);
	__kernel_size_t size = page_size;
	struct lsm_ctx *tctx = (struct lsm_ctx *)ctx;

	ASSERT_NE(NULL, ctx);
	ASSERT_GE(1, syscall(__NR_lsm_get_self_attr, tctx, &size,
			     LSM_ATTR_CURRENT));
	ASSERT_EQ(-1, syscall(__NR_lsm_set_self_attr, tctx, size,
			      LSM_ATTR_CURRENT | LSM_ATTR_PREV));

	free(ctx);
}

TEST_HARNESS_MAIN
