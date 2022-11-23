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

static struct lsm_ctx *next_ctx(struct lsm_ctx *tctx)
{
	void *vp;

	vp = (void *)tctx + sizeof(*tctx) + tctx->ctx_len;
	return (struct lsm_ctx *)vp;
}

TEST(ctx_null_lsm_set_self_attr)
{
	ASSERT_EQ(-1, syscall(__NR_lsm_set_self_attr, NULL, _SC_PAGESIZE,
			      LSM_ATTR_CURRENT));
	ASSERT_EQ(EFAULT, errno);
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
	ASSERT_EQ(EINVAL, errno);

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
	ASSERT_EQ(EINVAL, errno);

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
	ASSERT_EQ(EINVAL, errno);

	free(ctx);
}

TEST(basic_lsm_set_self_attr)
{
	const long page_size = sysconf(_SC_PAGESIZE);
	__kernel_size_t size = page_size;
	struct lsm_ctx *ctx = calloc(page_size, 1);
	struct lsm_ctx *tctx;
	__u32 *syscall_lsms = calloc(page_size, 1);
	char *attr = calloc(page_size, 1);
	bool active_apparmor = false;
	bool active_selinux = false;
	bool active_smack = false;
	int cnt_current = 0;
	int cnt_exec = 0;
	int cnt_fscreate = 0;
	int cnt_keycreate = 0;
	int cnt_prev = 0;
	int cnt_sockcreate = 0;
	int lsmcount;
	int count;
	int rc;
	int i;

	ASSERT_NE(NULL, ctx);
	ASSERT_NE(NULL, syscall_lsms);

	lsmcount = syscall(__NR_lsm_module_list, syscall_lsms, &size, 0);
	ASSERT_LE(1, lsmcount);

	for (i = 0; i < lsmcount; i++) {
		switch (syscall_lsms[i]) {
		case LSM_ID_SELINUX:
			active_selinux = true;
			cnt_current++;
			cnt_exec++;
			cnt_fscreate++;
			cnt_keycreate++;
			cnt_prev++;
			cnt_sockcreate++;
			break;
		case LSM_ID_SMACK:
			active_smack = true;
			cnt_current++;
			break;
		case LSM_ID_APPARMOR:
			active_apparmor = true;
			cnt_current++;
			cnt_exec++;
			cnt_prev++;
			break;
		default:
			break;
		}
	}

	if (cnt_current) {
		size = page_size;
		count = syscall(__NR_lsm_get_self_attr, ctx, &size,
				LSM_ATTR_CURRENT);
		ASSERT_EQ(cnt_current, count);
		tctx = ctx;

		for (i = 0; i < count; i++) {
			switch (tctx->id) {
			case LSM_ID_SELINUX:
				ASSERT_EQ(active_selinux, true);
				rc = syscall(__NR_lsm_set_self_attr, tctx, size,
					     LSM_ATTR_CURRENT);
				ASSERT_EQ(0, rc);
				tctx->ctx[0] = 'X';
				rc = syscall(__NR_lsm_set_self_attr, tctx, size,
					     LSM_ATTR_CURRENT);
				ASSERT_EQ(-1, rc);
				ASSERT_EQ(EINVAL, errno);
				break;
			case LSM_ID_SMACK:
				ASSERT_EQ(active_smack, true);
				rc = syscall(__NR_lsm_set_self_attr, tctx, size,
					     LSM_ATTR_CURRENT);
				ASSERT_EQ(-1, rc);
				ASSERT_EQ(EPERM, errno);
				break;
			case LSM_ID_APPARMOR:
				ASSERT_EQ(active_apparmor, true);
				rc = syscall(__NR_lsm_set_self_attr, tctx, size,
					     LSM_ATTR_CURRENT);
				ASSERT_EQ(-1, rc);
				ASSERT_EQ(EINVAL, errno);
				break;
			default:
			}
			tctx = next_ctx(tctx);
		}
	}
	if (cnt_exec) {
		size = page_size;
		count = syscall(__NR_lsm_get_self_attr, ctx, &size,
				LSM_ATTR_EXEC);
		ASSERT_GE(cnt_exec, count);
		tctx = ctx;

		for (i = 0; i < count; i++) {
			switch (tctx->id) {
			case LSM_ID_SELINUX:
				ASSERT_EQ(active_selinux, true);
				rc = syscall(__NR_lsm_set_self_attr, tctx, size,
					     LSM_ATTR_EXEC);
				ASSERT_EQ(0, rc);
				tctx->ctx[0] = 'X';
				rc = syscall(__NR_lsm_set_self_attr, tctx, size,
					     LSM_ATTR_EXEC);
				ASSERT_EQ(-1, rc);
				ASSERT_EQ(EINVAL, errno);
				break;
			case LSM_ID_APPARMOR:
				ASSERT_EQ(active_apparmor, true);
				rc = syscall(__NR_lsm_set_self_attr, tctx, size,
					     LSM_ATTR_EXEC);
				ASSERT_EQ(-1, rc);
				ASSERT_EQ(EPERM, errno);
				break;
			default:
				break;
			}
			tctx = next_ctx(tctx);
		}
	}
	if (cnt_prev) {
		size = page_size;
		count = syscall(__NR_lsm_get_self_attr, ctx, &size,
				LSM_ATTR_PREV);
		ASSERT_GE(cnt_prev, count);
		tctx = ctx;

		for (i = 0; i < count; i++) {
			switch (tctx->id) {
			case LSM_ID_SELINUX:
				ASSERT_EQ(active_selinux, true);
				rc = syscall(__NR_lsm_set_self_attr, tctx, size,
					     LSM_ATTR_PREV);
				ASSERT_EQ(-1, rc);
				ASSERT_EQ(EINVAL, errno);
				tctx->ctx[0] = 'X';
				rc = syscall(__NR_lsm_set_self_attr, tctx, size,
					     LSM_ATTR_PREV);
				ASSERT_EQ(-1, rc);
				ASSERT_EQ(EINVAL, errno);
				break;
			case LSM_ID_APPARMOR:
				ASSERT_EQ(active_apparmor, true);
				rc = syscall(__NR_lsm_set_self_attr, tctx, size,
					     LSM_ATTR_PREV);
				ASSERT_EQ(-1, rc);
				ASSERT_EQ(EPERM, errno);
				break;
			default:
				break;
			}
			tctx = next_ctx(tctx);
		}
	}
	if (cnt_fscreate) {
		size = page_size;
		count = syscall(__NR_lsm_get_self_attr, ctx, &size,
				LSM_ATTR_FSCREATE);
		ASSERT_GE(cnt_fscreate, count);
		tctx = ctx;

		for (i = 0; i < count; i++) {
			switch (tctx->id) {
			case LSM_ID_SELINUX:
				ASSERT_EQ(active_selinux, true);
				rc = syscall(__NR_lsm_set_self_attr, tctx, size,
					     LSM_ATTR_FSCREATE);
				ASSERT_EQ(-1, rc);
				ASSERT_EQ(EINVAL, errno);
				tctx->ctx[0] = 'X';
				rc = syscall(__NR_lsm_set_self_attr, tctx, size,
					     LSM_ATTR_FSCREATE);
				ASSERT_EQ(-1, rc);
				ASSERT_EQ(EINVAL, errno);
				break;
			default:
				break;
			}
			tctx = next_ctx(tctx);
		}
	}
	if (cnt_keycreate) {
		size = page_size;
		count = syscall(__NR_lsm_get_self_attr, ctx, &size,
				LSM_ATTR_KEYCREATE);
		ASSERT_GE(cnt_keycreate, count);
		tctx = ctx;

		for (i = 0; i < count; i++) {
			switch (tctx->id) {
			case LSM_ID_SELINUX:
				ASSERT_EQ(active_selinux, true);
				rc = syscall(__NR_lsm_set_self_attr, tctx, size,
					     LSM_ATTR_KEYCREATE);
				ASSERT_EQ(-1, rc);
				ASSERT_EQ(EINVAL, errno);
				tctx->ctx[0] = 'X';
				rc = syscall(__NR_lsm_set_self_attr, tctx, size,
					     LSM_ATTR_KEYCREATE);
				ASSERT_EQ(-1, rc);
				ASSERT_EQ(EINVAL, errno);
				break;
			default:
				break;
			}
			tctx = next_ctx(tctx);
		}
	}
	if (cnt_sockcreate) {
		size = page_size;
		count = syscall(__NR_lsm_get_self_attr, ctx, &size,
				LSM_ATTR_SOCKCREATE);
		ASSERT_GE(cnt_sockcreate, count);
		tctx = ctx;

		for (i = 0; i < count; i++) {
			switch (tctx->id) {
			case LSM_ID_SELINUX:
				ASSERT_EQ(active_selinux, true);
				rc = syscall(__NR_lsm_set_self_attr, tctx, size,
					     LSM_ATTR_SOCKCREATE);
				ASSERT_EQ(-1, rc);
				ASSERT_EQ(EINVAL, errno);
				tctx->ctx[0] = 'X';
				rc = syscall(__NR_lsm_set_self_attr, tctx, size,
					     LSM_ATTR_SOCKCREATE);
				ASSERT_EQ(-1, rc);
				ASSERT_EQ(EINVAL, errno);
				break;
			default:
				break;
			}
			tctx = next_ctx(tctx);
		}
	}

	free(ctx);
	free(attr);
	free(syscall_lsms);
}

TEST_HARNESS_MAIN
