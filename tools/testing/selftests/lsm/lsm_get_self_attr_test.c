// SPDX-License-Identifier: GPL-2.0
/*
 * Linux Security Module infrastructure tests
 * Tests for the lsm_get_self_attr system call
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

#define PROCATTR	"/proc/self/attr/"

static int read_proc_attr(const char *attr, char *value, __kernel_size_t size)
{
	FILE *fp;
	int len;
	char *path;

	len = strlen(PROCATTR) + strlen(attr) + 1;
	path = calloc(len, 1);
	if (path == NULL)
		return -1;
	sprintf(path, "%s%s", PROCATTR, attr);

	fp = fopen(path, "r");
	free(path);

	if (fp == NULL)
		return -1;
	if (fread(value, 1, size, fp) <= 0)
		return -1;
	fclose(fp);

	path = strchr(value, '\n');
	if (path)
		*path = '\0';

	return 0;
}

static struct lsm_ctx *next_ctx(struct lsm_ctx *ctxp)
{
	void *vp;

	vp = (void *)ctxp + sizeof(*ctxp) + ctxp->ctx_len;
	return (struct lsm_ctx *)vp;
}

TEST(size_null_lsm_get_self_attr)
{
	const long page_size = sysconf(_SC_PAGESIZE);
	char *ctx = calloc(page_size, 1);

	ASSERT_NE(NULL, ctx);
	ASSERT_EQ(-1, syscall(__NR_lsm_get_self_attr, ctx, NULL,
			      LSM_ATTR_CURRENT));
	ASSERT_EQ(EFAULT, errno);

	free(ctx);
}

TEST(ctx_null_lsm_get_self_attr)
{
	const long page_size = sysconf(_SC_PAGESIZE);
	__kernel_size_t size = page_size;

	ASSERT_EQ(-1, syscall(__NR_lsm_get_self_attr, NULL, &size,
			      LSM_ATTR_CURRENT));
	ASSERT_EQ(EFAULT, errno);
	ASSERT_NE(1, size);
}

TEST(size_too_small_lsm_get_self_attr)
{
	const long page_size = sysconf(_SC_PAGESIZE);
	char *ctx = calloc(page_size, 1);
	__kernel_size_t size = 1;

	ASSERT_NE(NULL, ctx);
	ASSERT_EQ(-1, syscall(__NR_lsm_get_self_attr, ctx, &size,
			      LSM_ATTR_CURRENT));
	ASSERT_EQ(ERANGE, errno);
	ASSERT_NE(1, size);

	free(ctx);
}

TEST(flags_zero_lsm_get_self_attr)
{
	const long page_size = sysconf(_SC_PAGESIZE);
	char *ctx = calloc(page_size, 1);
	__kernel_size_t size = page_size;

	ASSERT_NE(NULL, ctx);
	ASSERT_EQ(-1, syscall(__NR_lsm_get_self_attr, ctx, &size, 0));
	ASSERT_EQ(EINVAL, errno);
	ASSERT_EQ(page_size, size);

	free(ctx);
}

TEST(flags_overset_lsm_get_self_attr)
{
	const long page_size = sysconf(_SC_PAGESIZE);
	char *ctx = calloc(page_size, 1);
	__kernel_size_t size = page_size;

	ASSERT_NE(NULL, ctx);
	ASSERT_EQ(-1, syscall(__NR_lsm_get_self_attr, ctx, &size,
			      LSM_ATTR_CURRENT | LSM_ATTR_PREV));
	ASSERT_EQ(EINVAL, errno);
	ASSERT_EQ(page_size, size);

	free(ctx);
}

TEST(basic_lsm_get_self_attr)
{
	const long page_size = sysconf(_SC_PAGESIZE);
	__kernel_size_t size = page_size;
	struct lsm_ctx *ctx = calloc(page_size, 1);
	struct lsm_ctx *tctx = NULL;
	__u32 *syscall_lsms = calloc(page_size, 1);
	char *attr = calloc(page_size, 1);
	int cnt_current = 0;
	int cnt_exec = 0;
	int cnt_fscreate = 0;
	int cnt_keycreate = 0;
	int cnt_prev = 0;
	int cnt_sockcreate = 0;
	int lsmcount;
	int count;
	int i;

	ASSERT_NE(NULL, ctx);
	ASSERT_NE(NULL, syscall_lsms);

	lsmcount = syscall(__NR_lsm_module_list, syscall_lsms, &size, 0);
	ASSERT_LE(1, lsmcount);

	for (i = 0; i < lsmcount; i++) {
		switch (syscall_lsms[i]) {
		case LSM_ID_SELINUX:
			cnt_current++;
			cnt_exec++;
			cnt_fscreate++;
			cnt_keycreate++;
			cnt_prev++;
			cnt_sockcreate++;
			break;
		case LSM_ID_SMACK:
			cnt_current++;
			break;
		case LSM_ID_APPARMOR:
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
		ASSERT_EQ(0, read_proc_attr("current", attr, page_size));
		ASSERT_EQ(0, strcmp((char *)tctx->ctx, attr));
		for (i = 1; i < count; i++) {
			tctx = next_ctx(tctx);
			ASSERT_NE(0, strcmp((char *)tctx->ctx, attr));
		}
	}
	if (cnt_exec) {
		size = page_size;
		count = syscall(__NR_lsm_get_self_attr, ctx, &size,
				LSM_ATTR_EXEC);
		ASSERT_GE(cnt_exec, count);
		if (count > 0) {
			tctx = ctx;
			ASSERT_EQ(0, read_proc_attr("exec", attr, page_size));
			ASSERT_EQ(0, strcmp((char *)tctx->ctx, attr));
		}
		for (i = 1; i < count; i++) {
			tctx = next_ctx(tctx);
			ASSERT_NE(0, strcmp((char *)tctx->ctx, attr));
		}
	}
	if (cnt_fscreate) {
		size = page_size;
		count = syscall(__NR_lsm_get_self_attr, ctx, &size,
				LSM_ATTR_FSCREATE);
		ASSERT_GE(cnt_fscreate, count);
		if (count > 0) {
			tctx = ctx;
			ASSERT_EQ(0, read_proc_attr("fscreate", attr,
						    page_size));
			ASSERT_EQ(0, strcmp((char *)tctx->ctx, attr));
		}
		for (i = 1; i < count; i++) {
			tctx = next_ctx(tctx);
			ASSERT_NE(0, strcmp((char *)tctx->ctx, attr));
		}
	}
	if (cnt_keycreate) {
		size = page_size;
		count = syscall(__NR_lsm_get_self_attr, ctx, &size,
				LSM_ATTR_KEYCREATE);
		ASSERT_GE(cnt_keycreate, count);
		if (count > 0) {
			tctx = ctx;
			ASSERT_EQ(0, read_proc_attr("keycreate", attr,
						    page_size));
			ASSERT_EQ(0, strcmp((char *)tctx->ctx, attr));
		}
		for (i = 1; i < count; i++) {
			tctx = next_ctx(tctx);
			ASSERT_NE(0, strcmp((char *)tctx->ctx, attr));
		}
	}
	if (cnt_prev) {
		size = page_size;
		count = syscall(__NR_lsm_get_self_attr, ctx, &size,
				LSM_ATTR_PREV);
		ASSERT_GE(cnt_prev, count);
		if (count > 0) {
			tctx = ctx;
			ASSERT_EQ(0, read_proc_attr("prev", attr, page_size));
			ASSERT_EQ(0, strcmp((char *)tctx->ctx, attr));
			for (i = 1; i < count; i++) {
				tctx = next_ctx(tctx);
				ASSERT_NE(0, strcmp((char *)tctx->ctx, attr));
			}
		}
	}
	if (cnt_sockcreate) {
		size = page_size;
		count = syscall(__NR_lsm_get_self_attr, ctx, &size,
				LSM_ATTR_SOCKCREATE);
		ASSERT_GE(cnt_sockcreate, count);
		if (count > 0) {
			tctx = ctx;
			ASSERT_EQ(0, read_proc_attr("sockcreate", attr,
						    page_size));
			ASSERT_EQ(0, strcmp((char *)tctx->ctx, attr));
		}
		for (i = 1; i < count; i++) {
			tctx = next_ctx(tctx);
			ASSERT_NE(0, strcmp((char *)tctx->ctx, attr));
		}
	}

	free(ctx);
	free(attr);
	free(syscall_lsms);
}

TEST_HARNESS_MAIN
