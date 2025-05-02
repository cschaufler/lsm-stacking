// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * LSM functions
 */

#ifndef _LSM_H_
#define _LSM_H_

#include <linux/printk.h>
#include <linux/lsm_hooks.h>
#include <linux/lsm_count.h>

/* LSM debugging */
extern bool lsm_debug;
#define lsm_pr(...)		pr_info(__VA_ARGS__)
#define lsm_pr_cont(...)	pr_cont(__VA_ARGS__)
#define lsm_pr_dbg(...)							\
	do {								\
		if (lsm_debug)						\
			pr_info(__VA_ARGS__);				\
	} while (0)

/* List of configured LSMs */
extern unsigned int lsm_count;
extern const struct lsm_id *lsm_idlist[];

/* LSM property configuration */
extern unsigned int lsm_count_prop_subj;
extern unsigned int lsm_count_prop_obj;

/* LSM blob configuration */
extern struct lsm_blob_sizes blob_sizes;

/* LSM blob caches */
extern struct kmem_cache *lsm_file_cache;
extern struct kmem_cache *lsm_inode_cache;

/* LSM blob allocators */
int lsm_cred_alloc(struct cred *cred, gfp_t gfp);
int lsm_task_alloc(struct task_struct *task);

/* LSM framework initializers */
int securityfs_init(void);
int min_addr_init(void);

#endif /* _LSM_H_ */
