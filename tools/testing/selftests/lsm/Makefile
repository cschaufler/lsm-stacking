# SPDX-License-Identifier: GPL-2.0
#
# First run: make -C ../../../.. headers_install

CFLAGS += -Wall -O2 $(KHDR_INCLUDES)

TEST_GEN_PROGS := lsm_get_self_attr_test lsm_module_list_test \
		  lsm_set_self_attr_test

include ../lib.mk

$(TEST_GEN_PROGS):
