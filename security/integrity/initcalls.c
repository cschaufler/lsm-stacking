// SPDX-License-Identifier: GPL-2.0+
/*
 * Platform certificate / keyring initcalls
 *
 */

#include <linux/init.h>

#include "initcalls.h"

/**
 * integrity_device_init - device_initcalls for IMA/EVM
 *
 * This helper function wraps all of the device_initcalls for both IMA and EVM.
 * It can be called multiple times, e.g. once from IMA and once from EVM,
 * without problem as it maintains an internal static state variable which
 * ensures that any setup/initialization is only done once.
 */
int __init integrity_device_init(void)
{
	int rc = 0, rc_tmp;
	static bool setup = false;

	if (setup)
		return 0;
	setup = true;

#if defined(CONFIG_INTEGRITY_PLATFORM_KEYRING)
	rc_tmp = platform_keyring_init();
	if (!rc && rc_tmp)
		rc = rc_tmp;
#endif

#if defined(CONFIG_INTEGRITY_MACHINE_KEYRING)
	rc_tmp = machine_keyring_init();
	if (!rc && rc_tmp)
		rc = rc_tmp;
#endif

#if defined(CONFIG_IMA_BLACKLIST_KEYRING)
	rc_tmp = ima_mok_init();
	if (!rc && rc_tmp)
		rc = rc_tmp;
#endif

	return rc;
}

/**
 * integrity_late_init - late_initcalls for IMA/EVM
 *
 * This helper function wraps all of the late_initcalls for both IMA and EVM.
 * It can be called multiple times, e.g. once from IMA and once from EVM,
 * without problem as it maintains an internal static state variable which
 * ensures that any setup/initialization is only done once.
 */
int __init integrity_late_init(void)
{
	int rc = 0, rc_tmp;
	static bool setup = false;

	if (setup)
		return 0;
	setup = true;

#if defined(CONFIG_LOAD_UEFI_KEYS)
	rc_tmp = load_uefi_certs();
	if (!rc && rc_tmp)
		rc = rc_tmp;
#endif

#if defined(CONFIG_LOAD_IPL_KEYS)
	rc_tmp = load_ipl_certs();
	if (!rc && rc_tmp)
		rc = rc_tmp;
#endif

#if defined(CONFIG_LOAD_PPC_KEYS)
	rc_tmp = load_powerpc_certs();
	if (!rc && rc_tmp)
		rc = rc_tmp;
#endif

	rc_tmp = integrity_fs_init();
	if (!rc && rc_tmp)
		rc = rc_tmp;

	rc_tmp = init_ima();
	if (!rc && rc_tmp)
		rc = rc_tmp;

	rc_tmp = init_evm();
	if (!rc && rc_tmp)
		rc = rc_tmp;

	return rc;
}
