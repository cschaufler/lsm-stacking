/* SPDX-License-Identifier: GPL-2.0 */

#ifndef PLATFORM_CERTS_INITCALLS_H
#define PLATFORM_CERTS_INITCALLS_H

int machine_keyring_init(void);
int platform_keyring_init(void);

int load_uefi_certs(void);
int load_ipl_certs(void);
int load_powerpc_certs(void);

int integrity_fs_init(void);

int init_ima(void);
int init_evm(void);

int ima_mok_init(void);

int integrity_device_init(void);
int integrity_late_init(void);

#endif
