/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2019 Vincent Wiemann <vincent.wiemann@ironai.com>
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "version.h"
#include "device.h"
#include "noise.h"
#include "queueing.h"
#include "ratelimiter.h"
#include "netlink.h"
#include "uapi/tunnelbridge.h"
#include "crypto/zinc.h"

#include <linux/version.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/genetlink.h>
#include <net/rtnetlink.h>

static int __init mod_init(void)
{
	int ret;

	if ((ret = chacha20_mod_init()) || (ret = poly1305_mod_init()) ||
	    (ret = chacha20poly1305_mod_init()) || (ret = blake2s_mod_init()) ||
	    (ret = curve25519_mod_init()))
		return ret;

#ifdef DEBUG
	if (!tb_packet_counter_selftest() ||
	    !tb_ratelimiter_selftest())
		return -ENOTRECOVERABLE;
#endif
	tb_noise_init();

	ret = tb_device_init();
	if (ret < 0)
		goto err_device;

	ret = tb_genetlink_init();
	if (ret < 0)
		goto err_netlink;

	pr_info("TunnelBridge " TUNNELBRIDGE_VERSION " loaded. See github.com/codefetch/tunnelbridge for information.\n");
	pr_info("Copyright (C) 2019 Vincent Wiemann <vincent.wiemann@ironai.com>. All Rights Reserved.\n");

	return 0;

err_netlink:
	tb_device_uninit();
err_device:
	return ret;
}

static void __exit mod_exit(void)
{
	tb_genetlink_uninit();
	tb_device_uninit();
}

module_init(mod_init);
module_exit(mod_exit);
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("TunnelBridge encrypted layer 2 tunnel");
MODULE_AUTHOR("Vincent Wiemann <vincent.wiemann@ironai.com>");
MODULE_VERSION(TUNNELBRIDGE_VERSION);
MODULE_ALIAS_RTNL_LINK(KBUILD_MODNAME);
MODULE_ALIAS_GENL_FAMILY(TB_GENL_NAME);
