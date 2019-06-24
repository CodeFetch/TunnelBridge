/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2019 Vincent Wiemann <vincent.wiemann@ironai.com>
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef _TB_NETLINK_H
#define _TB_NETLINK_H

int tb_genetlink_init(void);
void tb_genetlink_uninit(void);

#endif /* _TB_NETLINK_H */
