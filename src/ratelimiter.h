/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2019 Vincent Wiemann <vincent.wiemann@ironai.com>
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef _TB_RATELIMITER_H
#define _TB_RATELIMITER_H

#include <linux/skbuff.h>

int tb_ratelimiter_init(void);
void tb_ratelimiter_uninit(void);
bool tb_ratelimiter_allow(struct sk_buff *skb, struct net *net);

#ifdef DEBUG
bool tb_ratelimiter_selftest(void);
#endif

#endif /* _TB_RATELIMITER_H */
