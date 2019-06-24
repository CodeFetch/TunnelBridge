/* SPDX-License-Identifier: GPL-2.0 OR MIT */
/*
 * Copyright (C) 2019 Vincent Wiemann <vincent.wiemann@ironai.com>
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef _TB_ZINC_H
#define _TB_ZINC_H

int chacha20_mod_init(void);
int poly1305_mod_init(void);
int chacha20poly1305_mod_init(void);
int blake2s_mod_init(void);
int curve25519_mod_init(void);

#endif
