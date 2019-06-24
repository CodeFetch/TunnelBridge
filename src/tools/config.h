/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2019 Vincent Wiemann <vincent.wiemann@ironai.com>
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>

struct tbdevice;
struct tbpeer;
struct tballowedip;

struct config_ctx {
	struct tbdevice *device;
	struct tbpeer *last_peer;
	struct tballowedip *last_allowedip;
	bool is_peer_section, is_device_section;
};

struct tbdevice *config_read_cmd(char *argv[], int argc);
bool config_read_init(struct config_ctx *ctx, bool append);
bool config_read_line(struct config_ctx *ctx, const char *line);
struct tbdevice *config_read_finish(struct config_ctx *ctx);

#endif
