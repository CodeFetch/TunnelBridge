/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2019 Vincent Wiemann <vincent.wiemann@ironai.com>
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef IPC_H
#define IPC_H

#include <stdbool.h>

struct tbdevice;

int ipc_set_device(struct tbdevice *dev);
int ipc_get_device(struct tbdevice **dev, const char *interface);
char *ipc_list_devices(void);

#endif
