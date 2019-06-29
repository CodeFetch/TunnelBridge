/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2019 Vincent Wiemann <vincent.wiemann@ironai.com>
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef CONTAINERS_H
#define CONTAINERS_H

#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>

#include "../uapi/tunnelbridge.h"

/* Cross platform __kernel_timespec */
struct timespec64 {
	int64_t tv_sec;
	int64_t tv_nsec;
};

enum {
	TBPEER_REMOVE_ME = 1U << 0,
	TBPEER_REPLACE_ALLOWEDIPS = 1U << 1,
	TBPEER_HAS_PUBLIC_KEY = 1U << 2,
	TBPEER_HAS_PRESHARED_KEY = 1U << 3,
	TBPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL = 1U << 4
};

struct tbpeer {
	uint32_t flags;

	uint8_t public_key[TB_KEY_LEN];
	uint8_t preshared_key[TB_KEY_LEN];

	union {
		struct sockaddr addr;
		struct sockaddr_in addr4;
		struct sockaddr_in6 addr6;
	} endpoint;

	struct timespec64 last_handshake_time;
	uint64_t rx_bytes, tx_bytes;
	uint16_t persistent_keepalive_interval;

	struct tballowedip *first_allowedip, *last_allowedip;
	struct tbpeer *next_peer;
};

enum {
	TBDEVICE_REPLACE_PEERS = 1U << 0,
	TBDEVICE_HAS_PRIVATE_KEY = 1U << 1,
	TBDEVICE_HAS_PUBLIC_KEY = 1U << 2,
	TBDEVICE_HAS_LISTEN_PORT = 1U << 3,
	TBDEVICE_HAS_FWMARK = 1U << 4
	TBDEVICE_ETH = 1U << 5
	TBDEVICE_ETH_FORWARDING = 1U << 6
};

struct tbdevice {
	char name[IFNAMSIZ];
	uint32_t ifindex;

	uint32_t flags;

	uint8_t public_key[TB_KEY_LEN];
	uint8_t private_key[TB_KEY_LEN];

	uint32_t fwmark;
	uint16_t listen_port;

	struct tbpeer *first_peer, *last_peer;
};

#define for_each_tbpeer(__dev, __peer) for ((__peer) = (__dev)->first_peer; (__peer); (__peer) = (__peer)->next_peer)

static inline void free_tbdevice(struct tbdevice *dev)
{
	if (!dev)
		return;

	for (struct tbpeer *peer = dev->first_peer, *np = peer ? peer->next_peer : NULL; peer; peer = np, np = peer ? peer->next_peer : NULL)
		free(peer);

	free(dev);
}

#endif
