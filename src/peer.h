/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2019 Vincent Wiemann <vincent.wiemann@ironai.com>
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef _TB_PEER_H
#define _TB_PEER_H

#include "device.h"
#include "noise.h"
#include "cookie.h"

#include <linux/types.h>
#include <linux/netfilter.h>
#include <linux/spinlock.h>
#include <linux/kref.h>
#include <net/dst_cache.h>

struct tb_device;

struct endpoint {
	union {
		struct sockaddr addr;
		struct sockaddr_in addr4;
		struct sockaddr_in6 addr6;
	};
	union {
		struct {
			struct in_addr src4;
			/* Essentially the same as addr6->scope_id */
			int src_if4;
		};
		struct in6_addr src6;
	};
};

struct tb_peer {
	struct tb_device *device;
	struct crypt_queue tx_queue, rx_queue;
	struct sk_buff_head staged_packet_queue;
	int serial_work_cpu;
	struct noise_keypairs keypairs;
	struct endpoint endpoint;
	struct dst_cache endpoint_cache;
	rwlock_t endpoint_lock;
	struct noise_handshake handshake;
	atomic64_t last_sent_handshake;
	struct work_struct transmit_handshake_work, clear_peer_work;
	struct cookie latest_cookie;
	struct hlist_node pubkey_hash;
	u64 rx_bytes, tx_bytes;
	struct timer_list timer_retransmit_handshake, timer_send_keepalive;
	struct timer_list timer_new_handshake, timer_zero_key_material;
	struct timer_list timer_persistent_keepalive;
	unsigned int timer_handshake_attempts;
	u16 persistent_keepalive_interval;
	bool timer_need_another_keepalive;
	bool sent_lastminute_handshake;
	struct timespec64 walltime_last_handshake;
	struct kref refcount;
	struct rcu_head rcu;
	struct list_head peer_list;
	u64 internal_id;
	struct napi_struct napi;
	bool is_dead;
};

struct tb_peer *tb_peer_create(struct tb_device *tb,
			       const u8 public_key[NOISE_PUBLIC_KEY_LEN],
			       const u8 preshared_key[NOISE_SYMMETRIC_KEY_LEN]);

struct tb_peer *__must_check tb_peer_get_maybe_zero(struct tb_peer *peer);
static inline struct tb_peer *tb_peer_get(struct tb_peer *peer)
{
	kref_get(&peer->refcount);
	return peer;
}
void tb_peer_put(struct tb_peer *peer);
void tb_peer_remove(struct tb_peer *peer);
void tb_peer_remove_all(struct tb_device *tb);

#endif /* _TB_PEER_H */
