/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2018 Vincent Wiemann <vincent.wiemann@ironai.com>. All Rights Reserved.
 */

#ifndef _TB_CLIENT_H
#define _TB_CLIENT_H

#include "device.h"

#include <linux/hashtable.h>
#include <linux/rculist.h>
#include <linux/spinlock.h>

/* Forward packets between peers (including multicast) */
#define TB_CLIENT_FORWARDING 1
/* Check if clients have timed out every number of secs */
#define TB_CLIENT_TIMER_INTERVAL 60
/* Timeout after number of secs */
#define TB_CLIENT_TIMER_TIMEOUT 120

#define tb_hash_for_each_rcu_bh(name, bkt, obj, member)			\
	for ((bkt) = 0, obj = NULL; obj == NULL && (bkt) < HASH_SIZE(name);\
			(bkt)++)\
		hlist_for_each_entry_rcu_bh(obj, &name[bkt], member)

struct tb_peer;

/* TODO: move to rhashtable, BUT with per-bucket spinlocks */
struct client_hashtable {
	DECLARE_HASHTABLE(hashtable, 13);
	spinlock_t lock;
	u32 salt;
};

struct tb_client {
	struct tb_device *device;
	struct tb_peer *peer;
	unsigned char ha[ETH_ALEN];
	atomic_t timeout;
	struct hlist_node client_hash;
	struct kref refcount;
	struct rcu_head rcu;
};

int debug_print_skb_dump(struct sk_buff *skb, char *message);

struct tb_client *tb_client_create(struct tb_device *tb, struct tb_peer *peer, const u8 *ha);
struct tb_client *tb_client_lookup_dst(struct client_hashtable *table, struct sk_buff *skb);
struct tb_client *tb_client_lookup_src(struct client_hashtable *table, struct sk_buff *skb);
struct tb_client *tb_client_update_peer(struct tb_client *old, struct tb_peer *peer);
void tb_client_put(struct tb_client *client);
int tb_client_remove(struct tb_client *client);
void tb_client_remove_all(struct client_hashtable *table);
void tb_client_remove_by_peer(struct tb_peer *peer);
void tb_client_init(struct tb_device *tb);
void tb_client_destroy(struct tb_device *tb);

#endif /* _TB_CLIENT_H */

