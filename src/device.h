/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2019 Vincent Wiemann <vincent.wiemann@ironai.com>
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef _TB_DEVICE_H
#define _TB_DEVICE_H

#include "noise.h"
#include "client.h"
#include "peerlookup.h"
#include "cookie.h"

#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>
#include <linux/net.h>
#include <linux/ptr_ring.h>

struct tb_device;

struct multicore_worker {
	void *ptr;
	struct work_struct work;
};

struct crypt_queue {
	struct ptr_ring ring;
	union {
		struct {
			struct multicore_worker __percpu *worker;
			int last_cpu;
		};
		struct work_struct work;
	};
};

struct tb_device {
	struct net_device *dev;
	struct crypt_queue encrypt_queue, decrypt_queue;
	struct sock __rcu *sock4, *sock6;
	struct net *creating_net;
	struct noise_static_identity static_identity;
	struct workqueue_struct *handshake_receive_wq, *handshake_send_wq;
	struct workqueue_struct *packet_crypt_wq;
	struct sk_buff_head incoming_handshakes;
	int incoming_handshake_cpu;
	struct multicore_worker __percpu *incoming_handshakes_worker;
	struct cookie_checker cookie_checker;
	struct pubkey_hashtable *peer_hashtable;
	struct index_hashtable *index_hashtable;
	struct client_hashtable client_hashtable;
	struct timer_list timer_client_timeout;
	struct mutex device_update_lock, socket_update_lock;
	struct list_head device_list, peer_list;
	unsigned int num_peers, device_update_gen;
	u16 incoming_port;
	bool have_creating_net_ref;
};

int tb_device_init(void);
void tb_device_uninit(void);
void tb_xmit_peer(struct sk_buff *skb, struct net_device *dev, struct tb_peer *peer);
void tb_xmit_broadcast(struct sk_buff *skb, struct net_device *dev, struct tb_peer *sender);

#endif /* _TB_DEVICE_H */
