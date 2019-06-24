/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2019 Vincent Wiemann <vincent.wiemann@ironai.com>
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef _TB_SOCKET_H
#define _TB_SOCKET_H

#include <linux/netdevice.h>
#include <linux/udp.h>
#include <linux/if_vlan.h>
#include <linux/if_ether.h>

int tb_socket_init(struct tb_device *tb, u16 port);
void tb_socket_reinit(struct tb_device *tb, struct sock *new4,
		      struct sock *new6);
int tb_socket_send_buffer_to_peer(struct tb_peer *peer, void *data,
				  size_t len, u8 ds);
int tb_socket_send_skb_to_peer(struct tb_peer *peer, struct sk_buff *skb,
			       u8 ds);
int tb_socket_send_buffer_as_reply_to_skb(struct tb_device *tb,
					  struct sk_buff *in_skb,
					  void *out_buffer, size_t len);

int tb_socket_endpoint_from_skb(struct endpoint *endpoint,
				const struct sk_buff *skb);
void tb_socket_set_peer_endpoint(struct tb_peer *peer,
				 const struct endpoint *endpoint);
void tb_socket_set_peer_endpoint_from_skb(struct tb_peer *peer,
					  const struct sk_buff *skb);
void tb_socket_clear_peer_endpoint_src(struct tb_peer *peer);

#if defined(CONFIG_DYNAMIC_DEBUG) || defined(DEBUG)
#define net_dbg_skb_ratelimited(fmt, dev, skb, ...) do {                       \
		struct endpoint __endpoint;                                    \
		tb_socket_endpoint_from_skb(&__endpoint, skb);                 \
		net_dbg_ratelimited(fmt, dev, &__endpoint.addr,                \
				    ##__VA_ARGS__);                            \
	} while (0)
#else
#define net_dbg_skb_ratelimited(fmt, skb, ...)
#endif

#endif /* _TB_SOCKET_H */
