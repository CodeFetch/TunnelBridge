/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2019 Vincent Wiemann <vincent.wiemann@ironai.com>
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "queueing.h"
#include "socket.h"
#include "timers.h"
#include "device.h"
#include "ratelimiter.h"
#include "peer.h"
#include "messages.h"

#include <linux/module.h>
#include <linux/rtnetlink.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/if_arp.h>
#include <linux/icmp.h>
#include <linux/suspend.h>
#include <net/icmp.h>
#include <net/rtnetlink.h>
#include <net/ip_tunnels.h>
#include <net/addrconf.h>

static LIST_HEAD(device_list);

static int tb_open(struct net_device *dev)
{
	struct in_device *dev_v4 = __in_dev_get_rtnl(dev);
#ifndef COMPAT_CANNOT_USE_IN6_DEV_GET
	struct inet6_dev *dev_v6 = __in6_dev_get(dev);
#endif
	struct tb_device *tb = netdev_priv(dev);
	struct tb_peer *peer;
	int ret;

	if (dev_v4) {
		/* At some point we might put this check near the ip_rt_send_
		 * redirect call of ip_forward in net/ipv4/ip_forward.c, similar
		 * to the current secpath check.
		 */
		IN_DEV_CONF_SET(dev_v4, SEND_REDIRECTS, false);
		IPV4_DEVCONF_ALL(dev_net(dev), SEND_REDIRECTS) = false;
	}
#ifndef COMPAT_CANNOT_USE_IN6_DEV_GET
	if (dev_v6)
#ifndef COMPAT_CANNOT_USE_DEV_CNF
		dev_v6->cnf.addr_gen_mode = IN6_ADDR_GEN_MODE_NONE;
#else
		dev_v6->addr_gen_mode = IN6_ADDR_GEN_MODE_NONE;
#endif
#endif

	ret = tb_socket_init(tb, tb->incoming_port);
	if (ret < 0)
		return ret;
	mutex_lock(&tb->device_update_lock);
	list_for_each_entry(peer, &tb->peer_list, peer_list) {
		tb_packet_send_staged_packets(peer);
		if (peer->persistent_keepalive_interval)
			tb_packet_send_keepalive(peer);
	}
	mutex_unlock(&tb->device_update_lock);
	return 0;
}

#ifdef CONFIG_PM_SLEEP
static int tb_pm_notification(struct notifier_block *nb, unsigned long action,
			      void *data)
{
	struct tb_device *tb;
	struct tb_peer *peer;

	/* If the machine is constantly suspending and resuming, as part of
	 * its normal operation rather than as a somewhat rare event, then we
	 * don't actually want to clear keys.
	 */
	if (IS_ENABLED(CONFIG_PM_AUTOSLEEP) || IS_ENABLED(CONFIG_ANDROID))
		return 0;

	if (action != PM_HIBERNATION_PREPARE && action != PM_SUSPEND_PREPARE)
		return 0;

	rtnl_lock();
	list_for_each_entry(tb, &device_list, device_list) {
		mutex_lock(&tb->device_update_lock);
		list_for_each_entry(peer, &tb->peer_list, peer_list) {
			del_timer(&peer->timer_zero_key_material);
			tb_noise_handshake_clear(&peer->handshake);
			tb_noise_keypairs_clear(&peer->keypairs);
		}
		mutex_unlock(&tb->device_update_lock);
	}
	rtnl_unlock();
	rcu_barrier();
	return 0;
}

static struct notifier_block pm_notifier = { .notifier_call = tb_pm_notification };
#endif

static int tb_stop(struct net_device *dev)
{
	struct tb_device *tb = netdev_priv(dev);
	struct tb_peer *peer;

	mutex_lock(&tb->device_update_lock);
	list_for_each_entry(peer, &tb->peer_list, peer_list) {
		tb_packet_purge_staged_packets(peer);
		tb_timers_stop(peer);
		tb_noise_handshake_clear(&peer->handshake);
		tb_noise_keypairs_clear(&peer->keypairs);
		atomic64_set(&peer->last_sent_handshake,
			     (u64)ktime_get_coarse_boottime() -
			     (u64)(REKEY_TIMEOUT + 1) * NSEC_PER_SEC);
	}
	mutex_unlock(&tb->device_update_lock);
	skb_queue_purge(&tb->incoming_handshakes);
	tb_socket_reinit(tb, NULL, NULL);
	return 0;
}

void tb_xmit_peer(struct sk_buff *skb, struct net_device *dev, struct tb_peer *peer)
{
	struct sk_buff_head packets;
	struct sk_buff *next;

	if (unlikely(!skb))
		return;

	debug_print_skb_dump(skb, "tb: device.c: tb_xmit_peer");

	__skb_queue_head_init(&packets);
	if (!skb_is_gso(skb)) {
		skb->next = NULL;
	} else {
		struct sk_buff *segs = skb_gso_segment(skb, 0);

		if (unlikely(IS_ERR(segs)))
			goto err;

		dev_kfree_skb(skb);
		skb = segs;
	}
	do {
		next = skb->next;
		skb->next = skb->prev = NULL;

		skb = skb_share_check(skb, GFP_ATOMIC);
		if (unlikely(!skb))
			continue;

		/* We only need to keep the original dst around for icmp,
		 * so at this point we're in a position to drop it.
		 */
		skb_dst_drop(skb);

		PACKET_CB(skb)->mtu = dev->mtu;

		__skb_queue_tail(&packets, skb);
	} while ((skb = next) != NULL);

	spin_lock_bh(&peer->staged_packet_queue.lock);
	/* If the queue is getting too big, we start removing the oldest packets
	 * until it's small again. We do this before adding the new packet, so
	 * we don't remove GSO segments that are in excess.
	 */
	while (skb_queue_len(&peer->staged_packet_queue) > MAX_STAGED_PACKETS) {
		dev_kfree_skb(__skb_dequeue(&peer->staged_packet_queue));
		++dev->stats.tx_dropped;
	}
	skb_queue_splice_tail(&packets, &peer->staged_packet_queue);
	spin_unlock_bh(&peer->staged_packet_queue.lock);

	tb_packet_send_staged_packets(peer);

err:
	++dev->stats.tx_errors;
	kfree_skb(skb);
}

void tb_xmit_broadcast(struct sk_buff *skb, struct net_device *dev, 
					  struct tb_peer *sender)
{
	struct tb_device *tb = netdev_priv(dev);
	struct tb_peer *peer = NULL;
	int i;

	if(unlikely(!skb))
		return;

	debug_print_skb_dump(skb, "tb: device.c: tb_xmit_broadcast");

	rcu_read_lock_bh();
	/*!memcmp(peer->handshake.remote_static, sender->handshake.remote_static, NOISE_PUBLIC_KEY_LEN)*/

	tb_hash_for_each_rcu_bh(tb->peer_hashtable.hashtable, i, peer, pubkey_hash)
		if (!sender || peer != sender)
			tb_xmit_peer(skb_copy(skb, GFP_ATOMIC), dev, peer);

	rcu_read_unlock_bh();

	kfree_skb(skb);
}

static netdev_tx_t tb_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct tb_device *tb = netdev_priv(dev);
	struct tb_peer *peer;
	struct tb_client *client = NULL;
	int ret;

	skb = skb_share_check(skb, GFP_ATOMIC);

	debug_print_skb_dump(skb, "tb: device.c: tb_xmit");

	if(unlikely(!skb)) {
		++dev->stats.tx_errors;
		return -ENOBUFS;
	}

	/* Lookup source address */
	client = tb_client_lookup_src(&tb->client_hashtable, skb);
	if(likely(client)) {
		if(client->peer) {
			/* Has roamed to us */
			tb_client_update_peer(client, NULL);
			tb_peer_put(client->peer);
		}

		tb_client_put(client);
	} else {
		/* New client - Does not take reference on new client */
		tb_client_create(tb, NULL, (const u8 *)&eth_hdr(skb)->h_source);
	}

	PACKET_CB(skb)->mtu = dev->mtu;

	/* Lookup destination address */
	if (is_multicast_ether_addr((const u8 *)&eth_hdr(skb)->h_dest)) {
		 /* Packet is multicast -> send to all peers */
		tb_xmit_broadcast(skb, dev, NULL);
	} else {
		client = tb_client_lookup_dst(&tb->client_hashtable, skb);

		if(likely(client)) {
			if(client->peer) {
				/* Send packet to peer */
				tb_xmit_peer(skb, dev, peer);
			} else {
				/* Destination is local -> ignore */
				tb_client_put(client);
				ret = NETDEV_TX_OK;
				goto out;
			}

			tb_client_put(client);
		} else {
			/* We don't know the destination -> send packet to all peers */
			tb_xmit_broadcast(skb, dev, NULL);
		}
	}

	return NETDEV_TX_OK;

out:
	kfree_skb(skb);
	return ret;
}

static const struct net_device_ops netdev_ops = {
	.ndo_open		= tb_open,
	.ndo_stop		= tb_stop,
	.ndo_start_xmit		= tb_xmit,
	.ndo_get_stats64	= ip_tunnel_get_stats64
};

static void tb_destruct(struct net_device *dev)
{
	struct tb_device *tb = netdev_priv(dev);

	rtnl_lock();
	list_del(&tb->device_list);
	rtnl_unlock();
	mutex_lock(&tb->device_update_lock);
	tb->incoming_port = 0;
	tb_socket_reinit(tb, NULL, NULL);
	/* The final references are cleared in the below calls to destroy_workqueue. */
	tb_peer_remove_all(tb);
	destroy_workqueue(tb->handshake_receive_wq);
	destroy_workqueue(tb->handshake_send_wq);
	destroy_workqueue(tb->packet_crypt_wq);
	tb_packet_queue_free(&tb->decrypt_queue, true);
	tb_packet_queue_free(&tb->encrypt_queue, true);
	rcu_barrier(); /* Wait for all the peers to be actually freed. */
	tb_ratelimiter_uninit();
	memzero_explicit(&tb->static_identity, sizeof(tb->static_identity));
	skb_queue_purge(&tb->incoming_handshakes);
	free_percpu(dev->tstats);
	free_percpu(tb->incoming_handshakes_worker);
	if (tb->have_creating_net_ref)
		put_net(tb->creating_net);
	kvfree(tb->index_hashtable);
	kvfree(tb->peer_hashtable);
	mutex_unlock(&tb->device_update_lock);

	pr_debug("%s: Interface deleted\n", dev->name);
	free_netdev(dev);
}

static const struct device_type device_type = { .name = KBUILD_MODNAME };

static void tb_setup(struct net_device *dev)
{
	struct tb_device *tb = netdev_priv(dev);
	enum { TB_NETDEV_FEATURES = NETIF_F_HW_CSUM | NETIF_F_RXCSUM |
				    NETIF_F_SG | NETIF_F_GSO |
				    NETIF_F_GSO_SOFTWARE | NETIF_F_HIGHDMA };

	ether_setup(dev);
	dev->netdev_ops = &netdev_ops;
	random_ether_addr(dev->dev_addr);
	dev->needed_headroom = DATA_PACKET_HEAD_ROOM;
	dev->needed_tailroom = noise_encrypted_len(MESSAGE_PADDING_MULTIPLE);
#ifndef COMPAT_CANNOT_USE_IFF_NO_QUEUE
	dev->priv_flags |= IFF_NO_QUEUE;
#else
	dev->tx_queue_len = 0;
#endif
	dev->features |= NETIF_F_LLTX;
	dev->features |= TB_NETDEV_FEATURES;
	dev->hw_features |= TB_NETDEV_FEATURES;
	dev->hw_enc_features |= TB_NETDEV_FEATURES;
	dev->mtu = ETH_DATA_LEN - MESSAGE_MINIMUM_LENGTH -
		   sizeof(struct udphdr) - sizeof(struct ethhdr) -
		   max(sizeof(struct ipv6hdr), sizeof(struct iphdr));

	SET_NETDEV_DEVTYPE(dev, &device_type);

	/* We need to keep the dst around in case of icmp replies. */
	netif_keep_dst(dev);

	memset(tb, 0, sizeof(*tb));
	tb->dev = dev;
}

static int tb_newlink(struct net *src_net, struct net_device *dev,
		      struct nlattr *tb[], struct nlattr *data[],
		      struct netlink_ext_ack *extack)
{
	struct tb_device *tb = netdev_priv(dev);
	int ret = -ENOMEM;

	tb->creating_net = src_net;
	init_rwsem(&tb->static_identity.lock);
	mutex_init(&tb->socket_update_lock);
	mutex_init(&tb->device_update_lock);
	skb_queue_head_init(&tb->incoming_handshakes);
	tb_client_init(tb);
	tb_cookie_checker_init(&tb->cookie_checker, tb);
	INIT_LIST_HEAD(&tb->peer_list);
	tb->device_update_gen = 1;

	tb->peer_hashtable = tb_pubkey_hashtable_alloc();
	if (!tb->peer_hashtable)
		return ret;

	tb->index_hashtable = tb_index_hashtable_alloc();
	if (!tb->index_hashtable)
		goto err_free_peer_hashtable;

	dev->tstats = netdev_alloc_pcpu_stats(struct pcpu_sw_netstats);
	if (!dev->tstats)
		goto err_free_index_hashtable;

	tb->incoming_handshakes_worker =
		tb_packet_percpu_multicore_worker_alloc(
				tb_packet_handshake_receive_worker, tb);
	if (!tb->incoming_handshakes_worker)
		goto err_free_tstats;

	tb->handshake_receive_wq = alloc_workqueue("tb-kex-%s",
			WQ_CPU_INTENSIVE | WQ_FREEZABLE, 0, dev->name);
	if (!tb->handshake_receive_wq)
		goto err_free_incoming_handshakes;

	tb->handshake_send_wq = alloc_workqueue("tb-kex-%s",
			WQ_UNBOUND | WQ_FREEZABLE, 0, dev->name);
	if (!tb->handshake_send_wq)
		goto err_destroy_handshake_receive;

	tb->packet_crypt_wq = alloc_workqueue("tb-crypt-%s",
			WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM, 0, dev->name);
	if (!tb->packet_crypt_wq)
		goto err_destroy_handshake_send;

	ret = tb_packet_queue_init(&tb->encrypt_queue, tb_packet_encrypt_worker,
				   true, MAX_QUEUED_PACKETS);
	if (ret < 0)
		goto err_destroy_packet_crypt;

	ret = tb_packet_queue_init(&tb->decrypt_queue, tb_packet_decrypt_worker,
				   true, MAX_QUEUED_PACKETS);
	if (ret < 0)
		goto err_free_encrypt_queue;

	ret = tb_ratelimiter_init();
	if (ret < 0)
		goto err_free_decrypt_queue;

	ret = register_netdevice(dev);
	if (ret < 0)
		goto err_uninit_ratelimiter;

	list_add(&tb->device_list, &device_list);

	/* We wait until the end to assign priv_destructor, so that
	 * register_netdevice doesn't call it for us if it fails.
	 */
	dev->priv_destructor = tb_destruct;

	pr_debug("%s: Interface created\n", dev->name);
	return ret;

err_uninit_ratelimiter:
	tb_ratelimiter_uninit();
err_free_decrypt_queue:
	tb_packet_queue_free(&tb->decrypt_queue, true);
err_free_encrypt_queue:
	tb_packet_queue_free(&tb->encrypt_queue, true);
err_destroy_packet_crypt:
	destroy_workqueue(tb->packet_crypt_wq);
err_destroy_handshake_send:
	destroy_workqueue(tb->handshake_send_wq);
err_destroy_handshake_receive:
	destroy_workqueue(tb->handshake_receive_wq);
err_free_incoming_handshakes:
	free_percpu(tb->incoming_handshakes_worker);
err_free_tstats:
	free_percpu(dev->tstats);
err_free_index_hashtable:
	kvfree(tb->index_hashtable);
err_free_peer_hashtable:
	kvfree(tb->peer_hashtable);
	return ret;
}

static struct rtnl_link_ops link_ops __read_mostly = {
	.kind			= KBUILD_MODNAME,
	.priv_size		= sizeof(struct tb_device),
	.setup			= tb_setup,
	.newlink		= tb_newlink,
};

static int tb_netdevice_notification(struct notifier_block *nb,
				     unsigned long action, void *data)
{
	struct net_device *dev = ((struct netdev_notifier_info *)data)->dev;
	struct tb_device *tb = netdev_priv(dev);

	ASSERT_RTNL();

	if (action != NETDEV_REGISTER || dev->netdev_ops != &netdev_ops)
		return 0;

	if (dev_net(dev) == tb->creating_net && tb->have_creating_net_ref) {
		put_net(tb->creating_net);
		tb->have_creating_net_ref = false;
	} else if (dev_net(dev) != tb->creating_net &&
		   !tb->have_creating_net_ref) {
		tb->have_creating_net_ref = true;
		get_net(tb->creating_net);
	}
	return 0;
}

static struct notifier_block netdevice_notifier = {
	.notifier_call = tb_netdevice_notification
};

int __init tb_device_init(void)
{
	int ret;

#ifdef CONFIG_PM_SLEEP
	ret = register_pm_notifier(&pm_notifier);
	if (ret)
		return ret;
#endif

	ret = register_netdevice_notifier(&netdevice_notifier);
	if (ret)
		goto error_pm;

	ret = rtnl_link_register(&link_ops);
	if (ret)
		goto error_netdevice;

	return 0;

error_netdevice:
	unregister_netdevice_notifier(&netdevice_notifier);
error_pm:
#ifdef CONFIG_PM_SLEEP
	unregister_pm_notifier(&pm_notifier);
#endif
	return ret;
}

void tb_device_uninit(void)
{
	rtnl_link_unregister(&link_ops);
	unregister_netdevice_notifier(&netdevice_notifier);
#ifdef CONFIG_PM_SLEEP
	unregister_pm_notifier(&pm_notifier);
#endif
	rcu_barrier();
}
