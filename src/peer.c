/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2019 Vincent Wiemann <vincent.wiemann@ironai.com>
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "peer.h"
#include "device.h"
#include "queueing.h"
#include "timers.h"
#include "peerlookup.h"
#include "noise.h"

#include <linux/kref.h>
#include <linux/lockdep.h>
#include <linux/rcupdate.h>
#include <linux/list.h>

static atomic64_t peer_counter = ATOMIC64_INIT(0);

struct tb_peer *tb_peer_create(struct tb_device *tb,
			       const u8 public_key[NOISE_PUBLIC_KEY_LEN],
			       const u8 preshared_key[NOISE_SYMMETRIC_KEY_LEN])
{
	struct tb_peer *peer;

	lockdep_assert_held(&tb->device_update_lock);

	if (tb->num_peers >= MAX_PEERS_PER_DEVICE)
		return NULL;

	peer = kzalloc(sizeof(*peer), GFP_KERNEL);
	if (unlikely(!peer))
		return NULL;
	peer->device = tb;

	if (!tb_noise_handshake_init(&peer->handshake, &tb->static_identity,
				     public_key, preshared_key, peer))
		goto err_1;
	if (dst_cache_init(&peer->endpoint_cache, GFP_KERNEL))
		goto err_1;
	if (tb_packet_queue_init(&peer->tx_queue, tb_packet_tx_worker, false,
				 MAX_QUEUED_PACKETS))
		goto err_2;
	if (tb_packet_queue_init(&peer->rx_queue, NULL, false,
				 MAX_QUEUED_PACKETS))
		goto err_3;

	peer->internal_id = atomic64_inc_return(&peer_counter);
	peer->serial_work_cpu = nr_cpumask_bits;
	tb_cookie_init(&peer->latest_cookie);
	tb_timers_init(peer);
	tb_cookie_checker_precompute_peer_keys(peer);
	spin_lock_init(&peer->keypairs.keypair_update_lock);
	INIT_WORK(&peer->transmit_handshake_work,
		  tb_packet_handshake_send_worker);
	rwlock_init(&peer->endpoint_lock);
	kref_init(&peer->refcount);
	skb_queue_head_init(&peer->staged_packet_queue);
	atomic64_set(&peer->last_sent_handshake,
		     (u64)ktime_get_coarse_boottime() -
		     (u64)(REKEY_TIMEOUT + 1) * NSEC_PER_SEC);
	set_bit(NAPI_STATE_NO_BUSY_POLL, &peer->napi.state);
	netif_napi_add(tb->dev, &peer->napi, tb_packet_rx_poll,
		       NAPI_POLL_WEIGHT);
	napi_enable(&peer->napi);
	list_add_tail(&peer->peer_list, &tb->peer_list);
	INIT_LIST_HEAD(&peer->allowedips_list);
	tb_pubkey_hashtable_add(tb->peer_hashtable, peer);
	++tb->num_peers;
	pr_debug("%s: Peer %llu created\n", tb->dev->name, peer->internal_id);
	return peer;

err_3:
	tb_packet_queue_free(&peer->tx_queue, false);
err_2:
	dst_cache_destroy(&peer->endpoint_cache);
err_1:
	kfree(peer);
	return NULL;
}

struct tb_peer *tb_peer_get_maybe_zero(struct tb_peer *peer)
{
	RCU_LOCKDEP_WARN(!rcu_read_lock_bh_held(),
			 "Taking peer reference without holding the RCU read lock");
	if (unlikely(!peer || !kref_get_unless_zero(&peer->refcount)))
		return NULL;
	return peer;
}

static void peer_make_dead(struct tb_peer *peer)
{
	/* Remove from configuration-time lookup structures. */
	list_del_init(&peer->peer_list);
	tb_allowedips_remove_by_peer(&peer->device->peer_allowedips, peer,
				     &peer->device->device_update_lock);
	tb_pubkey_hashtable_remove(peer->device->peer_hashtable, peer);

	/* Mark as dead, so that we don't allow jumping contexts after. */
	WRITE_ONCE(peer->is_dead, true);

	/* The caller must now synchronize_rcu() for this to take effect. */
}

static void peer_remove_after_dead(struct tb_peer *peer)
{
	WARN_ON(!peer->is_dead);

	/* No more keypairs can be created for this peer, since is_dead protects
	 * add_new_keypair, so we can now destroy existing ones.
	 */
	tb_noise_keypairs_clear(&peer->keypairs);

	/* Destroy all ongoing timers that were in-flight at the beginning of
	 * this function.
	 */
	tb_timers_stop(peer);

	/* The transition between packet encryption/decryption queues isn't
	 * guarded by is_dead, but each reference's life is strictly bounded by
	 * two generations: once for parallel crypto and once for serial
	 * ingestion, so we can simply flush twice, and be sure that we no
	 * longer have references inside these queues.
	 */

	/* a) For encrypt/decrypt. */
	flush_workqueue(peer->device->packet_crypt_wq);
	/* b.1) For send (but not receive, since that's napi). */
	flush_workqueue(peer->device->packet_crypt_wq);
	/* b.2.1) For receive (but not send, since that's wq). */
	napi_disable(&peer->napi);
	/* b.2.1) It's now safe to remove the napi struct, which must be done
	 * here from process context.
	 */
	netif_napi_del(&peer->napi);

	/* Ensure any workstructs we own (like transmit_handshake_work or
	 * clear_peer_work) no longer are in use.
	 */
	flush_workqueue(peer->device->handshake_send_wq);

	/* After the above flushes, a peer might still be active in a few
	 * different contexts: 1) from xmit(), before hitting is_dead and
	 * returning, 2) from tb_packet_consume_data(), before hitting is_dead
	 * and returning, 3) from tb_receive_handshake_packet() after a point
	 * where it has processed an incoming handshake packet, but where
	 * all calls to pass it off to timers fails because of is_dead. We won't
	 * have new references in (1) eventually, because we're removed from
	 * allowedips; we won't have new references in (2) eventually, because
	 * tb_index_hashtable_lookup will always return NULL, since we removed
	 * all existing keypairs and no more can be created; we won't have new
	 * references in (3) eventually, because we're removed from the pubkey
	 * hash table, which allows for a maximum of one handshake response,
	 * via the still-uncleared index hashtable entry, but not more than one,
	 * and in tb_cookie_message_consume, the lookup eventually gets a peer
	 * with a refcount of zero, so no new reference is taken.
	 */

	--peer->device->num_peers;
	tb_peer_put(peer);
}

/* We have a separate "remove" function make sure that all active places where
 * a peer is currently operating will eventually come to an end and not pass
 * their reference onto another context.
 */
void tb_peer_remove(struct tb_peer *peer)
{
	if (unlikely(!peer))
		return;
	lockdep_assert_held(&peer->device->device_update_lock);

	peer_make_dead(peer);
	synchronize_rcu();
	peer_remove_after_dead(peer);
}

void tb_peer_remove_all(struct tb_device *tb)
{
	struct list_head dead_peers = LIST_HEAD_INIT(dead_peers);
	struct tb_peer *peer, *temp;

	lockdep_assert_held(&tb->device_update_lock);

	/* Avoid having to traverse individually for each one. */
	tb_allowedips_free(&tb->peer_allowedips, &tb->device_update_lock);

	list_for_each_entry_safe(peer, temp, &tb->peer_list, peer_list) {
		peer_make_dead(peer);
		list_add_tail(&peer->peer_list, &dead_peers);
	}
	synchronize_rcu();
	list_for_each_entry_safe(peer, temp, &dead_peers, peer_list)
		peer_remove_after_dead(peer);
}

static void rcu_release(struct rcu_head *rcu)
{
	struct tb_peer *peer = container_of(rcu, struct tb_peer, rcu);

	dst_cache_destroy(&peer->endpoint_cache);
	tb_packet_queue_free(&peer->rx_queue, false);
	tb_packet_queue_free(&peer->tx_queue, false);

	/* The final zeroing takes care of clearing any remaining handshake key
	 * material and other potentially sensitive information.
	 */
	kzfree(peer);
}

static void kref_release(struct kref *refcount)
{
	struct tb_peer *peer = container_of(refcount, struct tb_peer, refcount);

	pr_debug("%s: Peer %llu (%pISpfsc) destroyed\n",
		 peer->device->dev->name, peer->internal_id,
		 &peer->endpoint.addr);

	/* Remove ourself from dynamic runtime lookup structures, now that the
	 * last reference is gone.
	 */
	tb_index_hashtable_remove(peer->device->index_hashtable,
				  &peer->handshake.entry);

	/* Remove any lingering packets that didn't have a chance to be
	 * transmitted.
	 */
	tb_packet_purge_staged_packets(peer);

	/* Free the memory used. */
	call_rcu(&peer->rcu, rcu_release);
}

void tb_peer_put(struct tb_peer *peer)
{
	if (unlikely(!peer))
		return;
	kref_put(&peer->refcount, kref_release);
}
