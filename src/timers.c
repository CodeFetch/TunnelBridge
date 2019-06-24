/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2019 Vincent Wiemann <vincent.wiemann@ironai.com>
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "timers.h"
#include "device.h"
#include "peer.h"
#include "queueing.h"
#include "socket.h"

/*
 * - Timer for retransmitting the handshake if we don't hear back after
 * `REKEY_TIMEOUT + jitter` ms.
 *
 * - Timer for sending empty packet if we have received a packet but after have
 * not sent one for `KEEPALIVE_TIMEOUT` ms.
 *
 * - Timer for initiating new handshake if we have sent a packet but after have
 * not received one (even empty) for `(KEEPALIVE_TIMEOUT + REKEY_TIMEOUT) +
 * jitter` ms.
 *
 * - Timer for zeroing out all ephemeral keys after `(REJECT_AFTER_TIME * 3)` ms
 * if no new keys have been received.
 *
 * - Timer for, if enabled, sending an empty authenticated packet every user-
 * specified seconds.
 */

static inline void mod_peer_timer(struct tb_peer *peer,
				  struct timer_list *timer,
				  unsigned long expires)
{
	rcu_read_lock_bh();
	if (likely(netif_running(peer->device->dev) &&
		   !READ_ONCE(peer->is_dead)))
		mod_timer(timer, expires);
	rcu_read_unlock_bh();
}

static void tb_expired_retransmit_handshake(struct timer_list *timer)
{
	struct tb_peer *peer = from_timer(peer, timer,
					  timer_retransmit_handshake);

	if (peer->timer_handshake_attempts > MAX_TIMER_HANDSHAKES) {
		pr_debug("%s: Handshake for peer %llu (%pISpfsc) did not complete after %d attempts, giving up\n",
			 peer->device->dev->name, peer->internal_id,
			 &peer->endpoint.addr, MAX_TIMER_HANDSHAKES + 2);

		del_timer(&peer->timer_send_keepalive);
		/* We drop all packets without a keypair and don't try again,
		 * if we try unsuccessfully for too long to make a handshake.
		 */
		tb_packet_purge_staged_packets(peer);

		/* We set a timer for destroying any residue that might be left
		 * of a partial exchange.
		 */
		if (!timer_pending(&peer->timer_zero_key_material))
			mod_peer_timer(peer, &peer->timer_zero_key_material,
				       jiffies + REJECT_AFTER_TIME * 3 * HZ);
	} else {
		++peer->timer_handshake_attempts;
		pr_debug("%s: Handshake for peer %llu (%pISpfsc) did not complete after %d seconds, retrying (try %d)\n",
			 peer->device->dev->name, peer->internal_id,
			 &peer->endpoint.addr, REKEY_TIMEOUT,
			 peer->timer_handshake_attempts + 1);

		/* We clear the endpoint address src address, in case this is
		 * the cause of trouble.
		 */
		tb_socket_clear_peer_endpoint_src(peer);

		tb_packet_send_queued_handshake_initiation(peer, true);
	}
}

static void tb_expired_send_keepalive(struct timer_list *timer)
{
	struct tb_peer *peer = from_timer(peer, timer, timer_send_keepalive);

	tb_packet_send_keepalive(peer);
	if (peer->timer_need_another_keepalive) {
		peer->timer_need_another_keepalive = false;
		mod_peer_timer(peer, &peer->timer_send_keepalive,
			       jiffies + KEEPALIVE_TIMEOUT * HZ);
	}
}

static void tb_expired_new_handshake(struct timer_list *timer)
{
	struct tb_peer *peer = from_timer(peer, timer, timer_new_handshake);

	pr_debug("%s: Retrying handshake with peer %llu (%pISpfsc) because we stopped hearing back after %d seconds\n",
		 peer->device->dev->name, peer->internal_id,
		 &peer->endpoint.addr, KEEPALIVE_TIMEOUT + REKEY_TIMEOUT);
	/* We clear the endpoint address src address, in case this is the cause
	 * of trouble.
	 */
	tb_socket_clear_peer_endpoint_src(peer);
	tb_packet_send_queued_handshake_initiation(peer, false);
}

static void tb_expired_zero_key_material(struct timer_list *timer)
{
	struct tb_peer *peer = from_timer(peer, timer, timer_zero_key_material);

	rcu_read_lock_bh();
	if (!READ_ONCE(peer->is_dead)) {
		tb_peer_get(peer);
		if (!queue_work(peer->device->handshake_send_wq,
				&peer->clear_peer_work))
			/* If the work was already on the queue, we want to drop
			 * the extra reference.
			 */
			tb_peer_put(peer);
	}
	rcu_read_unlock_bh();
}

static void tb_queued_expired_zero_key_material(struct work_struct *work)
{
	struct tb_peer *peer = container_of(work, struct tb_peer,
					    clear_peer_work);

	pr_debug("%s: Zeroing out all keys for peer %llu (%pISpfsc), since we haven't received a new one in %d seconds\n",
		 peer->device->dev->name, peer->internal_id,
		 &peer->endpoint.addr, REJECT_AFTER_TIME * 3);
	tb_noise_handshake_clear(&peer->handshake);
	tb_noise_keypairs_clear(&peer->keypairs);
	tb_peer_put(peer);
}

static void tb_expired_send_persistent_keepalive(struct timer_list *timer)
{
	struct tb_peer *peer = from_timer(peer, timer,
					  timer_persistent_keepalive);

	if (likely(peer->persistent_keepalive_interval))
		tb_packet_send_keepalive(peer);
}

/* Should be called after an authenticated data packet is sent. */
void tb_timers_data_sent(struct tb_peer *peer)
{
	if (!timer_pending(&peer->timer_new_handshake))
		mod_peer_timer(peer, &peer->timer_new_handshake,
			jiffies + (KEEPALIVE_TIMEOUT + REKEY_TIMEOUT) * HZ +
			prandom_u32_max(REKEY_TIMEOUT_JITTER_MAX_JIFFIES));
}

/* Should be called after an authenticated data packet is received. */
void tb_timers_data_received(struct tb_peer *peer)
{
	if (likely(netif_running(peer->device->dev))) {
		if (!timer_pending(&peer->timer_send_keepalive))
			mod_peer_timer(peer, &peer->timer_send_keepalive,
				       jiffies + KEEPALIVE_TIMEOUT * HZ);
		else
			peer->timer_need_another_keepalive = true;
	}
}

/* Should be called after any type of authenticated packet is sent, whether
 * keepalive, data, or handshake.
 */
void tb_timers_any_authenticated_packet_sent(struct tb_peer *peer)
{
	del_timer(&peer->timer_send_keepalive);
}

/* Should be called after any type of authenticated packet is received, whether
 * keepalive, data, or handshake.
 */
void tb_timers_any_authenticated_packet_received(struct tb_peer *peer)
{
	del_timer(&peer->timer_new_handshake);
}

/* Should be called after a handshake initiation message is sent. */
void tb_timers_handshake_initiated(struct tb_peer *peer)
{
	mod_peer_timer(peer, &peer->timer_retransmit_handshake,
		       jiffies + REKEY_TIMEOUT * HZ +
		       prandom_u32_max(REKEY_TIMEOUT_JITTER_MAX_JIFFIES));
}

/* Should be called after a handshake response message is received and processed
 * or when getting key confirmation via the first data message.
 */
void tb_timers_handshake_complete(struct tb_peer *peer)
{
	del_timer(&peer->timer_retransmit_handshake);
	peer->timer_handshake_attempts = 0;
	peer->sent_lastminute_handshake = false;
	ktime_get_real_ts64(&peer->walltime_last_handshake);
}

/* Should be called after an ephemeral key is created, which is before sending a
 * handshake response or after receiving a handshake response.
 */
void tb_timers_session_derived(struct tb_peer *peer)
{
	mod_peer_timer(peer, &peer->timer_zero_key_material,
		       jiffies + REJECT_AFTER_TIME * 3 * HZ);
}

/* Should be called before a packet with authentication, whether
 * keepalive, data, or handshakem is sent, or after one is received.
 */
void tb_timers_any_authenticated_packet_traversal(struct tb_peer *peer)
{
	if (peer->persistent_keepalive_interval)
		mod_peer_timer(peer, &peer->timer_persistent_keepalive,
			jiffies + peer->persistent_keepalive_interval * HZ);
}

void tb_timers_init(struct tb_peer *peer)
{
	timer_setup(&peer->timer_retransmit_handshake,
		    tb_expired_retransmit_handshake, 0);
	timer_setup(&peer->timer_send_keepalive, tb_expired_send_keepalive, 0);
	timer_setup(&peer->timer_new_handshake, tb_expired_new_handshake, 0);
	timer_setup(&peer->timer_zero_key_material,
		    tb_expired_zero_key_material, 0);
	timer_setup(&peer->timer_persistent_keepalive,
		    tb_expired_send_persistent_keepalive, 0);
	INIT_WORK(&peer->clear_peer_work, tb_queued_expired_zero_key_material);
	peer->timer_handshake_attempts = 0;
	peer->sent_lastminute_handshake = false;
	peer->timer_need_another_keepalive = false;
}

void tb_timers_stop(struct tb_peer *peer)
{
	del_timer_sync(&peer->timer_retransmit_handshake);
	del_timer_sync(&peer->timer_send_keepalive);
	del_timer_sync(&peer->timer_new_handshake);
	del_timer_sync(&peer->timer_zero_key_material);
	del_timer_sync(&peer->timer_persistent_keepalive);
	flush_work(&peer->clear_peer_work);
}
