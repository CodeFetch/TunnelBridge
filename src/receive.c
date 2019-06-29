/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2019 Vincent Wiemann <vincent.wiemann@ironai.com>
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "queueing.h"
#include "device.h"
#include "peer.h"
#include "timers.h"
#include "messages.h"
#include "cookie.h"
#include "socket.h"
#include "client.h"
#include "device.h"

#include <linux/simd.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <net/ip_tunnels.h>

/* Must be called with bh disabled. */
static void update_rx_stats(struct tb_peer *peer, size_t len)
{
	struct pcpu_sw_netstats *tstats =
		get_cpu_ptr(peer->device->dev->tstats);

	u64_stats_update_begin(&tstats->syncp);
	++tstats->rx_packets;
	tstats->rx_bytes += len;
	peer->rx_bytes += len;
	u64_stats_update_end(&tstats->syncp);
	put_cpu_ptr(tstats);
}

#define SKB_TYPE_LE32(skb) (((struct message_header *)(skb)->data)->type)

static size_t validate_header_len(struct sk_buff *skb)
{
	if (unlikely(skb->len < sizeof(struct message_header)))
		return 0;
	if (SKB_TYPE_LE32(skb) == cpu_to_le32(MESSAGE_DATA) &&
	    skb->len >= MESSAGE_MINIMUM_LENGTH)
		return sizeof(struct message_data);
	if (SKB_TYPE_LE32(skb) == cpu_to_le32(MESSAGE_HANDSHAKE_INITIATION) &&
	    skb->len == sizeof(struct message_handshake_initiation))
		return sizeof(struct message_handshake_initiation);
	if (SKB_TYPE_LE32(skb) == cpu_to_le32(MESSAGE_HANDSHAKE_RESPONSE) &&
	    skb->len == sizeof(struct message_handshake_response))
		return sizeof(struct message_handshake_response);
	if (SKB_TYPE_LE32(skb) == cpu_to_le32(MESSAGE_HANDSHAKE_COOKIE) &&
	    skb->len == sizeof(struct message_handshake_cookie))
		return sizeof(struct message_handshake_cookie);
	return 0;
}

static int prepare_skb_header(struct sk_buff *skb, struct tb_device *tb)
{
	size_t data_offset, data_len, header_len;
	struct udphdr *udp;

	if (unlikely(tb_skb_examine_untrusted_ip_hdr(skb) != skb->protocol ||
		     skb_transport_header(skb) < skb->head ||
		     (skb_transport_header(skb) + sizeof(struct udphdr)) >
			     skb_tail_pointer(skb)))
		return -EINVAL; /* Bogus IP header */
	udp = udp_hdr(skb);
	data_offset = (u8 *)udp - skb->data;
	if (unlikely(data_offset > U16_MAX ||
		     data_offset + sizeof(struct udphdr) > skb->len))
		/* Packet has offset at impossible location or isn't big enough
		 * to have UDP fields.
		 */
		return -EINVAL;
	data_len = ntohs(udp->len);
	if (unlikely(data_len < sizeof(struct udphdr) ||
		     data_len > skb->len - data_offset))
		/* UDP packet is reporting too small of a size or lying about
		 * its size.
		 */
		return -EINVAL;
	data_len -= sizeof(struct udphdr);
	data_offset = (u8 *)udp + sizeof(struct udphdr) - skb->data;
	if (unlikely(!pskb_may_pull(skb,
				data_offset + sizeof(struct message_header)) ||
		     pskb_trim(skb, data_len + data_offset) < 0))
		return -EINVAL;
	skb_pull(skb, data_offset);
	if (unlikely(skb->len != data_len))
		/* Final len does not agree with calculated len */
		return -EINVAL;
	header_len = validate_header_len(skb);
	if (unlikely(!header_len))
		return -EINVAL;
	__skb_push(skb, data_offset);
	if (unlikely(!pskb_may_pull(skb, data_offset + header_len)))
		return -EINVAL;
	__skb_pull(skb, data_offset);
	return 0;
}

static void tb_receive_handshake_packet(struct tb_device *tb,
					struct sk_buff *skb)
{
	enum cookie_mac_state mac_state;
	struct tb_peer *peer = NULL;
	/* This is global, so that our load calculation applies to the whole
	 * system. We don't care about races with it at all.
	 */
	static u64 last_under_load;
	bool packet_needs_cookie;
	bool under_load;

	if (SKB_TYPE_LE32(skb) == cpu_to_le32(MESSAGE_HANDSHAKE_COOKIE)) {
		net_dbg_skb_ratelimited("%s: Receiving cookie response from %pISpfsc\n",
					tb->dev->name, skb);
		tb_cookie_message_consume(
			(struct message_handshake_cookie *)skb->data, tb);
		return;
	}

	under_load = skb_queue_len(&tb->incoming_handshakes) >=
		     MAX_QUEUED_INCOMING_HANDSHAKES / 8;
	if (under_load)
		last_under_load = ktime_get_coarse_boottime();
	else if (last_under_load)
		under_load = !tb_birthdate_has_expired(last_under_load, 1);
	mac_state = tb_cookie_validate_packet(&tb->cookie_checker, skb,
					      under_load);
	if ((under_load && mac_state == VALID_MAC_WITH_COOKIE) ||
	    (!under_load && mac_state == VALID_MAC_BUT_NO_COOKIE)) {
		packet_needs_cookie = false;
	} else if (under_load && mac_state == VALID_MAC_BUT_NO_COOKIE) {
		packet_needs_cookie = true;
	} else {
		net_dbg_skb_ratelimited("%s: Invalid MAC of handshake, dropping packet from %pISpfsc\n",
					tb->dev->name, skb);
		return;
	}

	switch (SKB_TYPE_LE32(skb)) {
	case cpu_to_le32(MESSAGE_HANDSHAKE_INITIATION): {
		struct message_handshake_initiation *message =
			(struct message_handshake_initiation *)skb->data;

		if (packet_needs_cookie) {
			tb_packet_send_handshake_cookie(tb, skb,
							message->sender_index);
			return;
		}
		peer = tb_noise_handshake_consume_initiation(message, tb);
		if (unlikely(!peer)) {
			net_dbg_skb_ratelimited("%s: Invalid handshake initiation from %pISpfsc\n",
						tb->dev->name, skb);
			return;
		}
		tb_socket_set_peer_endpoint_from_skb(peer, skb);
		net_dbg_ratelimited("%s: Receiving handshake initiation from peer %llu (%pISpfsc)\n",
				    tb->dev->name, peer->internal_id,
				    &peer->endpoint.addr);
		tb_packet_send_handshake_response(peer);
		break;
	}
	case cpu_to_le32(MESSAGE_HANDSHAKE_RESPONSE): {
		struct message_handshake_response *message =
			(struct message_handshake_response *)skb->data;

		if (packet_needs_cookie) {
			tb_packet_send_handshake_cookie(tb, skb,
							message->sender_index);
			return;
		}
		peer = tb_noise_handshake_consume_response(message, tb);
		if (unlikely(!peer)) {
			net_dbg_skb_ratelimited("%s: Invalid handshake response from %pISpfsc\n",
						tb->dev->name, skb);
			return;
		}
		tb_socket_set_peer_endpoint_from_skb(peer, skb);
		net_dbg_ratelimited("%s: Receiving handshake response from peer %llu (%pISpfsc)\n",
				    tb->dev->name, peer->internal_id,
				    &peer->endpoint.addr);
		if (tb_noise_handshake_begin_session(&peer->handshake,
						     &peer->keypairs)) {
			tb_timers_session_derived(peer);
			tb_timers_handshake_complete(peer);
			/* Calling this function will either send any existing
			 * packets in the queue and not send a keepalive, which
			 * is the best case, Or, if there's nothing in the
			 * queue, it will send a keepalive, in order to give
			 * immediate confirmation of the session.
			 */
			tb_packet_send_keepalive(peer);
		}
		break;
	}
	}

	if (unlikely(!peer)) {
		WARN(1, "Somehow a wrong type of packet wound up in the handshake queue!\n");
		return;
	}

	local_bh_disable();
	update_rx_stats(peer, skb->len);
	local_bh_enable();

	tb_timers_any_authenticated_packet_received(peer);
	tb_timers_any_authenticated_packet_traversal(peer);
	tb_peer_put(peer);
}

void tb_packet_handshake_receive_worker(struct work_struct *work)
{
	struct tb_device *tb = container_of(work, struct multicore_worker,
					    work)->ptr;
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&tb->incoming_handshakes)) != NULL) {
		tb_receive_handshake_packet(tb, skb);
		dev_kfree_skb(skb);
		cond_resched();
	}
}

static void keep_key_fresh(struct tb_peer *peer)
{
	struct noise_keypair *keypair;
	bool send = false;

	if (peer->sent_lastminute_handshake)
		return;

	rcu_read_lock_bh();
	keypair = rcu_dereference_bh(peer->keypairs.current_keypair);
	if (likely(keypair && READ_ONCE(keypair->sending.is_valid)) &&
	    keypair->i_am_the_initiator &&
	    unlikely(tb_birthdate_has_expired(keypair->sending.birthdate,
			REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT)))
		send = true;
	rcu_read_unlock_bh();

	if (send) {
		peer->sent_lastminute_handshake = true;
		tb_packet_send_queued_handshake_initiation(peer, false);
	}
}

static bool decrypt_packet(struct sk_buff *skb, struct noise_symmetric_key *key,
			   simd_context_t *simd_context)
{
	struct scatterlist sg[MAX_SKB_FRAGS + 8];
	struct sk_buff *trailer;
	unsigned int offset;
	int num_frags;

	if (unlikely(!key))
		return false;

	if (unlikely(!READ_ONCE(key->is_valid) ||
		  tb_birthdate_has_expired(key->birthdate, REJECT_AFTER_TIME) ||
		  key->counter.receive.counter >= REJECT_AFTER_MESSAGES)) {
		WRITE_ONCE(key->is_valid, false);
		return false;
	}

	PACKET_CB(skb)->nonce =
		le64_to_cpu(((struct message_data *)skb->data)->counter);

	/* We ensure that the network header is part of the packet before we
	 * call skb_cow_data, so that there's no chance that data is removed
	 * from the skb, so that later we can extract the original endpoint.
	 */
	offset = skb->data - skb_network_header(skb);
	skb_push(skb, offset);
	num_frags = skb_cow_data(skb, 0, &trailer);
	offset += sizeof(struct message_data);
	skb_pull(skb, offset);
	if (unlikely(num_frags < 0 || num_frags > ARRAY_SIZE(sg)))
		return false;

	sg_init_table(sg, num_frags);
	if (skb_to_sgvec(skb, sg, 0, skb->len) <= 0)
		return false;

	if (!chacha20poly1305_decrypt_sg(sg, sg, skb->len, NULL, 0,
					 PACKET_CB(skb)->nonce, key->key,
					 simd_context))
		return false;

	/* Another ugly situation of pushing and pulling the header so as to
	 * keep endpoint information intact.
	 */
	skb_push(skb, offset);
	if (pskb_trim(skb, skb->len - noise_encrypted_len(0)))
		return false;
	skb_pull(skb, offset);

	return true;
}

/* This is RFC6479, a replay detection bitmap algorithm that avoids bitshifts */
static bool counter_validate(union noise_counter *counter, u64 their_counter)
{
	unsigned long index, index_current, top, i;
	bool ret = false;

	spin_lock_bh(&counter->receive.lock);

	if (unlikely(counter->receive.counter >= REJECT_AFTER_MESSAGES + 1 ||
		     their_counter >= REJECT_AFTER_MESSAGES))
		goto out;

	++their_counter;

	if (unlikely((COUNTER_WINDOW_SIZE + their_counter) <
		     counter->receive.counter))
		goto out;

	index = their_counter >> ilog2(BITS_PER_LONG);

	if (likely(their_counter > counter->receive.counter)) {
		index_current = counter->receive.counter >> ilog2(BITS_PER_LONG);
		top = min_t(unsigned long, index - index_current,
			    COUNTER_BITS_TOTAL / BITS_PER_LONG);
		for (i = 1; i <= top; ++i)
			counter->receive.backtrack[(i + index_current) &
				((COUNTER_BITS_TOTAL / BITS_PER_LONG) - 1)] = 0;
		counter->receive.counter = their_counter;
	}

	index &= (COUNTER_BITS_TOTAL / BITS_PER_LONG) - 1;
	ret = !test_and_set_bit(their_counter & (BITS_PER_LONG - 1),
				&counter->receive.backtrack[index]);

out:
	spin_unlock_bh(&counter->receive.lock);
	return ret;
}

#include "selftest/counter.c"

static void tb_packet_consume_data_done(struct tb_peer *peer,
					struct sk_buff *skb,
					struct endpoint *endpoint)
{
	struct net_device *dev = peer->device->dev;
	struct tb_client *client;

	tb_socket_set_peer_endpoint(peer, endpoint);

	if (unlikely(tb_noise_received_with_keypair(&peer->keypairs,
						    PACKET_CB(skb)->keypair))) {
		tb_timers_handshake_complete(peer);
		tb_packet_send_staged_packets(peer);
	}

	keep_key_fresh(peer);

	tb_timers_any_authenticated_packet_received(peer);
	tb_timers_any_authenticated_packet_traversal(peer);

	/* A packet with length 0 is a keepalive packet */
	if (unlikely(!skb->len)) {
		update_rx_stats(peer, message_data_len(0));
		net_dbg_ratelimited("%s: Receiving keepalive packet from peer %llu (%pISpfsc)\n",
				    dev->name, peer->internal_id,
				    &peer->endpoint.addr);
		goto packet_processed;
	}

	tb_timers_data_received(peer);

	if (unlikely(skb_mac_header(skb) < skb->head))
		goto dishonest_packet_size;
	if (unlikely(!(pskb_may_pull(skb, ETH_HLEN))))
		goto dishonest_packet_type;

	skb->protocol = eth_type_trans(skb, dev);
	skb_reset_network_header(skb);
	debug_print_skb_dump(skb, "tb: receive.c: tb_packet_consume_data_done");

	/* We've already verified the Poly1305 auth tag, which means this packet
	 * was not modified in transit. We can therefore tell the networking
	 * stack that all checksums of every layer of encapsulation have already
	 * been checked "by the hardware" and therefore is unneccessary to check
	 * again in software.
	 */
	skb->ip_summed = CHECKSUM_UNNECESSARY;
#ifndef COMPAT_CANNOT_USE_CSUM_LEVEL
	skb->csum_level = ~0; /* All levels */
#endif

	/* TODO we may check the ethernet packet payload size here */

	client = wg_client_lookup_src(&peer->device->client_hashtable, skb);

	if (likely(client)) {
		if(unlikely(client->peer != peer)) {
			printk("Client has roamed");
			/* Has roamed - Does not take reference on new client */
			wg_client_update_peer(client, peer);
		}

		wg_client_put(client);
	} else {
		printk("Client is new");
		/* New client - Does not take reference on new client */
		wg_client_create(peer->device, peer, (const u8 *)&eth_hdr(skb)->h_source);
	}
/* TODO: Use netlink flag here instead */
#if WG_CLIENT_FORWARDING == 1
	if (is_multicast_ether_addr((const u8 *)&eth_hdr(skb)->h_dest)) {
		/* Packet is multicast -> forward packet to all other peers */
		printk("Packet is multicast");
		wg_tap_xmit_multicast(skb_copy(skb, GFP_ATOMIC), dev, peer);
	} else {
		client = wg_client_lookup_dst(&peer->device->client_hashtable, skb);

		if (client) {
			if (peer && peer != client->peer)
				printk("Forwarding to peer");
				/* Forward packet to destination peer */
				wg_tap_xmit_peer(skb_copy(skb, GFP_ATOMIC), dev, client->peer);

			wg_client_put(client);
		} else {
			printk("Destination unknown -> multicast");
			/* We don't know the destination -> forward packet to all other peers */
			wg_tap_xmit_multicast(skb_copy(skb, GFP_ATOMIC), dev, peer);
		}
	}
#endif
	printk("GRO receive");

	if (unlikely(napi_gro_receive(&peer->napi, skb) == GRO_DROP)) {
		++dev->stats.rx_dropped;
		net_dbg_ratelimited("%s: Failed to give packet to userspace from peer %llu (%pISpfsc)\n",
				    dev->name, peer->internal_id,
				    &peer->endpoint.addr);
	} else {
		update_rx_stats(peer, message_data_len(skb->len));
	}
	return;

dishonest_packet_peer:
	net_dbg_skb_ratelimited("%s: Packet has unallowed src IP (%pISc) from peer %llu (%pISpfsc)\n",
				dev->name, skb, peer->internal_id,
				&peer->endpoint.addr);
	++dev->stats.rx_errors;
	++dev->stats.rx_frame_errors;
	goto packet_processed;
dishonest_packet_type:
	net_dbg_ratelimited("%s: Packet is neither ipv4 nor ipv6 from peer %llu (%pISpfsc)\n",
			    dev->name, peer->internal_id, &peer->endpoint.addr);
	++dev->stats.rx_errors;
	++dev->stats.rx_frame_errors;
	goto packet_processed;
dishonest_packet_size:
	net_dbg_ratelimited("%s: Packet has incorrect size from peer %llu (%pISpfsc)\n",
			    dev->name, peer->internal_id, &peer->endpoint.addr);
	++dev->stats.rx_errors;
	++dev->stats.rx_length_errors;
	goto packet_processed;
packet_processed:
	dev_kfree_skb(skb);
}

int tb_packet_rx_poll(struct napi_struct *napi, int budget)
{
	struct tb_peer *peer = container_of(napi, struct tb_peer, napi);
	struct crypt_queue *queue = &peer->rx_queue;
	struct noise_keypair *keypair;
	struct endpoint endpoint;
	enum packet_state state;
	struct sk_buff *skb;
	int work_done = 0;
	bool free;

	if (unlikely(budget <= 0))
		return 0;

	while ((skb = __ptr_ring_peek(&queue->ring)) != NULL &&
	       (state = atomic_read_acquire(&PACKET_CB(skb)->state)) !=
		       PACKET_STATE_UNCRYPTED) {
		__ptr_ring_discard_one(&queue->ring);
		peer = PACKET_PEER(skb);
		keypair = PACKET_CB(skb)->keypair;
		free = true;

		if (unlikely(state != PACKET_STATE_CRYPTED))
			goto next;

		if (unlikely(!counter_validate(&keypair->receiving.counter,
					       PACKET_CB(skb)->nonce))) {
			net_dbg_ratelimited("%s: Packet has invalid nonce %llu (max %llu)\n",
					    peer->device->dev->name,
					    PACKET_CB(skb)->nonce,
					    keypair->receiving.counter.receive.counter);
			goto next;
		}

		if (unlikely(tb_socket_endpoint_from_skb(&endpoint, skb)))
			goto next;

		debug_print_skb_dump(skb, "tb: receive.c: tb_packet_rx_poll");

		tb_reset_packet(skb);
		tb_packet_consume_data_done(peer, skb, &endpoint);
		free = false;

next:
		tb_noise_keypair_put(keypair, false);
		tb_peer_put(peer);
		if (unlikely(free))
			dev_kfree_skb(skb);

		if (++work_done >= budget)
			break;
	}

	if (work_done < budget)
		napi_complete_done(napi, work_done);

	return work_done;
}

void tb_packet_decrypt_worker(struct work_struct *work)
{
	struct crypt_queue *queue = container_of(work, struct multicore_worker,
						 work)->ptr;
	simd_context_t simd_context;
	struct sk_buff *skb;

	simd_get(&simd_context);
	while ((skb = ptr_ring_consume_bh(&queue->ring)) != NULL) {
		enum packet_state state = likely(decrypt_packet(skb,
					   &PACKET_CB(skb)->keypair->receiving,
					   &simd_context)) ?
				PACKET_STATE_CRYPTED : PACKET_STATE_DEAD;
		tb_queue_enqueue_per_peer_napi(&PACKET_PEER(skb)->rx_queue, skb,
					       state);
		simd_relax(&simd_context);
	}

	simd_put(&simd_context);
}

static void tb_packet_consume_data(struct tb_device *tb, struct sk_buff *skb)
{
	__le32 idx = ((struct message_data *)skb->data)->key_idx;
	struct tb_peer *peer = NULL;
	int ret;

	debug_print_skb_dump(skb, "tb: receive.c: tb_packet_consume_data");

	rcu_read_lock_bh();
	PACKET_CB(skb)->keypair =
		(struct noise_keypair *)tb_index_hashtable_lookup(
			tb->index_hashtable, INDEX_HASHTABLE_KEYPAIR, idx,
			&peer);
	if (unlikely(!tb_noise_keypair_get(PACKET_CB(skb)->keypair)))
		goto err_keypair;

	if (unlikely(READ_ONCE(peer->is_dead)))
		goto err;

	ret = tb_queue_enqueue_per_device_and_peer(&tb->decrypt_queue,
						   &peer->rx_queue, skb,
						   tb->packet_crypt_wq,
						   &tb->decrypt_queue.last_cpu);
	if (unlikely(ret == -EPIPE))
		tb_queue_enqueue_per_peer(&peer->rx_queue, skb, PACKET_STATE_DEAD);
	if (likely(!ret || ret == -EPIPE)) {
		rcu_read_unlock_bh();
		return;
	}
err:
	tb_noise_keypair_put(PACKET_CB(skb)->keypair, false);
err_keypair:
	rcu_read_unlock_bh();
	tb_peer_put(peer);
	dev_kfree_skb(skb);
}

void tb_packet_receive(struct tb_device *tb, struct sk_buff *skb)
{
	if (unlikely(prepare_skb_header(skb, tb) < 0))
		goto err;
	switch (SKB_TYPE_LE32(skb)) {
	case cpu_to_le32(MESSAGE_HANDSHAKE_INITIATION):
	case cpu_to_le32(MESSAGE_HANDSHAKE_RESPONSE):
	case cpu_to_le32(MESSAGE_HANDSHAKE_COOKIE): {
		int cpu;

		if (skb_queue_len(&tb->incoming_handshakes) >
			    MAX_QUEUED_INCOMING_HANDSHAKES ||
		    unlikely(!rng_is_initialized())) {
			net_dbg_skb_ratelimited("%s: Dropping handshake packet from %pISpfsc\n",
						tb->dev->name, skb);
			goto err;
		}
		skb_queue_tail(&tb->incoming_handshakes, skb);
		/* Queues up a call to packet_process_queued_handshake_
		 * packets(skb):
		 */
		cpu = tb_cpumask_next_online(&tb->incoming_handshake_cpu);
		queue_work_on(cpu, tb->handshake_receive_wq,
			&per_cpu_ptr(tb->incoming_handshakes_worker, cpu)->work);
		break;
	}
	case cpu_to_le32(MESSAGE_DATA):
		PACKET_CB(skb)->ds = ip_tunnel_get_dsfield(ip_hdr(skb), skb);
		debug_print_skb_dump(skb, "tb: receive.c: tb_packet_receive");
		tb_packet_consume_data(tb, skb);
		break;
	default:
		net_dbg_skb_ratelimited("%s: Invalid packet from %pISpfsc\n",
					tb->dev->name, skb);
		goto err;
	}
	return;

err:
	dev_kfree_skb(skb);
}
