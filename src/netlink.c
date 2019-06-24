/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2019 Vincent Wiemann <vincent.wiemann@ironai.com>
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "netlink.h"
#include "device.h"
#include "peer.h"
#include "socket.h"
#include "queueing.h"
#include "messages.h"
#include "uapi/tunnelbridge.h"
#include <linux/if.h>
#include <net/genetlink.h>
#include <net/sock.h>

static struct genl_family genl_family;

static const struct nla_policy device_policy[TBDEVICE_A_MAX + 1] = {
	[TBDEVICE_A_IFINDEX]		= { .type = NLA_U32 },
	[TBDEVICE_A_IFNAME]		= { .type = NLA_NUL_STRING, .len = IFNAMSIZ - 1 },
	[TBDEVICE_A_PRIVATE_KEY]	= { .type = NLA_EXACT_LEN, .len = NOISE_PUBLIC_KEY_LEN },
	[TBDEVICE_A_PUBLIC_KEY]		= { .type = NLA_EXACT_LEN, .len = NOISE_PUBLIC_KEY_LEN },
	[TBDEVICE_A_FLAGS]		= { .type = NLA_U32 },
	[TBDEVICE_A_LISTEN_PORT]	= { .type = NLA_U16 },
	[TBDEVICE_A_FWMARK]		= { .type = NLA_U32 },
	[TBDEVICE_A_PEERS]		= { .type = NLA_NESTED }
};

static const struct nla_policy peer_policy[TBPEER_A_MAX + 1] = {
	[TBPEER_A_PUBLIC_KEY]				= { .type = NLA_EXACT_LEN, .len = NOISE_PUBLIC_KEY_LEN },
	[TBPEER_A_PRESHARED_KEY]			= { .type = NLA_EXACT_LEN, .len = NOISE_SYMMETRIC_KEY_LEN },
	[TBPEER_A_FLAGS]				= { .type = NLA_U32 },
	[TBPEER_A_ENDPOINT]				= { .type = NLA_MIN_LEN, .len = sizeof(struct sockaddr) },
	[TBPEER_A_PERSISTENT_KEEPALIVE_INTERVAL]	= { .type = NLA_U16 },
	[TBPEER_A_LAST_HANDSHAKE_TIME]			= { .type = NLA_EXACT_LEN, .len = sizeof(struct __kernel_timespec) },
	[TBPEER_A_RX_BYTES]				= { .type = NLA_U64 },
	[TBPEER_A_TX_BYTES]				= { .type = NLA_U64 },
	[TBPEER_A_ALLOWEDIPS]				= { .type = NLA_NESTED },
	[TBPEER_A_PROTOCOL_VERSION]			= { .type = NLA_U32 }
};

static const struct nla_policy allowedip_policy[TBALLOWEDIP_A_MAX + 1] = {
	[TBALLOWEDIP_A_FAMILY]		= { .type = NLA_U16 },
	[TBALLOWEDIP_A_IPADDR]		= { .type = NLA_MIN_LEN, .len = sizeof(struct in_addr) },
	[TBALLOWEDIP_A_CIDR_MASK]	= { .type = NLA_U8 }
};

static struct tb_device *lookup_interface(struct nlattr **attrs,
					  struct sk_buff *skb)
{
	struct net_device *dev = NULL;

	if (!attrs[TBDEVICE_A_IFINDEX] == !attrs[TBDEVICE_A_IFNAME])
		return ERR_PTR(-EBADR);
	if (attrs[TBDEVICE_A_IFINDEX])
		dev = dev_get_by_index(sock_net(skb->sk),
				       nla_get_u32(attrs[TBDEVICE_A_IFINDEX]));
	else if (attrs[TBDEVICE_A_IFNAME])
		dev = dev_get_by_name(sock_net(skb->sk),
				      nla_data(attrs[TBDEVICE_A_IFNAME]));
	if (!dev)
		return ERR_PTR(-ENODEV);
	if (!dev->rtnl_link_ops || !dev->rtnl_link_ops->kind ||
	    strcmp(dev->rtnl_link_ops->kind, KBUILD_MODNAME)) {
		dev_put(dev);
		return ERR_PTR(-EOPNOTSUPP);
	}
	return netdev_priv(dev);
}

static int get_allowedips(struct sk_buff *skb, const u8 *ip, u8 cidr,
			  int family)
{
	struct nlattr *allowedip_nest;

	allowedip_nest = nla_nest_start(skb, 0);
	if (!allowedip_nest)
		return -EMSGSIZE;

	if (nla_put_u8(skb, TBALLOWEDIP_A_CIDR_MASK, cidr) ||
	    nla_put_u16(skb, TBALLOWEDIP_A_FAMILY, family) ||
	    nla_put(skb, TBALLOWEDIP_A_IPADDR, family == AF_INET6 ?
		    sizeof(struct in6_addr) : sizeof(struct in_addr), ip)) {
		nla_nest_cancel(skb, allowedip_nest);
		return -EMSGSIZE;
	}

	nla_nest_end(skb, allowedip_nest);
	return 0;
}

static int
get_peer(struct tb_peer *peer, struct allowedips_node **next_allowedips_node,
	 u64 *allowedips_seq, struct sk_buff *skb)
{
	struct nlattr *allowedips_nest, *peer_nest = nla_nest_start(skb, 0);
	struct allowedips_node *allowedips_node = *next_allowedips_node;
	bool fail;

	if (!peer_nest)
		return -EMSGSIZE;

	down_read(&peer->handshake.lock);
	fail = nla_put(skb, TBPEER_A_PUBLIC_KEY, NOISE_PUBLIC_KEY_LEN,
		       peer->handshake.remote_static);
	up_read(&peer->handshake.lock);
	if (fail)
		goto err;

	if (!allowedips_node) {
		const struct __kernel_timespec last_handshake = {
			.tv_sec = peer->walltime_last_handshake.tv_sec,
			.tv_nsec = peer->walltime_last_handshake.tv_nsec
		};

		down_read(&peer->handshake.lock);
		fail = nla_put(skb, TBPEER_A_PRESHARED_KEY,
			       NOISE_SYMMETRIC_KEY_LEN,
			       peer->handshake.preshared_key);
		up_read(&peer->handshake.lock);
		if (fail)
			goto err;

		if (nla_put(skb, TBPEER_A_LAST_HANDSHAKE_TIME,
			    sizeof(last_handshake), &last_handshake) ||
		    nla_put_u16(skb, TBPEER_A_PERSISTENT_KEEPALIVE_INTERVAL,
				peer->persistent_keepalive_interval) ||
		    nla_put_u64_64bit(skb, TBPEER_A_TX_BYTES, peer->tx_bytes,
				      TBPEER_A_UNSPEC) ||
		    nla_put_u64_64bit(skb, TBPEER_A_RX_BYTES, peer->rx_bytes,
				      TBPEER_A_UNSPEC) ||
		    nla_put_u32(skb, TBPEER_A_PROTOCOL_VERSION, 1))
			goto err;

		read_lock_bh(&peer->endpoint_lock);
		if (peer->endpoint.addr.sa_family == AF_INET)
			fail = nla_put(skb, TBPEER_A_ENDPOINT,
				       sizeof(peer->endpoint.addr4),
				       &peer->endpoint.addr4);
		else if (peer->endpoint.addr.sa_family == AF_INET6)
			fail = nla_put(skb, TBPEER_A_ENDPOINT,
				       sizeof(peer->endpoint.addr6),
				       &peer->endpoint.addr6);
		read_unlock_bh(&peer->endpoint_lock);
		if (fail)
			goto err;
		allowedips_node =
			list_first_entry_or_null(&peer->allowedips_list,
					struct allowedips_node, peer_list);
	}
	if (!allowedips_node)
		goto no_allowedips;
	if (!*allowedips_seq)
		*allowedips_seq = peer->device->peer_allowedips.seq;
	else if (*allowedips_seq != peer->device->peer_allowedips.seq)
		goto no_allowedips;

	allowedips_nest = nla_nest_start(skb, TBPEER_A_ALLOWEDIPS);
	if (!allowedips_nest)
		goto err;

	list_for_each_entry_from(allowedips_node, &peer->allowedips_list,
				 peer_list) {
		u8 cidr, ip[16] __aligned(__alignof(u64));
		int family;

		family = tb_allowedips_read_node(allowedips_node, ip, &cidr);
		if (get_allowedips(skb, ip, cidr, family)) {
			nla_nest_end(skb, allowedips_nest);
			nla_nest_end(skb, peer_nest);
			*next_allowedips_node = allowedips_node;
			return -EMSGSIZE;
		}
	}
	nla_nest_end(skb, allowedips_nest);
no_allowedips:
	nla_nest_end(skb, peer_nest);
	*next_allowedips_node = NULL;
	*allowedips_seq = 0;
	return 0;
err:
	nla_nest_cancel(skb, peer_nest);
	return -EMSGSIZE;
}

static int tb_get_device_start(struct netlink_callback *cb)
{
	struct nlattr **attrs = genl_family_attrbuf(&genl_family);
	struct tb_device *tb;
	int ret;

	ret = nlmsg_parse(cb->nlh, GENL_HDRLEN + genl_family.hdrsize, attrs,
			  genl_family.maxattr, device_policy, NULL);
	if (ret < 0)
		return ret;
	tb = lookup_interface(attrs, cb->skb);
	if (IS_ERR(tb))
		return PTR_ERR(tb);
	cb->args[0] = (long)tb;
	return 0;
}

static int tb_get_device_dump(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct tb_peer *peer, *next_peer_cursor, *last_peer_cursor;
	struct nlattr *peers_nest;
	struct tb_device *tb;
	int ret = -EMSGSIZE;
	bool done = true;
	void *hdr;

	tb = (struct tb_device *)cb->args[0];
	next_peer_cursor = (struct tb_peer *)cb->args[1];
	last_peer_cursor = (struct tb_peer *)cb->args[1];

	rtnl_lock();
	mutex_lock(&tb->device_update_lock);
	cb->seq = tb->device_update_gen;

	hdr = genlmsg_put(skb, NETLINK_CB(cb->skb).portid, cb->nlh->nlmsg_seq,
			  &genl_family, NLM_F_MULTI, TB_CMD_GET_DEVICE);
	if (!hdr)
		goto out;
	genl_dump_check_consistent(cb, hdr);

	if (!last_peer_cursor) {
		if (nla_put_u16(skb, TBDEVICE_A_LISTEN_PORT,
				tb->incoming_port) ||
		    nla_put_u32(skb, TBDEVICE_A_FWMARK, tb->fwmark) ||
		    nla_put_u32(skb, TBDEVICE_A_IFINDEX, tb->dev->ifindex) ||
		    nla_put_string(skb, TBDEVICE_A_IFNAME, tb->dev->name))
			goto out;

		down_read(&tb->static_identity.lock);
		if (tb->static_identity.has_identity) {
			if (nla_put(skb, TBDEVICE_A_PRIVATE_KEY,
				    NOISE_PUBLIC_KEY_LEN,
				    tb->static_identity.static_private) ||
			    nla_put(skb, TBDEVICE_A_PUBLIC_KEY,
				    NOISE_PUBLIC_KEY_LEN,
				    tb->static_identity.static_public)) {
				up_read(&tb->static_identity.lock);
				goto out;
			}
		}
		up_read(&tb->static_identity.lock);
	}

	peers_nest = nla_nest_start(skb, TBDEVICE_A_PEERS);
	if (!peers_nest)
		goto out;
	ret = 0;
	/* If the last cursor was removed via list_del_init in peer_remove, then
	 * we just treat this the same as there being no more peers left. The
	 * reason is that seq_nr should indicate to userspace that this isn't a
	 * coherent dump anyway, so they'll try again.
	 */
	if (list_empty(&tb->peer_list) ||
	    (last_peer_cursor && list_empty(&last_peer_cursor->peer_list))) {
		nla_nest_cancel(skb, peers_nest);
		goto out;
	}
	lockdep_assert_held(&tb->device_update_lock);
	peer = list_prepare_entry(last_peer_cursor, &tb->peer_list, peer_list);
	list_for_each_entry_continue(peer, &tb->peer_list, peer_list) {
		if (get_peer(peer, (struct allowedips_node **)&cb->args[2],
			     (u64 *)&cb->args[4] /* and args[5] */, skb)) {
			done = false;
			break;
		}
		next_peer_cursor = peer;
	}
	nla_nest_end(skb, peers_nest);

out:
	if (!ret && !done && next_peer_cursor)
		tb_peer_get(next_peer_cursor);
	tb_peer_put(last_peer_cursor);
	mutex_unlock(&tb->device_update_lock);
	rtnl_unlock();

	if (ret) {
		genlmsg_cancel(skb, hdr);
		return ret;
	}
	genlmsg_end(skb, hdr);
	if (done) {
		cb->args[1] = 0;
		return 0;
	}
	cb->args[1] = (long)next_peer_cursor;
	return skb->len;

	/* At this point, we can't really deal ourselves with safely zeroing out
	 * the private key material after usage. This will need an additional API
	 * in the kernel for marking skbs as zero_on_free.
	 */
}

static int tb_get_device_done(struct netlink_callback *cb)
{
	struct tb_device *tb = (struct tb_device *)cb->args[0];
	struct tb_peer *peer = (struct tb_peer *)cb->args[1];

	if (tb)
		dev_put(tb->dev);
	tb_peer_put(peer);
	return 0;
}

static int set_port(struct tb_device *tb, u16 port)
{
	struct tb_peer *peer;

	if (tb->incoming_port == port)
		return 0;
	list_for_each_entry(peer, &tb->peer_list, peer_list)
		tb_socket_clear_peer_endpoint_src(peer);
	if (!netif_running(tb->dev)) {
		tb->incoming_port = port;
		return 0;
	}
	return tb_socket_init(tb, port);
}

static int set_allowedip(struct tb_peer *peer, struct nlattr **attrs)
{
	int ret = -EINVAL;
	u16 family;
	u8 cidr;

	if (!attrs[TBALLOWEDIP_A_FAMILY] || !attrs[TBALLOWEDIP_A_IPADDR] ||
	    !attrs[TBALLOWEDIP_A_CIDR_MASK])
		return ret;
	family = nla_get_u16(attrs[TBALLOWEDIP_A_FAMILY]);
	cidr = nla_get_u8(attrs[TBALLOWEDIP_A_CIDR_MASK]);

	if (family == AF_INET && cidr <= 32 &&
	    nla_len(attrs[TBALLOWEDIP_A_IPADDR]) == sizeof(struct in_addr))
		ret = tb_allowedips_insert_v4(
			&peer->device->peer_allowedips,
			nla_data(attrs[TBALLOWEDIP_A_IPADDR]), cidr, peer,
			&peer->device->device_update_lock);
	else if (family == AF_INET6 && cidr <= 128 &&
		 nla_len(attrs[TBALLOWEDIP_A_IPADDR]) == sizeof(struct in6_addr))
		ret = tb_allowedips_insert_v6(
			&peer->device->peer_allowedips,
			nla_data(attrs[TBALLOWEDIP_A_IPADDR]), cidr, peer,
			&peer->device->device_update_lock);

	return ret;
}

static int set_peer(struct tb_device *tb, struct nlattr **attrs)
{
	u8 *public_key = NULL, *preshared_key = NULL;
	struct tb_peer *peer = NULL;
	u32 flags = 0;
	int ret;

	ret = -EINVAL;
	if (attrs[TBPEER_A_PUBLIC_KEY] &&
	    nla_len(attrs[TBPEER_A_PUBLIC_KEY]) == NOISE_PUBLIC_KEY_LEN)
		public_key = nla_data(attrs[TBPEER_A_PUBLIC_KEY]);
	else
		goto out;
	if (attrs[TBPEER_A_PRESHARED_KEY] &&
	    nla_len(attrs[TBPEER_A_PRESHARED_KEY]) == NOISE_SYMMETRIC_KEY_LEN)
		preshared_key = nla_data(attrs[TBPEER_A_PRESHARED_KEY]);
	if (attrs[TBPEER_A_FLAGS])
		flags = nla_get_u32(attrs[TBPEER_A_FLAGS]);

	ret = -EPFNOSUPPORT;
	if (attrs[TBPEER_A_PROTOCOL_VERSION]) {
		if (nla_get_u32(attrs[TBPEER_A_PROTOCOL_VERSION]) != 1)
			goto out;
	}

	peer = tb_pubkey_hashtable_lookup(tb->peer_hashtable,
					  nla_data(attrs[TBPEER_A_PUBLIC_KEY]));
	if (!peer) { /* Peer doesn't exist yet. Add a new one. */
		ret = -ENODEV;
		if (flags & TBPEER_F_REMOVE_ME)
			goto out; /* Tried to remove a non-existing peer. */

		/* The peer is new, so there aren't allowed IPs to remove. */
		flags &= ~TBPEER_F_REPLACE_ALLOWEDIPS;

		down_read(&tb->static_identity.lock);
		if (tb->static_identity.has_identity &&
		    !memcmp(nla_data(attrs[TBPEER_A_PUBLIC_KEY]),
			    tb->static_identity.static_public,
			    NOISE_PUBLIC_KEY_LEN)) {
			/* We silently ignore peers that have the same public
			 * key as the device. The reason we do it silently is
			 * that we'd like for people to be able to reuse the
			 * same set of API calls across peers.
			 */
			up_read(&tb->static_identity.lock);
			ret = 0;
			goto out;
		}
		up_read(&tb->static_identity.lock);

		ret = -ENOMEM;
		peer = tb_peer_create(tb, public_key, preshared_key);
		if (!peer)
			goto out;
		/* Take additional reference, as though we've just been
		 * looked up.
		 */
		tb_peer_get(peer);
	}

	ret = 0;
	if (flags & TBPEER_F_REMOVE_ME) {
		tb_peer_remove(peer);
		goto out;
	}

	if (preshared_key) {
		down_write(&peer->handshake.lock);
		memcpy(&peer->handshake.preshared_key, preshared_key,
		       NOISE_SYMMETRIC_KEY_LEN);
		up_write(&peer->handshake.lock);
	}

	if (attrs[TBPEER_A_ENDPOINT]) {
		struct sockaddr *addr = nla_data(attrs[TBPEER_A_ENDPOINT]);
		size_t len = nla_len(attrs[TBPEER_A_ENDPOINT]);

		if ((len == sizeof(struct sockaddr_in) &&
		     addr->sa_family == AF_INET) ||
		    (len == sizeof(struct sockaddr_in6) &&
		     addr->sa_family == AF_INET6)) {
			struct endpoint endpoint = { { { 0 } } };

			memcpy(&endpoint.addr, addr, len);
			tb_socket_set_peer_endpoint(peer, &endpoint);
		}
	}

	if (flags & TBPEER_F_REPLACE_ALLOWEDIPS)
		tb_allowedips_remove_by_peer(&tb->peer_allowedips, peer,
					     &tb->device_update_lock);

	if (attrs[TBPEER_A_ALLOWEDIPS]) {
		struct nlattr *attr, *allowedip[TBALLOWEDIP_A_MAX + 1];
		int rem;

		nla_for_each_nested(attr, attrs[TBPEER_A_ALLOWEDIPS], rem) {
			ret = nla_parse_nested(allowedip, TBALLOWEDIP_A_MAX,
					       attr, allowedip_policy, NULL);
			if (ret < 0)
				goto out;
			ret = set_allowedip(peer, allowedip);
			if (ret < 0)
				goto out;
		}
	}

	if (attrs[TBPEER_A_PERSISTENT_KEEPALIVE_INTERVAL]) {
		const u16 persistent_keepalive_interval = nla_get_u16(
				attrs[TBPEER_A_PERSISTENT_KEEPALIVE_INTERVAL]);
		const bool send_keepalive =
			!peer->persistent_keepalive_interval &&
			persistent_keepalive_interval &&
			netif_running(tb->dev);

		peer->persistent_keepalive_interval = persistent_keepalive_interval;
		if (send_keepalive)
			tb_packet_send_keepalive(peer);
	}

	if (netif_running(tb->dev))
		tb_packet_send_staged_packets(peer);

out:
	tb_peer_put(peer);
	if (attrs[TBPEER_A_PRESHARED_KEY])
		memzero_explicit(nla_data(attrs[TBPEER_A_PRESHARED_KEY]),
				 nla_len(attrs[TBPEER_A_PRESHARED_KEY]));
	return ret;
}

static int tb_set_device(struct sk_buff *skb, struct genl_info *info)
{
	struct tb_device *tb = lookup_interface(info->attrs, skb);
	int ret;

	if (IS_ERR(tb)) {
		ret = PTR_ERR(tb);
		goto out_nodev;
	}

	rtnl_lock();
	mutex_lock(&tb->device_update_lock);

	ret = -EPERM;
	if ((info->attrs[TBDEVICE_A_LISTEN_PORT] ||
	     info->attrs[TBDEVICE_A_FWMARK]) &&
	    !ns_capable(tb->creating_net->user_ns, CAP_NET_ADMIN))
		goto out;

	++tb->device_update_gen;

	if (info->attrs[TBDEVICE_A_FWMARK]) {
		struct tb_peer *peer;

		tb->fwmark = nla_get_u32(info->attrs[TBDEVICE_A_FWMARK]);
		list_for_each_entry(peer, &tb->peer_list, peer_list)
			tb_socket_clear_peer_endpoint_src(peer);
	}

	if (info->attrs[TBDEVICE_A_LISTEN_PORT]) {
		ret = set_port(tb,
			nla_get_u16(info->attrs[TBDEVICE_A_LISTEN_PORT]));
		if (ret)
			goto out;
	}

	if (info->attrs[TBDEVICE_A_FLAGS] &&
	    nla_get_u32(info->attrs[TBDEVICE_A_FLAGS]) &
		    TBDEVICE_F_REPLACE_PEERS)
		tb_peer_remove_all(tb);

	if (info->attrs[TBDEVICE_A_PRIVATE_KEY] &&
	    nla_len(info->attrs[TBDEVICE_A_PRIVATE_KEY]) ==
		    NOISE_PUBLIC_KEY_LEN) {
		u8 *private_key = nla_data(info->attrs[TBDEVICE_A_PRIVATE_KEY]);
		u8 public_key[NOISE_PUBLIC_KEY_LEN];
		struct tb_peer *peer, *temp;

		/* We remove before setting, to prevent race, which means doing
		 * two 25519-genpub ops.
		 */
		if (curve25519_generate_public(public_key, private_key)) {
			peer = tb_pubkey_hashtable_lookup(tb->peer_hashtable,
							  public_key);
			if (peer) {
				tb_peer_put(peer);
				tb_peer_remove(peer);
			}
		}

		down_write(&tb->static_identity.lock);
		tb_noise_set_static_identity_private_key(&tb->static_identity,
							 private_key);
		list_for_each_entry_safe(peer, temp, &tb->peer_list,
					 peer_list) {
			if (!tb_noise_precompute_static_static(peer))
				tb_peer_remove(peer);
		}
		tb_cookie_checker_precompute_device_keys(&tb->cookie_checker);
		up_write(&tb->static_identity.lock);
	}

	if (info->attrs[TBDEVICE_A_PEERS]) {
		struct nlattr *attr, *peer[TBPEER_A_MAX + 1];
		int rem;

		nla_for_each_nested(attr, info->attrs[TBDEVICE_A_PEERS], rem) {
			ret = nla_parse_nested(peer, TBPEER_A_MAX, attr,
					       peer_policy, NULL);
			if (ret < 0)
				goto out;
			ret = set_peer(tb, peer);
			if (ret < 0)
				goto out;
		}
	}
	ret = 0;

out:
	mutex_unlock(&tb->device_update_lock);
	rtnl_unlock();
	dev_put(tb->dev);
out_nodev:
	if (info->attrs[TBDEVICE_A_PRIVATE_KEY])
		memzero_explicit(nla_data(info->attrs[TBDEVICE_A_PRIVATE_KEY]),
				 nla_len(info->attrs[TBDEVICE_A_PRIVATE_KEY]));
	return ret;
}

#ifndef COMPAT_CANNOT_USE_CONST_GENL_OPS
static const
#else
static
#endif
struct genl_ops genl_ops[] = {
	{
		.cmd = TB_CMD_GET_DEVICE,
#ifndef COMPAT_CANNOT_USE_NETLINK_START
		.start = tb_get_device_start,
#endif
		.dumpit = tb_get_device_dump,
		.done = tb_get_device_done,
#ifdef COMPAT_CANNOT_INDIVIDUAL_NETLINK_OPS_POLICY
		.policy = device_policy,
#endif
		.flags = GENL_UNS_ADMIN_PERM
	}, {
		.cmd = TB_CMD_SET_DEVICE,
		.doit = tb_set_device,
#ifdef COMPAT_CANNOT_INDIVIDUAL_NETLINK_OPS_POLICY
		.policy = device_policy,
#endif
		.flags = GENL_UNS_ADMIN_PERM
	}
};

static struct genl_family genl_family
#ifndef COMPAT_CANNOT_USE_GENL_NOPS
__ro_after_init = {
	.ops = genl_ops,
	.n_ops = ARRAY_SIZE(genl_ops),
#else
= {
#endif
	.name = TB_GENL_NAME,
	.version = TB_GENL_VERSION,
	.maxattr = TBDEVICE_A_MAX,
	.module = THIS_MODULE,
#ifndef COMPAT_CANNOT_INDIVIDUAL_NETLINK_OPS_POLICY
	.policy = device_policy,
#endif
	.netnsok = true
};

int __init tb_genetlink_init(void)
{
	return genl_register_family(&genl_family);
}

void __exit tb_genetlink_uninit(void)
{
	genl_unregister_family(&genl_family);
}
