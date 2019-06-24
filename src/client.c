/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2018 Vincent Wiemann <vincent.wiemann@ironai.com>. All Rights Reserved.
 */

#include "device.h"
#include "messages.h"
#include "peer.h"

#include <linux/jhash.h>
#include <linux/random.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/ktime.h>
#include <linux/etherdevice.h>

static struct kmem_cache *client_cachep __read_mostly;
static unsigned long client_timer_interval;


/* debug_print_skb_dump(skb, "tb: device.c: tb_tap_xmit"); */
int debug_print_skb_dump(struct sk_buff *skb, char *message)
{
	int k = 1;
	unsigned long long i, j = 0;
	unsigned long long len = (unsigned long long)(skb->tail - skb->head);
	char *data = skb->head;

	if(skb_is_nonlinear(skb)) {
		printk("%s: NONLINEAR!\n", message);
		return -1;
	}

	if(skb->dev) {
		printk("Device %s", skb->dev->name);
	}

	printk("Src %pM Dest %pM\n", &eth_hdr(skb)->h_source, &eth_hdr(skb)->h_dest);

	printk("%s:\n", message);
/*
	for (i = 0; i < len; i++, k++) {
		if(i == (skb->data - skb->head))
			printk("\tDATA %llu\n", (unsigned long long)(skb->data - skb->head));
		if(i == (skb->tail - skb->head))
			printk("\tTAIL %llu\n", (unsigned long long)(skb->tail - skb->head));
		if(i == skb->mac_header)
			printk("\tL2 %llu\n", (unsigned long long)skb->mac_header);
		if(i == skb->network_header)
			printk("\tL3 %llu\n", (unsigned long long)skb->network_header);
		if(i == skb->transport_header)
			printk("\tL4 %llu\n", (unsigned long long)skb->transport_header);
		if( i == len-1 || k == 16) {
			printk("%02x\n", (~(~0 << 8) & *(data+i)));
			j = 0;
			k = 0;
		}
		else if (j) {
			printk("%02x ", (~(~0 << 8) & *(data+i)));
			j--;
		}
		else {
			printk("%02x", (~(~0 << 8) & *(data+i)));
			j++;
		}
	}
*/
	return 0;
}


/**
 * client_bucket() - Return the bucket of the hash table matching a MAC address
 * @table: pointer to the client hash table
 * @ha: MAC address
 *
 * Return: pointer to the hash table bucket
 */
static struct hlist_head *client_bucket(struct client_hashtable *table, const u8 *ha)
{
	u32 hash = table->salt;

	hash = jhash(ha, ETH_ALEN, hash);
	hash = hash % HASH_SIZE(table->hashtable);

	return &table->hashtable[hash];
}

/**
 * client_hashtable_init() - Initialize a hash table, its salt and spinlock
 * @table: pointer to the client hash table
 */
static void client_hashtable_init(struct client_hashtable *table)
{
	hash_init(table->hashtable);
	table->salt = (__force __le32)get_random_u32();
	spin_lock_init(&table->lock);
}

/**
 * client_hashtable_insert() - Insert a client object into a hash table
 * @table: pointer to the client hash table
 * @client: pointer to the client object
 *
 * Return: true if successful else false
 */
static bool client_hashtable_insert(struct client_hashtable *table,
				 struct tb_client *client)
{
	struct tb_client *existing_client;
	struct hlist_head *bucket = client_bucket(table, (u8 *)&client->ha);

	/* Remove entry just to be sure */
	spin_lock_bh(&table->lock);
	hlist_del_init_rcu(&client->client_hash);
	spin_unlock_bh(&table->lock);

	rcu_read_lock_bh();

	/* Read-only first */
	hlist_for_each_entry_rcu_bh(existing_client, bucket, client_hash) {
		if (ether_addr_equal_unaligned((u8 *)&existing_client->ha, (u8 *)&client->ha))
			/* MAC address already in hash table */
			goto err;
	}

	spin_lock_bh(&table->lock);
	hlist_for_each_entry_rcu_bh(existing_client, bucket, client_hash) {
		if (ether_addr_equal_unaligned((u8 *)&existing_client->ha, (u8 *)&client->ha))
			/* Someone was quicker */
			goto err_unlock;
	}

	hlist_add_head_rcu(&client->client_hash, bucket);
	spin_unlock_bh(&table->lock);

	rcu_read_unlock_bh();

	return true;

err_unlock:
	spin_unlock_bh(&table->lock);
err:
	rcu_read_unlock_bh();
	net_dbg_ratelimited("%s: failed to insert client %pM. Address already in hash table.\n",
			    container_of(table, struct tb_device, client_hashtable)->dev->name, &client->ha);

	return false;
}

/**
 * client_hashtable_replace() - Replace a client object in specific hash table
 * @table: pointer to the client hash table
 * @old: pointer to old client object
 * @new: pointer to new client object
 *
 * Return: true if successful else false
 */
static bool client_hashtable_replace(struct client_hashtable *table,
				struct tb_client *old,
				struct tb_client *new)
{
	/* TODO Shouldn't this be checked again after spinlock was acquired? */
	if (unlikely(hlist_unhashed(&old->client_hash)))
		return false;

	spin_lock_bh(&table->lock);
	hlist_replace_rcu(&old->client_hash, &new->client_hash);
	INIT_HLIST_NODE(&old->client_hash);
	spin_unlock_bh(&table->lock);

	return true;
}

/**
 * client_hashtable_remove() - Remove a client object from specific hash table
 * @table: pointer to the client hash table
 * @client: pointer to the client object to remove from hash table
 */
static void client_hashtable_remove(struct tb_client *client)
{
	spin_lock_bh(&client->device->client_hashtable.lock);
	hlist_del_init_rcu(&client->client_hash);
	spin_unlock_bh(&client->device->client_hashtable.lock);
}

/**
 * tb_client_create() - Create a new client object
 * @peer: pointer to the peer object the client is using else NULL
 * @ha: the MAC address of the client
 *
 * Return: the client object if successful, else NULL
 */
struct tb_client *tb_client_create(struct tb_device *tb, struct tb_peer *peer, const u8 *ha)
{
	struct tb_client *client = kmem_cache_alloc(client_cachep, GFP_ATOMIC);

	if (unlikely(!client)) {
		if(peer) {
			net_dbg_ratelimited("%s: failed to allocate client %pM using peer %llu\n",
					    tb->dev->name, ha, peer->internal_id);
		} else {
			net_dbg_ratelimited("%s: failed to allocate local client %pM\n",
					    tb->dev->name, ha);
		}

		return NULL;
	}

	/* Get a reference to the peer */
	tb_peer_get_maybe_zero(peer);

	atomic_set(&client->timeout, jiffies_to_msecs(jiffies) / 1000 + TB_CLIENT_TIMER_TIMEOUT);
	client->device = tb;
	client->peer = peer;
	ether_addr_copy((u8 *)&client->ha, ha);
	kref_init(&client->refcount);

	if(!client_hashtable_insert(&tb->client_hashtable, client))
		return NULL;

	return client;
}

/**
 * client_free_rcu() - Frees the client object
 * @rcu: rcu head
 */
static void client_free_rcu(struct rcu_head *rcu)
{
	kmem_cache_free(client_cachep, container_of(rcu, struct tb_client, rcu));
}

/**
 * client_free_kref() - Removes the client object from the hash table and queues for free after rcu grace period
 * @kref: kref
 */
static void client_free_kref(struct kref *kref)
{
	struct tb_client *client = container_of(kref, struct tb_client, refcount);

	if(client->peer) {
		/* Release reference on peer */
		tb_peer_put(client->peer);
		net_dbg_ratelimited("%s: client %pM destroyed using peer %llu\n",
				    client->device->dev->name,
				    &client->ha,
				    client->peer->internal_id);
	} else {
		net_dbg_ratelimited("%s: local client %pM destroyed\n",
				    client->device->dev->name,
				    &client->ha);
	}

	client_hashtable_remove(client);
	call_rcu_bh(&client->rcu, client_free_rcu);
}

/**
 * client_get() - Taking a reference on given client object
 * @client: pointer to the client object
 *
 * Return: the client object if successful, else NULL
 */
static struct tb_client *client_get(struct tb_client *client)
{
	RCU_LOCKDEP_WARN(!rcu_read_lock_bh_held(),
		"Taking client reference without holding the RCU BH read lock");

	if (unlikely(!client || !kref_get_unless_zero(&client->refcount)))
		return NULL;

	return client;
}

/**
 * client_put() - Decrements the refcount and queues for removal if equals 0
 * @client: pointer to the client object
 * @unreference_now: if true removes the client object from the hash table immediately
 */
static __always_inline void client_put(struct tb_client *client, bool unreference_now)
{
	if (unlikely(!client))
		return;

	if (unlikely(unreference_now))
		client_hashtable_remove(client);

	kref_put(&client->refcount, client_free_kref);
}

/**
 * lookup() - Looks up the client object in the hash table and gets a strong reference
 * @table: the hash table to perform the lookup on
 * @ha: the MAC address to look for
 *
 * Return: pointer to the client object if found, else NULL
 */
static struct tb_client *
lookup(struct client_hashtable *table, const u8 *ha)
{
	struct tb_client *iter_client, *client = NULL;
	printk("lookup before");
	rcu_read_lock_bh();

	hlist_for_each_entry_rcu_bh(iter_client, client_bucket(table, (u8 *)ha),
				    client_hash) {
		printk("lookup in list");
		if (ether_addr_equal_unaligned((u8 *)&iter_client->ha, ha)) {
			printk("lookup in for");
			client = client_get(iter_client);
			break;
		}
	}

	rcu_read_unlock_bh();

	return client;
}

/**
 * tb_client_lookup_dst() - Looks up the destination MAC address of skb in hash table
 * @table: pointer to the hash table to perform a lookup on
 * @skb: the socket buffer to retrieve the MAC address from
 * @client: pointer to the client pointer if a strong reference to the client is wished
 *
 * Return: a strong reference to the peer if found, else NULL
 */
struct tb_client *tb_client_lookup_dst(struct client_hashtable *table, struct sk_buff *skb)
{
	return lookup(table, (u8 *)&eth_hdr(skb)->h_dest);
}

/**
 * tb_client_lookup_src() - Looks up the source MAC address of skb in hash table
 * @table: pointer to the hash table to perform a lookup on
 * @skb: the socket buffer to retrieve the MAC address from
 * @client: pointer to the client pointer if a strong reference to the client is wished
 *
 * Return: a strong reference to the peer if found, else NULL
 */
struct tb_client *tb_client_lookup_src(struct client_hashtable *table, struct sk_buff *skb)
{
	struct tb_client *client;

	printk("tb_client_lookup_src before");
	client = lookup(table, (u8 *)&eth_hdr(skb)->h_source);
	printk("tb_client_lookup_src after");

	if(client)
		atomic_set(&client->timeout, jiffies_to_msecs(jiffies) / 
			    1000 + TB_CLIENT_TIMER_TIMEOUT);
	
	return client;
}

/**
 * tb_client_update_peer() - Update a peer object by replacing it in the hash table and releasing reference on the old one
 * @old: pointer to the old client object
 * @peer: pointer to the new peer to use
 *
 * Return: the new client object if successful, else NULL
 */
struct tb_client *tb_client_update_peer(struct tb_client *old, struct tb_peer *peer)
{
	struct tb_client *new;
	bool ret;

	/* TODO Doesn't this need to be checked after spinlock? 
	 *	(copied from WireGuard)
	 */
	/* In the worst case we drop some packets. Dropping should never happen anyway?! */
	if (unlikely(hlist_unhashed(&old->client_hash)))
		return NULL;

	new = tb_client_create(old->device, peer, (u8 *)&old->ha);

	ret = client_hashtable_replace(&old->device->client_hashtable, old, new);

	if(ret) {
		client_put(old, false);
		return new;
	}

	return NULL;
}

/**
 * tb_client_put() - Decrease client object's refcount
 * @client: pointer to the client object
 */
void tb_client_put(struct tb_client *client)
{
	if (client)
		client_put(client, false);
}

/**
 * tb_client_remove() - Removes client object from it's hash table and decreases refcount
 * @client: pointer to the client object
 *
 * Return: always 1 for walk function
 */
int tb_client_remove(struct tb_client *client)
{
	if (client)
		client_put(client, true);

	/* Always returns 1 for walk function */
	return 1;
}

/**
 * tb_client_remove_all() - Removes all client objects from the given hash table
 * @table: pointer to the hash table
 */
void tb_client_remove_all(struct client_hashtable *table)
{
	struct tb_client *client;
	int i;

	tb_hash_for_each_rcu_bh(table->hashtable, i, client, client_hash)
		tb_client_remove(client);
}

/**
 * tb_client_remove_by_peer() - Removes all client objects from the hash table which use the specified peer
 * @peer: pointer to the peer object
 */
void tb_client_remove_by_peer(struct tb_peer *peer)
{
	struct tb_client *client;
	int i;

	rcu_read_lock_bh();

	tb_hash_for_each_rcu_bh(peer->device->client_hashtable.hashtable, i, client, client_hash) {
		if((!client->peer && !peer) || (peer && client->peer && 
		    !memcmp(peer->handshake.remote_static, client->peer->handshake.remote_static, NOISE_PUBLIC_KEY_LEN)))
			tb_client_remove(client);
	}

	rcu_read_unlock_bh();
}

/**
 * client_timer_expired() - Called when the timer fires
 * @timer: pointer to the timer
 */
static void client_timer_expired(struct timer_list *timer)
{
	struct tb_device *tb = container_of(timer, struct tb_device, timer_client_timeout);
	struct tb_client *client;
	static unsigned long next, now;
	int i;

	now = jiffies_to_msecs(jiffies) / 1000;

	rcu_read_lock_bh();

	tb_hash_for_each_rcu_bh(tb->client_hashtable.hashtable, i, client, client_hash)
		if(atomic_read(&client->timeout) < now)
			tb_client_remove(client);

	rcu_read_unlock_bh();

	next = jiffies + msecs_to_jiffies(TB_CLIENT_TIMER_INTERVAL * 1000);
	if (likely(netif_running(tb->dev)))
		mod_timer(&tb->timer_client_timeout, next);
}

/**
 * tb_client_init() - Initializes the client hash table and the timeout check timer
 * @device: pointer to the WireGuard device to perform action on
 */
void tb_client_init(struct tb_device *tb)
{
	client_timer_interval = msecs_to_jiffies(TB_CLIENT_TIMER_INTERVAL * 1000);
	client_hashtable_init(&tb->client_hashtable);
	timer_setup(&tb->timer_client_timeout, client_timer_expired, 0);
}

/**
 * tb_client_destroy() - Destroys the client hash table and the timeout check timer
 * @device: pointer to the WireGuard device to perform action on
 */
void tb_client_destroy(struct tb_device *tb)
{
	del_timer_sync(&tb->timer_client_timeout);
	tb_client_remove_all(&tb->client_hashtable);
}

