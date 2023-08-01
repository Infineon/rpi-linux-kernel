// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2014 Broadcom Corporation
 */


#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <ifxu_utils.h>

#include "core.h"
#include "debug.h"
#include "bus.h"
#include "proto.h"
#include "flowring.h"
#include "msgbuf.h"
#include "common.h"


#define IFXF_FLOWRING_HIGH		1024
#define IFXF_FLOWRING_LOW		(IFXF_FLOWRING_HIGH - 256)
#define IFXF_FLOWRING_INVALID_IFIDX	0xff

#define IFXF_FLOWRING_HASH_AP(da, fifo, ifidx) (da[5] * 2 + fifo + ifidx * 16)
#define IFXF_FLOWRING_HASH_STA(fifo, ifidx) (fifo + ifidx * 16)

static const u8 ifxf_flowring_prio2fifo[] = {
	0,
	1,
	1,
	0,
	2,
	2,
	3,
	3
};

static const u8 ALLFFMAC[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };


static bool
ifxf_flowring_is_tdls_mac(struct ifxf_flowring *flow, u8 mac[ETH_ALEN])
{
	struct ifxf_flowring_tdls_entry *search;

	search = flow->tdls_entry;

	while (search) {
		if (memcmp(search->mac, mac, ETH_ALEN) == 0)
			return true;
		search = search->next;
	}

	return false;
}


u32 ifxf_flowring_lookup(struct ifxf_flowring *flow, u8 da[ETH_ALEN],
			  u8 prio, u8 ifidx)
{
	struct ifxf_flowring_hash *hash;
	u16 hash_idx;
	u32 i;
	bool found;
	bool sta;
	u8 fifo;
	u8 *mac;

	fifo = ifxf_flowring_prio2fifo[prio];
	sta = (flow->addr_mode[ifidx] == ADDR_INDIRECT);
	mac = da;
	if ((!sta) && (is_multicast_ether_addr(da))) {
		mac = (u8 *)ALLFFMAC;
		fifo = 0;
	}
	if ((sta) && (flow->tdls_active) &&
	    (ifxf_flowring_is_tdls_mac(flow, da))) {
		sta = false;
	}
	hash_idx =  sta ? IFXF_FLOWRING_HASH_STA(fifo, ifidx) :
			  IFXF_FLOWRING_HASH_AP(mac, fifo, ifidx);
	hash_idx &= (IFXF_FLOWRING_HASHSIZE - 1);
	found = false;
	hash = flow->hash;
	for (i = 0; i < IFXF_FLOWRING_HASHSIZE; i++) {
		if ((sta || (memcmp(hash[hash_idx].mac, mac, ETH_ALEN) == 0)) &&
		    (hash[hash_idx].fifo == fifo) &&
		    (hash[hash_idx].ifidx == ifidx)) {
			found = true;
			break;
		}
		hash_idx++;
		hash_idx &= (IFXF_FLOWRING_HASHSIZE - 1);
	}
	if (found)
		return hash[hash_idx].flowid;

	return IFXF_FLOWRING_INVALID_ID;
}


u32 ifxf_flowring_create(struct ifxf_flowring *flow, u8 da[ETH_ALEN],
			  u8 prio, u8 ifidx)
{
	struct ifxf_flowring_ring *ring;
	struct ifxf_flowring_hash *hash;
	u16 hash_idx;
	u32 i;
	bool found;
	u8 fifo;
	bool sta;
	u8 *mac;

	fifo = ifxf_flowring_prio2fifo[prio];
	sta = (flow->addr_mode[ifidx] == ADDR_INDIRECT);
	mac = da;
	if ((!sta) && (is_multicast_ether_addr(da))) {
		mac = (u8 *)ALLFFMAC;
		fifo = 0;
	}
	if ((sta) && (flow->tdls_active) &&
	    (ifxf_flowring_is_tdls_mac(flow, da))) {
		sta = false;
	}
	hash_idx =  sta ? IFXF_FLOWRING_HASH_STA(fifo, ifidx) :
			  IFXF_FLOWRING_HASH_AP(mac, fifo, ifidx);
	hash_idx &= (IFXF_FLOWRING_HASHSIZE - 1);
	found = false;
	hash = flow->hash;
	for (i = 0; i < IFXF_FLOWRING_HASHSIZE; i++) {
		if ((hash[hash_idx].ifidx == IFXF_FLOWRING_INVALID_IFIDX) &&
		    (is_zero_ether_addr(hash[hash_idx].mac))) {
			found = true;
			break;
		}
		hash_idx++;
		hash_idx &= (IFXF_FLOWRING_HASHSIZE - 1);
	}
	if (found) {
		for (i = 0; i < flow->nrofrings; i++) {
			if (flow->rings[i] == NULL)
				break;
		}
		if (i == flow->nrofrings)
			return -ENOMEM;

		ring = kzalloc(sizeof(*ring), GFP_ATOMIC);
		if (!ring)
			return -ENOMEM;

		memcpy(hash[hash_idx].mac, mac, ETH_ALEN);
		hash[hash_idx].fifo = fifo;
		hash[hash_idx].ifidx = ifidx;
		hash[hash_idx].flowid = i;

		ring->hash_id = hash_idx;
		ring->status = RING_CLOSED;
		skb_queue_head_init(&ring->skblist);
		flow->rings[i] = ring;

		return i;
	}
	return IFXF_FLOWRING_INVALID_ID;
}


u8 ifxf_flowring_tid(struct ifxf_flowring *flow, u16 flowid)
{
	struct ifxf_flowring_ring *ring;

	ring = flow->rings[flowid];

	return flow->hash[ring->hash_id].fifo;
}


static void ifxf_flowring_block(struct ifxf_flowring *flow, u16 flowid,
				 bool blocked)
{
	struct ifxf_flowring_ring *ring;
	struct ifxf_bus *bus_if;
	struct ifxf_pub *drvr;
	struct ifxf_if *ifp;
	bool currently_blocked;
	int i;
	u8 ifidx;
	unsigned long flags;

	spin_lock_irqsave(&flow->block_lock, flags);

	ring = flow->rings[flowid];
	if (ring->blocked == blocked) {
		spin_unlock_irqrestore(&flow->block_lock, flags);
		return;
	}
	ifidx = ifxf_flowring_ifidx_get(flow, flowid);

	currently_blocked = false;
	for (i = 0; i < flow->nrofrings; i++) {
		if ((flow->rings[i]) && (i != flowid)) {
			ring = flow->rings[i];
			if ((ring->status == RING_OPEN) &&
			    (ifxf_flowring_ifidx_get(flow, i) == ifidx)) {
				if (ring->blocked) {
					currently_blocked = true;
					break;
				}
			}
		}
	}
	flow->rings[flowid]->blocked = blocked;
	if (currently_blocked) {
		spin_unlock_irqrestore(&flow->block_lock, flags);
		return;
	}

	bus_if = dev_get_drvdata(flow->dev);
	drvr = bus_if->drvr;
	ifp = ifxf_get_ifp(drvr, ifidx);
	ifxf_txflowblock_if(ifp, IFXF_NETIF_STOP_REASON_FLOW, blocked);

	spin_unlock_irqrestore(&flow->block_lock, flags);
}


void ifxf_flowring_delete(struct ifxf_flowring *flow, u16 flowid)
{
	struct ifxf_bus *bus_if = dev_get_drvdata(flow->dev);
	struct ifxf_flowring_ring *ring;
	struct ifxf_if *ifp;
	u16 hash_idx;
	u8 ifidx;
	struct sk_buff *skb;

	ring = flow->rings[flowid];
	if (!ring)
		return;

	ifidx = ifxf_flowring_ifidx_get(flow, flowid);
	ifp = ifxf_get_ifp(bus_if->drvr, ifidx);

	ifxf_flowring_block(flow, flowid, false);
	hash_idx = ring->hash_id;
	flow->hash[hash_idx].ifidx = IFXF_FLOWRING_INVALID_IFIDX;
	eth_zero_addr(flow->hash[hash_idx].mac);
	flow->rings[flowid] = NULL;

	skb = skb_dequeue(&ring->skblist);
	while (skb) {
		ifxf_txfinalize(ifp, skb, false);
		skb = skb_dequeue(&ring->skblist);
	}

	kfree(ring);
}


u32 ifxf_flowring_enqueue(struct ifxf_flowring *flow, u16 flowid,
			   struct sk_buff *skb)
{
	struct ifxf_flowring_ring *ring;

	ring = flow->rings[flowid];

	skb_queue_tail(&ring->skblist, skb);

	if (!ring->blocked &&
	    (skb_queue_len(&ring->skblist) > IFXF_FLOWRING_HIGH)) {
		ifxf_flowring_block(flow, flowid, true);
		ifxf_dbg(MSGBUF, "Flowcontrol: BLOCK for ring %d\n", flowid);
		/* To prevent (work around) possible race condition, check
		 * queue len again. It is also possible to use locking to
		 * protect, but that is undesirable for every enqueue and
		 * dequeue. This simple check will solve a possible race
		 * condition if it occurs.
		 */
		if (skb_queue_len(&ring->skblist) < IFXF_FLOWRING_LOW)
			ifxf_flowring_block(flow, flowid, false);
	}
	return skb_queue_len(&ring->skblist);
}


struct sk_buff *ifxf_flowring_dequeue(struct ifxf_flowring *flow, u16 flowid)
{
	struct ifxf_flowring_ring *ring;
	struct sk_buff *skb;

	ring = flow->rings[flowid];
	if (ring->status != RING_OPEN)
		return NULL;

	skb = skb_dequeue(&ring->skblist);

	if (ring->blocked &&
	    (skb_queue_len(&ring->skblist) < IFXF_FLOWRING_LOW)) {
		ifxf_flowring_block(flow, flowid, false);
		ifxf_dbg(MSGBUF, "Flowcontrol: OPEN for ring %d\n", flowid);
	}

	return skb;
}


void ifxf_flowring_reinsert(struct ifxf_flowring *flow, u16 flowid,
			     struct sk_buff *skb)
{
	struct ifxf_flowring_ring *ring;

	ring = flow->rings[flowid];

	skb_queue_head(&ring->skblist, skb);
}


u32 ifxf_flowring_qlen(struct ifxf_flowring *flow, u16 flowid)
{
	struct ifxf_flowring_ring *ring;

	ring = flow->rings[flowid];
	if (!ring)
		return 0;

	if (ring->status != RING_OPEN)
		return 0;

	return skb_queue_len(&ring->skblist);
}


void ifxf_flowring_open(struct ifxf_flowring *flow, u16 flowid)
{
	struct ifxf_flowring_ring *ring;

	ring = flow->rings[flowid];
	if (!ring) {
		ifxf_err("Ring NULL, for flowid %d\n", flowid);
		return;
	}

	ring->status = RING_OPEN;
}


u8 ifxf_flowring_ifidx_get(struct ifxf_flowring *flow, u16 flowid)
{
	struct ifxf_flowring_ring *ring;
	u16 hash_idx;

	ring = flow->rings[flowid];
	hash_idx = ring->hash_id;

	return flow->hash[hash_idx].ifidx;
}


struct ifxf_flowring *ifxf_flowring_attach(struct device *dev, u16 nrofrings)
{
	struct ifxf_flowring *flow;
	u32 i;

	flow = kzalloc(sizeof(*flow), GFP_KERNEL);
	if (flow) {
		flow->dev = dev;
		flow->nrofrings = nrofrings;
		spin_lock_init(&flow->block_lock);
		for (i = 0; i < ARRAY_SIZE(flow->addr_mode); i++)
			flow->addr_mode[i] = ADDR_INDIRECT;
		for (i = 0; i < ARRAY_SIZE(flow->hash); i++)
			flow->hash[i].ifidx = IFXF_FLOWRING_INVALID_IFIDX;
		flow->rings = kcalloc(nrofrings, sizeof(*flow->rings),
				      GFP_KERNEL);
		if (!flow->rings) {
			kfree(flow);
			flow = NULL;
		}
	}

	return flow;
}


void ifxf_flowring_detach(struct ifxf_flowring *flow)
{
	struct ifxf_bus *bus_if = dev_get_drvdata(flow->dev);
	struct ifxf_pub *drvr = bus_if->drvr;
	struct ifxf_flowring_tdls_entry *search;
	struct ifxf_flowring_tdls_entry *remove;
	u16 flowid;

	for (flowid = 0; flowid < flow->nrofrings; flowid++) {
		if (flow->rings[flowid])
			ifxf_msgbuf_delete_flowring(drvr, flowid);
	}

	search = flow->tdls_entry;
	while (search) {
		remove = search;
		search = search->next;
		kfree(remove);
	}
	kfree(flow->rings);
	kfree(flow);
}


void ifxf_flowring_configure_addr_mode(struct ifxf_flowring *flow, int ifidx,
					enum proto_addr_mode addr_mode)
{
	struct ifxf_bus *bus_if = dev_get_drvdata(flow->dev);
	struct ifxf_pub *drvr = bus_if->drvr;
	u32 i;
	u16 flowid;

	if (flow->addr_mode[ifidx] != addr_mode) {
		for (i = 0; i < ARRAY_SIZE(flow->hash); i++) {
			if (flow->hash[i].ifidx == ifidx) {
				flowid = flow->hash[i].flowid;
				if (flow->rings[flowid]->status != RING_OPEN)
					continue;
				ifxf_msgbuf_delete_flowring(drvr, flowid);
			}
		}
		flow->addr_mode[ifidx] = addr_mode;
	}
}


void ifxf_flowring_delete_peer(struct ifxf_flowring *flow, int ifidx,
				u8 peer[ETH_ALEN])
{
	struct ifxf_bus *bus_if = dev_get_drvdata(flow->dev);
	struct ifxf_pub *drvr = bus_if->drvr;
	struct ifxf_flowring_hash *hash;
	struct ifxf_flowring_tdls_entry *prev;
	struct ifxf_flowring_tdls_entry *search;
	u32 i;
	u16 flowid;
	bool sta;

	sta = (flow->addr_mode[ifidx] == ADDR_INDIRECT);

	search = flow->tdls_entry;
	prev = NULL;
	while (search) {
		if (memcmp(search->mac, peer, ETH_ALEN) == 0) {
			sta = false;
			break;
		}
		prev = search;
		search = search->next;
	}

	hash = flow->hash;
	for (i = 0; i < IFXF_FLOWRING_HASHSIZE; i++) {
		if ((sta || (memcmp(hash[i].mac, peer, ETH_ALEN) == 0)) &&
		    (hash[i].ifidx == ifidx)) {
			flowid = flow->hash[i].flowid;
			if (flow->rings[flowid]->status == RING_OPEN)
				ifxf_msgbuf_delete_flowring(drvr, flowid);
		}
	}

	if (search) {
		if (prev)
			prev->next = search->next;
		else
			flow->tdls_entry = search->next;
		kfree(search);
		if (flow->tdls_entry == NULL)
			flow->tdls_active = false;
	}
}


void ifxf_flowring_add_tdls_peer(struct ifxf_flowring *flow, int ifidx,
				  u8 peer[ETH_ALEN])
{
	struct ifxf_flowring_tdls_entry *tdls_entry;
	struct ifxf_flowring_tdls_entry *search;

	tdls_entry = kzalloc(sizeof(*tdls_entry), GFP_ATOMIC);
	if (tdls_entry == NULL)
		return;

	memcpy(tdls_entry->mac, peer, ETH_ALEN);
	tdls_entry->next = NULL;
	if (flow->tdls_entry == NULL) {
		flow->tdls_entry = tdls_entry;
	} else {
		search = flow->tdls_entry;
		if (memcmp(search->mac, peer, ETH_ALEN) == 0)
			goto free_entry;
		while (search->next) {
			search = search->next;
			if (memcmp(search->mac, peer, ETH_ALEN) == 0)
				goto free_entry;
		}
		search->next = tdls_entry;
	}

	flow->tdls_active = true;
	return;

free_entry:
	kfree(tdls_entry);
}
