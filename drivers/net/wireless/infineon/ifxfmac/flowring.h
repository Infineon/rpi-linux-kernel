// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2014 Broadcom Corporation
 */
#ifndef IFXFMAC_FLOWRING_H
#define IFXFMAC_FLOWRING_H


#define IFXF_FLOWRING_HASHSIZE		512		/* has to be 2^x */
#define IFXF_FLOWRING_INVALID_ID	0xFFFFFFFF


struct ifxf_flowring_hash {
	u8 mac[ETH_ALEN];
	u8 fifo;
	u8 ifidx;
	u16 flowid;
};

enum ring_status {
	RING_CLOSED,
	RING_CLOSING,
	RING_OPEN
};

struct ifxf_flowring_ring {
	u16 hash_id;
	bool blocked;
	enum ring_status status;
	struct sk_buff_head skblist;
};

struct ifxf_flowring_tdls_entry {
	u8 mac[ETH_ALEN];
	struct ifxf_flowring_tdls_entry *next;
};

struct ifxf_flowring {
	struct device *dev;
	struct ifxf_flowring_hash hash[IFXF_FLOWRING_HASHSIZE];
	struct ifxf_flowring_ring **rings;
	spinlock_t block_lock;
	enum proto_addr_mode addr_mode[IFXF_MAX_IFS];
	u16 nrofrings;
	bool tdls_active;
	struct ifxf_flowring_tdls_entry *tdls_entry;
};


u32 ifxf_flowring_lookup(struct ifxf_flowring *flow, u8 da[ETH_ALEN],
			  u8 prio, u8 ifidx);
u32 ifxf_flowring_create(struct ifxf_flowring *flow, u8 da[ETH_ALEN],
			  u8 prio, u8 ifidx);
void ifxf_flowring_delete(struct ifxf_flowring *flow, u16 flowid);
void ifxf_flowring_open(struct ifxf_flowring *flow, u16 flowid);
u8 ifxf_flowring_tid(struct ifxf_flowring *flow, u16 flowid);
u32 ifxf_flowring_enqueue(struct ifxf_flowring *flow, u16 flowid,
			   struct sk_buff *skb);
struct sk_buff *ifxf_flowring_dequeue(struct ifxf_flowring *flow, u16 flowid);
void ifxf_flowring_reinsert(struct ifxf_flowring *flow, u16 flowid,
			     struct sk_buff *skb);
u32 ifxf_flowring_qlen(struct ifxf_flowring *flow, u16 flowid);
u8 ifxf_flowring_ifidx_get(struct ifxf_flowring *flow, u16 flowid);
struct ifxf_flowring *ifxf_flowring_attach(struct device *dev, u16 nrofrings);
void ifxf_flowring_detach(struct ifxf_flowring *flow);
void ifxf_flowring_configure_addr_mode(struct ifxf_flowring *flow, int ifidx,
					enum proto_addr_mode addr_mode);
void ifxf_flowring_delete_peer(struct ifxf_flowring *flow, int ifidx,
				u8 peer[ETH_ALEN]);
void ifxf_flowring_add_tdls_peer(struct ifxf_flowring *flow, int ifidx,
				  u8 peer[ETH_ALEN]);


#endif /* IFXFMAC_FLOWRING_H */
