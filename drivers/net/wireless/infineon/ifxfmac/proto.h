// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2013 Broadcom Corporation
 */
#ifndef IFXFMAC_PROTO_H
#define IFXFMAC_PROTO_H


enum proto_addr_mode {
	ADDR_INDIRECT	= 0,
	ADDR_DIRECT
};

struct ifxf_skb_reorder_data {
	u8 *reorder;
};

struct ifxf_proto {
	int (*hdrpull)(struct ifxf_pub *drvr, bool do_fws,
		       struct sk_buff *skb, struct ifxf_if **ifp);
	int (*query_dcmd)(struct ifxf_pub *drvr, int ifidx, uint cmd,
			  void *buf, uint len, int *fwerr);
	int (*set_dcmd)(struct ifxf_pub *drvr, int ifidx, uint cmd, void *buf,
			uint len, int *fwerr);
	int (*tx_queue_data)(struct ifxf_pub *drvr, int ifidx,
			     struct sk_buff *skb);
	int (*txdata)(struct ifxf_pub *drvr, int ifidx, u8 offset,
		      struct sk_buff *skb);
	void (*configure_addr_mode)(struct ifxf_pub *drvr, int ifidx,
				    enum proto_addr_mode addr_mode);
	void (*delete_peer)(struct ifxf_pub *drvr, int ifidx,
			    u8 peer[ETH_ALEN]);
	void (*add_tdls_peer)(struct ifxf_pub *drvr, int ifidx,
			      u8 peer[ETH_ALEN]);
	void (*rxreorder)(struct ifxf_if *ifp, struct sk_buff *skb);
	void (*add_if)(struct ifxf_if *ifp);
	void (*del_if)(struct ifxf_if *ifp);
	void (*reset_if)(struct ifxf_if *ifp);
	int (*init_done)(struct ifxf_pub *drvr);
	void (*debugfs_create)(struct ifxf_pub *drvr);
	void *pd;
};


int ifxf_proto_attach(struct ifxf_pub *drvr);
void ifxf_proto_detach(struct ifxf_pub *drvr);

static inline int ifxf_proto_hdrpull(struct ifxf_pub *drvr, bool do_fws,
				      struct sk_buff *skb,
				      struct ifxf_if **ifp)
{
	struct ifxf_if *tmp = NULL;

	/* assure protocol is always called with
	 * non-null initialized pointer.
	 */
	if (ifp)
		*ifp = NULL;
	else
		ifp = &tmp;
	return drvr->proto->hdrpull(drvr, do_fws, skb, ifp);
}
static inline int ifxf_proto_query_dcmd(struct ifxf_pub *drvr, int ifidx,
					 uint cmd, void *buf, uint len,
					 int *fwerr)
{
	return drvr->proto->query_dcmd(drvr, ifidx, cmd, buf, len,fwerr);
}
static inline int ifxf_proto_set_dcmd(struct ifxf_pub *drvr, int ifidx,
				       uint cmd, void *buf, uint len,
				       int *fwerr)
{
	return drvr->proto->set_dcmd(drvr, ifidx, cmd, buf, len, fwerr);
}

static inline int ifxf_proto_tx_queue_data(struct ifxf_pub *drvr, int ifidx,
					    struct sk_buff *skb)
{
	return drvr->proto->tx_queue_data(drvr, ifidx, skb);
}

static inline int ifxf_proto_txdata(struct ifxf_pub *drvr, int ifidx,
				     u8 offset, struct sk_buff *skb)
{
	return drvr->proto->txdata(drvr, ifidx, offset, skb);
}
static inline void
ifxf_proto_configure_addr_mode(struct ifxf_pub *drvr, int ifidx,
				enum proto_addr_mode addr_mode)
{
	drvr->proto->configure_addr_mode(drvr, ifidx, addr_mode);
}
static inline void
ifxf_proto_delete_peer(struct ifxf_pub *drvr, int ifidx, u8 peer[ETH_ALEN])
{
	drvr->proto->delete_peer(drvr, ifidx, peer);
}
static inline void
ifxf_proto_add_tdls_peer(struct ifxf_pub *drvr, int ifidx, u8 peer[ETH_ALEN])
{
	drvr->proto->add_tdls_peer(drvr, ifidx, peer);
}
static inline bool ifxf_proto_is_reorder_skb(struct sk_buff *skb)
{
	struct ifxf_skb_reorder_data *rd;

	rd = (struct ifxf_skb_reorder_data *)skb->cb;
	return !!rd->reorder;
}

static inline void
ifxf_proto_rxreorder(struct ifxf_if *ifp, struct sk_buff *skb)
{
	ifp->drvr->proto->rxreorder(ifp, skb);
}

static inline void
ifxf_proto_add_if(struct ifxf_pub *drvr, struct ifxf_if *ifp)
{
	if (!drvr->proto->add_if)
		return;
	drvr->proto->add_if(ifp);
}

static inline void
ifxf_proto_del_if(struct ifxf_pub *drvr, struct ifxf_if *ifp)
{
	if (!drvr->proto->del_if)
		return;
	drvr->proto->del_if(ifp);
}

static inline void
ifxf_proto_reset_if(struct ifxf_pub *drvr, struct ifxf_if *ifp)
{
	if (!drvr->proto->reset_if)
		return;
	drvr->proto->reset_if(ifp);
}

static inline int
ifxf_proto_init_done(struct ifxf_pub *drvr)
{
	if (!drvr->proto->init_done)
		return 0;
	return drvr->proto->init_done(drvr);
}

static inline void
ifxf_proto_debugfs_create(struct ifxf_pub *drvr)
{
	drvr->proto->debugfs_create(drvr);
}

#endif /* IFXFMAC_PROTO_H */
