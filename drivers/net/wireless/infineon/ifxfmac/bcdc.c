// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2010 Broadcom Corporation
 */

/*******************************************************************************
 * Communicates with the dongle by using dcmd codes.
 * For certain dcmd codes, the dongle interprets string data from the host.
 ******************************************************************************/

#include <linux/types.h>
#include <linux/netdevice.h>

#include <ifxu_utils.h>
#include <ifxu_wifi.h>

#include "core.h"
#include "bus.h"
#include "fwsignal.h"
#include "debug.h"
#include "tracepoint.h"
#include "proto.h"
#include "bcdc.h"

struct ifxf_proto_bcdc_dcmd {
	__le32 cmd;	/* dongle command value */
	__le32 len;	/* lower 16: output buflen;
			 * upper 16: input buflen (excludes header) */
	__le32 flags;	/* flag defns given below */
	__le32 status;	/* status code returned from the device */
};

/* BCDC flag definitions */
#define BCDC_DCMD_ERROR		0x01		/* 1=cmd failed */
#define BCDC_DCMD_SET		0x02		/* 0=get, 1=set cmd */
#define BCDC_DCMD_IF_MASK	0xF000		/* I/F index */
#define BCDC_DCMD_IF_SHIFT	12
#define BCDC_DCMD_ID_MASK	0xFFFF0000	/* id an cmd pairing */
#define BCDC_DCMD_ID_SHIFT	16		/* ID Mask shift bits */
#define BCDC_DCMD_ID(flags)	\
	(((flags) & BCDC_DCMD_ID_MASK) >> BCDC_DCMD_ID_SHIFT)

/*
 * BCDC header - Broadcom specific extension of CDC.
 * Used on data packets to convey priority across USB.
 */
#define	BCDC_HEADER_LEN		4
#define BCDC_PROTO_VER		2	/* Protocol version */
#define BCDC_FLAG_VER_MASK	0xf0	/* Protocol version mask */
#define BCDC_FLAG_VER_SHIFT	4	/* Protocol version shift */
#define BCDC_FLAG_SUM_GOOD	0x04	/* Good RX checksums */
#define BCDC_FLAG_SUM_NEEDED	0x08	/* Dongle needs to do TX checksums */
#define BCDC_PRIORITY_MASK	0x7
#define BCDC_FLAG2_IF_MASK	0x0f	/* packet rx interface in APSTA */
#define BCDC_FLAG2_IF_SHIFT	0

#define BCDC_GET_IF_IDX(hdr) \
	((int)((((hdr)->flags2) & BCDC_FLAG2_IF_MASK) >> BCDC_FLAG2_IF_SHIFT))
#define BCDC_SET_IF_IDX(hdr, idx) \
	((hdr)->flags2 = (((hdr)->flags2 & ~BCDC_FLAG2_IF_MASK) | \
	((idx) << BCDC_FLAG2_IF_SHIFT)))

/**
 * struct ifxf_proto_bcdc_header - BCDC header format
 *
 * @flags: flags contain protocol and checksum info.
 * @priority: 802.1d priority and USB flow control info (bit 4:7).
 * @flags2: additional flags containing dongle interface index.
 * @data_offset: start of packet data. header is following by firmware signals.
 */
struct ifxf_proto_bcdc_header {
	u8 flags;
	u8 priority;
	u8 flags2;
	u8 data_offset;
};

/*
 * maximum length of firmware signal data between
 * the BCDC header and packet data in the tx path.
 */
#define IFXF_PROT_FW_SIGNAL_MAX_TXBYTES	12

#define RETRIES 2 /* # of retries to retrieve matching dcmd response */
#define BUS_HEADER_LEN	(16+64)		/* Must be atleast SDPCM_RESERVE
					 * (amount of header tha might be added)
					 * plus any space that might be needed
					 * for bus alignment padding.
					 */
#define ROUND_UP_MARGIN 2048

struct ifxf_bcdc {
	u16 reqid;
	u8 bus_header[BUS_HEADER_LEN];
	struct ifxf_proto_bcdc_dcmd msg;
	unsigned char buf[IFXF_DCMD_MAXLEN];
	struct ifxf_fws_info *fws;
};


struct ifxf_fws_info *drvr_to_fws(struct ifxf_pub *drvr)
{
	struct ifxf_bcdc *bcdc = drvr->proto->pd;

	return bcdc->fws;
}

static int
ifxf_proto_bcdc_msg(struct ifxf_pub *drvr, int ifidx, uint cmd, void *buf,
		     uint len, bool set)
{
	struct ifxf_bcdc *bcdc = (struct ifxf_bcdc *)drvr->proto->pd;
	struct ifxf_proto_bcdc_dcmd *msg = &bcdc->msg;
	u32 flags;

	ifxf_dbg(BCDC, "Enter\n");

	memset(msg, 0, sizeof(struct ifxf_proto_bcdc_dcmd));

	msg->cmd = cpu_to_le32(cmd);
	msg->len = cpu_to_le32(len);
	flags = (++bcdc->reqid << BCDC_DCMD_ID_SHIFT);
	if (set)
		flags |= BCDC_DCMD_SET;
	flags = (flags & ~BCDC_DCMD_IF_MASK) |
		(ifidx << BCDC_DCMD_IF_SHIFT);
	msg->flags = cpu_to_le32(flags);

	if (buf)
		memcpy(bcdc->buf, buf, len);

	len += sizeof(*msg);
	if (len > IFXF_TX_IOCTL_MAX_MSG_SIZE)
		len = IFXF_TX_IOCTL_MAX_MSG_SIZE;

	/* Send request */
	return ifxf_bus_txctl(drvr->bus_if, (unsigned char *)&bcdc->msg, len);
}

static int ifxf_proto_bcdc_cmplt(struct ifxf_pub *drvr, u32 id, u32 len)
{
	int ret;
	struct ifxf_bcdc *bcdc = (struct ifxf_bcdc *)drvr->proto->pd;

	ifxf_dbg(BCDC, "Enter\n");
	len += sizeof(struct ifxf_proto_bcdc_dcmd);
	do {
		ret = ifxf_bus_rxctl(drvr->bus_if, (unsigned char *)&bcdc->msg,
				      len);
		if (ret < 0)
			break;
	} while (BCDC_DCMD_ID(le32_to_cpu(bcdc->msg.flags)) != id);

	return ret;
}

static int
ifxf_proto_bcdc_query_dcmd(struct ifxf_pub *drvr, int ifidx, uint cmd,
			    void *buf, uint len, int *fwerr)
{
	struct ifxf_bcdc *bcdc = (struct ifxf_bcdc *)drvr->proto->pd;
	struct ifxf_proto_bcdc_dcmd *msg = &bcdc->msg;
	void *info;
	int ret = 0, retries = 0;
	u32 id, flags;

	ifxf_dbg(BCDC, "Enter, cmd %d len %d\n", cmd, len);

	*fwerr = 0;
	ret = ifxf_proto_bcdc_msg(drvr, ifidx, cmd, buf, len, false);
	if (ret < 0) {
		bphy_err(drvr, "ifxf_proto_bcdc_msg failed w/status %d\n",
			 ret);
		goto done;
	}

retry:
	/* wait for interrupt and get first fragment */
	ret = ifxf_proto_bcdc_cmplt(drvr, bcdc->reqid, len);
	if (ret < 0)
		goto done;

	flags = le32_to_cpu(msg->flags);
	id = (flags & BCDC_DCMD_ID_MASK) >> BCDC_DCMD_ID_SHIFT;

	if ((id < bcdc->reqid) && (++retries < RETRIES))
		goto retry;
	if (id != bcdc->reqid) {
		bphy_err(drvr, "%s: unexpected request id %d (expected %d)\n",
			 ifxf_ifname(ifxf_get_ifp(drvr, ifidx)), id,
			 bcdc->reqid);
		ret = -EINVAL;
		goto done;
	}

	/* Check info buffer */
	info = (void *)&bcdc->buf[0];

	/* Copy info buffer */
	if (buf) {
		if (ret < (int)len)
			len = ret;
		memcpy(buf, info, len);
	}

	ret = 0;

	/* Check the ERROR flag */
	if (flags & BCDC_DCMD_ERROR)
		*fwerr = le32_to_cpu(msg->status);
done:
	return ret;
}

static int
ifxf_proto_bcdc_set_dcmd(struct ifxf_pub *drvr, int ifidx, uint cmd,
			  void *buf, uint len, int *fwerr)
{
	struct ifxf_bcdc *bcdc = (struct ifxf_bcdc *)drvr->proto->pd;
	struct ifxf_proto_bcdc_dcmd *msg = &bcdc->msg;
	int ret;
	u32 flags, id;

	ifxf_dbg(BCDC, "Enter, cmd %d len %d\n", cmd, len);

	*fwerr = 0;
	ret = ifxf_proto_bcdc_msg(drvr, ifidx, cmd, buf, len, true);
	if (ret < 0)
		goto done;

	ret = ifxf_proto_bcdc_cmplt(drvr, bcdc->reqid, len);
	if (ret < 0)
		goto done;

	flags = le32_to_cpu(msg->flags);
	id = (flags & BCDC_DCMD_ID_MASK) >> BCDC_DCMD_ID_SHIFT;

	if (id != bcdc->reqid) {
		bphy_err(drvr, "%s: unexpected request id %d (expected %d)\n",
			 ifxf_ifname(ifxf_get_ifp(drvr, ifidx)), id,
			 bcdc->reqid);
		ret = -EINVAL;
		goto done;
	}

	ret = 0;

	/* Check the ERROR flag */
	if (flags & BCDC_DCMD_ERROR)
		*fwerr = le32_to_cpu(msg->status);

done:
	return ret;
}

static void
ifxf_proto_bcdc_hdrpush(struct ifxf_pub *drvr, int ifidx, u8 offset,
			 struct sk_buff *pktbuf)
{
	struct ifxf_proto_bcdc_header *h;

	ifxf_dbg(BCDC, "Enter\n");

	/* Push BDC header used to convey priority for buses that don't */
	skb_push(pktbuf, BCDC_HEADER_LEN);

	h = (struct ifxf_proto_bcdc_header *)(pktbuf->data);

	h->flags = (BCDC_PROTO_VER << BCDC_FLAG_VER_SHIFT);
	if (pktbuf->ip_summed == CHECKSUM_PARTIAL)
		h->flags |= BCDC_FLAG_SUM_NEEDED;

	h->priority = (pktbuf->priority & BCDC_PRIORITY_MASK);
	h->flags2 = 0;
	h->data_offset = offset;
	BCDC_SET_IF_IDX(h, ifidx);
	trace_ifxf_bcdchdr(pktbuf->data);
}

static int
ifxf_proto_bcdc_hdrpull(struct ifxf_pub *drvr, bool do_fws,
			 struct sk_buff *pktbuf, struct ifxf_if **ifp)
{
	struct ifxf_proto_bcdc_header *h;
	struct ifxf_if *tmp_if;

	ifxf_dbg(BCDC, "Enter\n");

	/* Pop BCDC header used to convey priority for buses that don't */
	if (pktbuf->len <= BCDC_HEADER_LEN) {
		ifxf_dbg(INFO, "rx data too short (%d <= %d)\n",
			  pktbuf->len, BCDC_HEADER_LEN);
		return -EBADE;
	}

	trace_ifxf_bcdchdr(pktbuf->data);
	h = (struct ifxf_proto_bcdc_header *)(pktbuf->data);

	tmp_if = ifxf_get_ifp(drvr, BCDC_GET_IF_IDX(h));
	if (!tmp_if) {
		ifxf_dbg(INFO, "no matching ifp found\n");
		return -EBADE;
	}
	if (((h->flags & BCDC_FLAG_VER_MASK) >> BCDC_FLAG_VER_SHIFT) !=
	    BCDC_PROTO_VER) {
		bphy_err(drvr, "%s: non-BCDC packet received, flags 0x%x\n",
			 ifxf_ifname(tmp_if), h->flags);
		return -EBADE;
	}

	if (h->flags & BCDC_FLAG_SUM_GOOD) {
		ifxf_dbg(BCDC, "%s: BDC rcv, good checksum, flags 0x%x\n",
			  ifxf_ifname(tmp_if), h->flags);
		pktbuf->ip_summed = CHECKSUM_UNNECESSARY;
	}

	pktbuf->priority = h->priority & BCDC_PRIORITY_MASK;

	skb_pull(pktbuf, BCDC_HEADER_LEN);
	if (do_fws)
		ifxf_fws_hdrpull(tmp_if, h->data_offset << 2, pktbuf);
	else
		skb_pull(pktbuf, h->data_offset << 2);

	if (pktbuf->len == 0)
		return -ENODATA;

	if (ifp != NULL)
		*ifp = tmp_if;
	return 0;
}

static int ifxf_proto_bcdc_tx_queue_data(struct ifxf_pub *drvr, int ifidx,
					  struct sk_buff *skb)
{
	struct ifxf_if *ifp = ifxf_get_ifp(drvr, ifidx);
	struct ifxf_bcdc *bcdc = drvr->proto->pd;

	if (!ifxf_fws_queue_skbs(bcdc->fws))
		return ifxf_proto_txdata(drvr, ifidx, 0, skb);

	return ifxf_fws_process_skb(ifp, skb);
}

static int
ifxf_proto_bcdc_txdata(struct ifxf_pub *drvr, int ifidx, u8 offset,
			struct sk_buff *pktbuf)
{
	ifxf_proto_bcdc_hdrpush(drvr, ifidx, offset, pktbuf);
	return ifxf_bus_txdata(drvr->bus_if, pktbuf);
}

void ifxf_proto_bcdc_txflowblock(struct device *dev, bool state)
{
	struct ifxf_bus *bus_if = dev_get_drvdata(dev);
	struct ifxf_pub *drvr = bus_if->drvr;

	ifxf_dbg(TRACE, "Enter\n");

	ifxf_fws_bus_blocked(drvr, state);
}

void
ifxf_proto_bcdc_txcomplete(struct device *dev, struct sk_buff *txp,
			    bool success)
{
	struct ifxf_bus *bus_if = dev_get_drvdata(dev);
	struct ifxf_bcdc *bcdc = bus_if->drvr->proto->pd;
	struct ifxf_if *ifp;

	/* await txstatus signal for firmware if active */
	if (ifxf_fws_fc_active(bcdc->fws)) {
		ifxf_fws_bustxcomplete(bcdc->fws, txp, success);
	} else {
		if (ifxf_proto_bcdc_hdrpull(bus_if->drvr, false, txp, &ifp))
			ifxu_pkt_buf_free_skb(txp);
		else
			ifxf_txfinalize(ifp, txp, success);
	}
}

static void
ifxf_proto_bcdc_configure_addr_mode(struct ifxf_pub *drvr, int ifidx,
				     enum proto_addr_mode addr_mode)
{
}

static void
ifxf_proto_bcdc_delete_peer(struct ifxf_pub *drvr, int ifidx,
			     u8 peer[ETH_ALEN])
{
}

static void
ifxf_proto_bcdc_add_tdls_peer(struct ifxf_pub *drvr, int ifidx,
			       u8 peer[ETH_ALEN])
{
}

static void ifxf_proto_bcdc_rxreorder(struct ifxf_if *ifp,
				       struct sk_buff *skb)
{
	ifxf_fws_rxreorder(ifp, skb);
}

static void
ifxf_proto_bcdc_add_if(struct ifxf_if *ifp)
{
	ifxf_fws_add_interface(ifp);
}

static void
ifxf_proto_bcdc_del_if(struct ifxf_if *ifp)
{
	ifxf_fws_del_interface(ifp);
}

static void
ifxf_proto_bcdc_reset_if(struct ifxf_if *ifp)
{
	ifxf_fws_reset_interface(ifp);
}

static int
ifxf_proto_bcdc_init_done(struct ifxf_pub *drvr)
{
	struct ifxf_bcdc *bcdc = drvr->proto->pd;
	struct ifxf_fws_info *fws;

	fws = ifxf_fws_attach(drvr);
	if (IS_ERR(fws))
		return PTR_ERR(fws);

	bcdc->fws = fws;
	return 0;
}

static void ifxf_proto_bcdc_debugfs_create(struct ifxf_pub *drvr)
{
	ifxf_fws_debugfs_create(drvr);
}

int ifxf_proto_bcdc_attach(struct ifxf_pub *drvr)
{
	struct ifxf_bcdc *bcdc;

	bcdc = kzalloc(sizeof(*bcdc), GFP_ATOMIC);
	if (!bcdc)
		goto fail;

	/* ensure that the msg buf directly follows the cdc msg struct */
	if ((unsigned long)(&bcdc->msg + 1) != (unsigned long)bcdc->buf) {
		bphy_err(drvr, "struct ifxf_proto_bcdc is not correctly defined\n");
		goto fail;
	}

	drvr->proto->hdrpull = ifxf_proto_bcdc_hdrpull;
	drvr->proto->query_dcmd = ifxf_proto_bcdc_query_dcmd;
	drvr->proto->set_dcmd = ifxf_proto_bcdc_set_dcmd;
	drvr->proto->tx_queue_data = ifxf_proto_bcdc_tx_queue_data;
	drvr->proto->txdata = ifxf_proto_bcdc_txdata;
	drvr->proto->configure_addr_mode = ifxf_proto_bcdc_configure_addr_mode;
	drvr->proto->delete_peer = ifxf_proto_bcdc_delete_peer;
	drvr->proto->add_tdls_peer = ifxf_proto_bcdc_add_tdls_peer;
	drvr->proto->rxreorder = ifxf_proto_bcdc_rxreorder;
	drvr->proto->add_if = ifxf_proto_bcdc_add_if;
	drvr->proto->del_if = ifxf_proto_bcdc_del_if;
	drvr->proto->reset_if = ifxf_proto_bcdc_reset_if;
	drvr->proto->init_done = ifxf_proto_bcdc_init_done;
	drvr->proto->debugfs_create = ifxf_proto_bcdc_debugfs_create;
	drvr->proto->pd = bcdc;

	drvr->hdrlen += BCDC_HEADER_LEN + IFXF_PROT_FW_SIGNAL_MAX_TXBYTES;
	drvr->bus_if->maxctl = IFXF_DCMD_MAXLEN +
			sizeof(struct ifxf_proto_bcdc_dcmd) + ROUND_UP_MARGIN;
	return 0;

fail:
	kfree(bcdc);
	return -ENOMEM;
}

void ifxf_proto_bcdc_detach(struct ifxf_pub *drvr)
{
	struct ifxf_bcdc *bcdc = drvr->proto->pd;

	drvr->proto->pd = NULL;
	ifxf_fws_detach(bcdc->fws);
	kfree(bcdc);
}
