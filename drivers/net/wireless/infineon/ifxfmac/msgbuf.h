// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2014 Broadcom Corporation
 */
#ifndef IFXFMAC_MSGBUF_H
#define IFXFMAC_MSGBUF_H

#ifdef CONFIG_IFXFMAC_PROTO_MSGBUF

#define IFXF_H2D_MSGRING_CONTROL_SUBMIT_MAX_ITEM	64
#define IFXF_H2D_MSGRING_RXPOST_SUBMIT_MAX_ITEM	1024
#define IFXF_D2H_MSGRING_CONTROL_COMPLETE_MAX_ITEM	64
#define IFXF_D2H_MSGRING_TX_COMPLETE_MAX_ITEM		1024
#define IFXF_D2H_MSGRING_RX_COMPLETE_MAX_ITEM		1024
#define IFXF_H2D_TXFLOWRING_MAX_ITEM			512

#define IFXF_H2D_MSGRING_CONTROL_SUBMIT_ITEMSIZE	40
#define IFXF_H2D_MSGRING_RXPOST_SUBMIT_ITEMSIZE	32
#define IFXF_D2H_MSGRING_CONTROL_COMPLETE_ITEMSIZE	24
#define IFXF_D2H_MSGRING_TX_COMPLETE_ITEMSIZE_PRE_V7	16
#define IFXF_D2H_MSGRING_TX_COMPLETE_ITEMSIZE		24
#define IFXF_D2H_MSGRING_RX_COMPLETE_ITEMSIZE_PRE_V7	32
#define IFXF_D2H_MSGRING_RX_COMPLETE_ITEMSIZE		40
#define IFXF_H2D_TXFLOWRING_ITEMSIZE			48

struct msgbuf_buf_addr {
	__le32		low_addr;
	__le32		high_addr;
};

int ifxf_proto_msgbuf_rx_trigger(struct device *dev);
void ifxf_msgbuf_delete_flowring(struct ifxf_pub *drvr, u16 flowid);
int ifxf_proto_msgbuf_attach(struct ifxf_pub *drvr);
void ifxf_proto_msgbuf_detach(struct ifxf_pub *drvr);
#else
static inline int ifxf_proto_msgbuf_attach(struct ifxf_pub *drvr)
{
	return 0;
}
static inline void ifxf_proto_msgbuf_detach(struct ifxf_pub *drvr) {}
#endif
int ifxf_msgbuf_tx_mbdata(struct ifxf_pub *drvr, u32 mbdata);

#endif /* IFXFMAC_MSGBUF_H */
