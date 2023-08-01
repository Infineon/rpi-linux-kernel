// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2012 Broadcom Corporation
 */

#ifndef FWSIGNAL_H_
#define FWSIGNAL_H_

/**
 * enum ifxf_fws_fifo - fifo indices used by dongle firmware.
 *
 * @IFXF_FWS_FIFO_FIRST: first fifo, ie. background.
 * @IFXF_FWS_FIFO_AC_BK: fifo for background traffic.
 * @IFXF_FWS_FIFO_AC_BE: fifo for best-effort traffic.
 * @IFXF_FWS_FIFO_AC_VI: fifo for video traffic.
 * @IFXF_FWS_FIFO_AC_VO: fifo for voice traffic.
 * @IFXF_FWS_FIFO_BCMC: fifo for broadcast/multicast (AP only).
 * @IFXF_FWS_FIFO_ATIM: fifo for ATIM (AP only).
 * @IFXF_FWS_FIFO_COUNT: number of fifos.
 */
enum ifxf_fws_fifo {
	IFXF_FWS_FIFO_FIRST,
	IFXF_FWS_FIFO_AC_BK = IFXF_FWS_FIFO_FIRST,
	IFXF_FWS_FIFO_AC_BE,
	IFXF_FWS_FIFO_AC_VI,
	IFXF_FWS_FIFO_AC_VO,
	IFXF_FWS_FIFO_BCMC,
	IFXF_FWS_FIFO_ATIM,
	IFXF_FWS_FIFO_COUNT
};

struct ifxf_fws_info *ifxf_fws_attach(struct ifxf_pub *drvr);
void ifxf_fws_detach(struct ifxf_fws_info *fws);
void ifxf_fws_debugfs_create(struct ifxf_pub *drvr);
bool ifxf_fws_queue_skbs(struct ifxf_fws_info *fws);
bool ifxf_fws_fc_active(struct ifxf_fws_info *fws);
void ifxf_fws_hdrpull(struct ifxf_if *ifp, s16 siglen, struct sk_buff *skb);
int ifxf_fws_process_skb(struct ifxf_if *ifp, struct sk_buff *skb);

void ifxf_fws_reset_interface(struct ifxf_if *ifp);
void ifxf_fws_add_interface(struct ifxf_if *ifp);
void ifxf_fws_del_interface(struct ifxf_if *ifp);
void ifxf_fws_bustxcomplete(struct ifxf_fws_info *fws, struct sk_buff *skb,
			     bool success);
void ifxf_fws_bus_blocked(struct ifxf_pub *drvr, bool flow_blocked);
void ifxf_fws_rxreorder(struct ifxf_if *ifp, struct sk_buff *skb);

#endif /* FWSIGNAL_H_ */
