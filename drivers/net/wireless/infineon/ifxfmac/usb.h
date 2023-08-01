// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2011 Broadcom Corporation
 */
#ifndef IFXFMAC_USB_H
#define IFXFMAC_USB_H

enum ifxf_usb_state {
	IFXFMAC_USB_STATE_DOWN,
	IFXFMAC_USB_STATE_DL_FAIL,
	IFXFMAC_USB_STATE_DL_DONE,
	IFXFMAC_USB_STATE_UP,
	IFXFMAC_USB_STATE_SLEEP
};

struct ifxf_stats {
	u32 tx_ctlpkts;
	u32 tx_ctlerrs;
	u32 rx_ctlpkts;
	u32 rx_ctlerrs;
};

struct ifxf_usbdev {
	struct ifxf_bus *bus;
	struct ifxf_usbdev_info *devinfo;
	enum ifxf_usb_state state;
	struct ifxf_stats stats;
	int ntxq, nrxq, rxsize;
	u32 bus_mtu;
	int devid;
	int chiprev; /* chip revision number */
};

/* IO Request Block (IRB) */
struct ifxf_usbreq {
	struct list_head list;
	struct ifxf_usbdev_info *devinfo;
	struct urb *urb;
	struct sk_buff  *skb;
};

#endif /* IFXFMAC_USB_H */
