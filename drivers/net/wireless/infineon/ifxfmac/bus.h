// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2010 Broadcom Corporation
 */

#ifndef IFXFMAC_BUS_H
#define IFXFMAC_BUS_H

#include <linux/kernel.h>
#include <linux/firmware.h>
#include "debug.h"
#include <linux/version.h>

/* IDs of the 6 default common rings of msgbuf protocol */
#define IFXF_H2D_MSGRING_CONTROL_SUBMIT	0
#define IFXF_H2D_MSGRING_RXPOST_SUBMIT		1
#define IFXF_H2D_MSGRING_FLOWRING_IDSTART	2
#define IFXF_D2H_MSGRING_CONTROL_COMPLETE	2
#define IFXF_D2H_MSGRING_TX_COMPLETE		3
#define IFXF_D2H_MSGRING_RX_COMPLETE		4


#define IFXF_NROF_H2D_COMMON_MSGRINGS		2
#define IFXF_NROF_D2H_COMMON_MSGRINGS		3
#define IFXF_NROF_COMMON_MSGRINGS	(IFXF_NROF_H2D_COMMON_MSGRINGS + \
					 IFXF_NROF_D2H_COMMON_MSGRINGS)

/* The interval to poll console */
#define IFXF_CONSOLE	10

/* The maximum console interval value (5 mins) */
#define MAX_CONSOLE_INTERVAL	(5 * 60)

/* The level of bus communication with the dongle */
enum ifxf_bus_state {
	IFXF_BUS_DOWN,		/* Not ready for frame transfers */
	IFXF_BUS_UP		/* Ready for frame transfers */
};

/* The level of bus communication with the dongle */
enum ifxf_bus_protocol_type {
	IFXF_PROTO_BCDC,
	IFXF_PROTO_MSGBUF
};

/* Firmware blobs that may be available */
enum ifxf_blob_type {
	IFXF_BLOB_CLM,
};

struct ifxf_mp_device;

struct ifxf_bus_dcmd {
	char *name;
	char *param;
	int param_len;
	struct list_head list;
};

/**
 * struct ifxf_bus_ops - bus callback operations.
 *
 * @preinit: execute bus/device specific dongle init commands (optional).
 * @init: prepare for communication with dongle.
 * @stop: clear pending frames, disable data flow.
 * @txdata: send a data frame to the dongle. When the data
 *	has been transferred, the common driver must be
 *	notified using ifxf_txcomplete(). The common
 *	driver calls this function with interrupts
 *	disabled.
 * @txctl: transmit a control request message to dongle.
 * @rxctl: receive a control response message from dongle.
 * @gettxq: obtain a reference of bus transmit queue (optional).
 * @wowl_config: specify if dongle is configured for wowl when going to suspend
 * @get_ramsize: obtain size of device memory.
 * @get_memdump: obtain device memory dump in provided buffer.
 * @get_blob: obtain a firmware blob.
 *
 * This structure provides an abstract interface towards the
 * bus specific driver. For control messages to common driver
 * will assure there is only one active transaction. Unless
 * indicated otherwise these callbacks are mandatory.
 */
struct ifxf_bus_ops {
	int (*preinit)(struct device *dev);
	void (*stop)(struct device *dev);
	int (*txdata)(struct device *dev, struct sk_buff *skb);
	int (*txctl)(struct device *dev, unsigned char *msg, uint len);
	int (*rxctl)(struct device *dev, unsigned char *msg, uint len);
	struct pktq * (*gettxq)(struct device *dev);
	void (*wowl_config)(struct device *dev, bool enabled);
	size_t (*get_ramsize)(struct device *dev);
	int (*get_memdump)(struct device *dev, void *data, size_t len);
	int (*get_blob)(struct device *dev, const struct firmware **fw,
			enum ifxf_blob_type type);
	void (*debugfs_create)(struct device *dev);
	int (*reset)(struct device *dev);
};


/**
 * struct ifxf_bus_msgbuf - bus ringbuf if in case of msgbuf.
 *
 * @commonrings: commonrings which are always there.
 * @flowrings: commonrings which are dynamically created and destroyed for data.
 * @rx_dataoffset: if set then all rx data has this offset.
 * @max_rxbufpost: maximum number of buffers to post for rx.
 * @max_flowrings: maximum number of tx flow rings supported.
 * @max_submissionrings: maximum number of submission rings(h2d) supported.
 * @max_completionrings: maximum number of completion rings(d2h) supported.
 */
struct ifxf_bus_msgbuf {
	struct ifxf_commonring *commonrings[IFXF_NROF_COMMON_MSGRINGS];
	struct ifxf_commonring **flowrings;
	u32 rx_dataoffset;
	u32 max_rxbufpost;
	u16 max_flowrings;
	u16 max_submissionrings;
	u16 max_completionrings;
};


/**
 * struct ifxf_bus_stats - bus statistic counters.
 *
 * @pktcowed: packets cowed for extra headroom/unorphan.
 * @pktcow_failed: packets dropped due to failed cow-ing.
 */
struct ifxf_bus_stats {
	atomic_t pktcowed;
	atomic_t pktcow_failed;
};

/**
 * struct ifxf_bt_dev - bt shared SDIO device.
 *
 * @ bt_data: bt internal structure data
 * @ bt_sdio_int_cb: bt registered interrupt callback function
 * @ bt_use_count: Counter that tracks whether BT is using the bus
 */
struct ifxf_bt_dev {
	void	*bt_data;
	void	(*bt_sdio_int_cb)(void *data);
	u32	use_count; /* Counter for tracking if BT is using the bus */
};

/**
 * struct ifxf_bus - interface structure between common and bus layer
 *
 * @bus_priv: pointer to private bus device.
 * @proto_type: protocol type, bcdc or msgbuf
 * @dev: device pointer of bus device.
 * @drvr: public driver information.
 * @state: operational state of the bus interface.
 * @stats: statistics shared between common and bus layer.
 * @maxctl: maximum size for rxctl request message.
 * @chip: device identifier of the dongle chip.
 * @always_use_fws_queue: bus wants use queue also when fwsignal is inactive.
 * @wowl_supported: is wowl supported by bus driver.
 * @chiprev: revision of the dongle chip.
 * @msgbuf: msgbuf protocol parameters provided by bus layer.
 * @bt_dev: bt shared SDIO device
 */
struct ifxf_bus {
	union {
		struct ifxf_sdio_dev *sdio;
		struct ifxf_usbdev *usb;
		struct ifxf_pciedev *pcie;
	} bus_priv;
	enum ifxf_bus_protocol_type proto_type;
	struct device *dev;
	struct ifxf_pub *drvr;
	enum ifxf_bus_state state;
	struct ifxf_bus_stats stats;
	uint maxctl;
	u32 chip;
	u32 chiprev;
	bool always_use_fws_queue;
	bool wowl_supported;

	const struct ifxf_bus_ops *ops;
	struct ifxf_bus_msgbuf *msgbuf;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0))
	bool allow_skborphan;
#endif
#ifdef CONFIG_IFXFMAC_BT_SHARED_SDIO
	struct ifxf_bt_dev *bt_dev;
#endif /* CONFIG_IFXFMAC_BT_SHARED_SDIO */
};

/*
 * callback wrappers
 */
static inline int ifxf_bus_preinit(struct ifxf_bus *bus)
{
	if (!bus->ops->preinit)
		return 0;
	return bus->ops->preinit(bus->dev);
}

static inline void ifxf_bus_stop(struct ifxf_bus *bus)
{
	bus->ops->stop(bus->dev);
}

static inline int ifxf_bus_txdata(struct ifxf_bus *bus, struct sk_buff *skb)
{
	return bus->ops->txdata(bus->dev, skb);
}

static inline
int ifxf_bus_txctl(struct ifxf_bus *bus, unsigned char *msg, uint len)
{
	return bus->ops->txctl(bus->dev, msg, len);
}

static inline
int ifxf_bus_rxctl(struct ifxf_bus *bus, unsigned char *msg, uint len)
{
	return bus->ops->rxctl(bus->dev, msg, len);
}

static inline
struct pktq *ifxf_bus_gettxq(struct ifxf_bus *bus)
{
	if (!bus->ops->gettxq)
		return ERR_PTR(-ENOENT);

	return bus->ops->gettxq(bus->dev);
}

static inline
void ifxf_bus_wowl_config(struct ifxf_bus *bus, bool enabled)
{
	if (bus->ops->wowl_config)
		bus->ops->wowl_config(bus->dev, enabled);
}

static inline size_t ifxf_bus_get_ramsize(struct ifxf_bus *bus)
{
	if (!bus->ops->get_ramsize)
		return 0;

	return bus->ops->get_ramsize(bus->dev);
}

static inline
int ifxf_bus_get_memdump(struct ifxf_bus *bus, void *data, size_t len)
{
	if (!bus->ops->get_memdump)
		return -EOPNOTSUPP;

	return bus->ops->get_memdump(bus->dev, data, len);
}

static inline
int ifxf_bus_get_blob(struct ifxf_bus *bus, const struct firmware **fw,
		       enum ifxf_blob_type type)
{
	return bus->ops->get_blob(bus->dev, fw, type);
}

static inline
void ifxf_bus_debugfs_create(struct ifxf_bus *bus)
{
	if (!bus->ops->debugfs_create)
		return;

	return bus->ops->debugfs_create(bus->dev);
}

static inline
int ifxf_bus_reset(struct ifxf_bus *bus)
{
	if (!bus->ops->reset)
		return -EOPNOTSUPP;

	return bus->ops->reset(bus->dev);
}

/*
 * interface functions from common layer
 */

/* Receive frame for delivery to OS.  Callee disposes of rxp. */
struct sk_buff *ifxf_rx_frame(struct device *dev, struct sk_buff *rxp, bool handle_event,
			       bool inirq);
/* Receive async event packet from firmware. Callee disposes of rxp. */
void ifxf_rx_event(struct device *dev, struct sk_buff *rxp);

int ifxf_alloc(struct device *dev, struct ifxf_mp_device *settings);
/* Indication from bus module regarding presence/insertion of dongle. */
int ifxf_attach(struct device *dev, bool start_bus);
/* Indication from bus module regarding removal/absence of dongle */
void ifxf_detach(struct device *dev);
void ifxf_free(struct device *dev);
/* Indication from bus module that dongle should be reset */
void ifxf_dev_reset(struct device *dev);
/* Request from bus module to initiate a coredump */
void ifxf_dev_coredump(struct device *dev);
/* Indication that firmware has halted or crashed */
void ifxf_fw_crashed(struct device *dev);

/* Configure the "global" bus state used by upper layers */
void ifxf_bus_change_state(struct ifxf_bus *bus, enum ifxf_bus_state state);

s32 ifxf_iovar_data_set(struct device *dev, char *name, void *data, u32 len);
void ifxf_bus_add_txhdrlen(struct device *dev, uint len);
int ifxf_fwlog_attach(struct device *dev);

#ifdef CONFIG_IFXFMAC_SDIO
void ifxf_sdio_exit(void);
int ifxf_sdio_register(void);
#else
static inline void ifxf_sdio_exit(void) { }
static inline int ifxf_sdio_register(void) { return 0; }
#endif

#ifdef CONFIG_IFXFMAC_USB
void ifxf_usb_exit(void);
int ifxf_usb_register(void);
#else
static inline void ifxf_usb_exit(void) { }
static inline int ifxf_usb_register(void) { return 0; }
#endif

#ifdef CONFIG_IFXFMAC_PCIE
void ifxf_pcie_exit(void);
int ifxf_pcie_register(void);
#else
static inline void ifxf_pcie_exit(void) { }
static inline int ifxf_pcie_register(void) { return 0; }
#endif

#endif /* IFXFMAC_BUS_H */
