// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2011 Broadcom Corporation
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/firmware.h>
#include <linux/usb.h>
#include <linux/vmalloc.h>

#include <ifxu_utils.h>
#include <ifx_hw_ids.h>
#include <ifxu_wifi.h>
#include "bus.h"
#include "debug.h"
#include "firmware.h"
#include "usb.h"
#include "core.h"
#include "common.h"
#include "bcdc.h"
#include "cfg80211.h"


#define IOCTL_RESP_TIMEOUT		msecs_to_jiffies(2000)

#define IFXF_USB_RESET_GETVER_SPINWAIT	100	/* in unit of ms */
#define IFXF_USB_RESET_GETVER_LOOP_CNT	10

#define IFXF_POSTBOOT_ID		0xA123  /* ID to detect if dongle
						   has boot up */
#define IFXF_USB_NRXQ			50
#define IFXF_USB_NTXQ			50

#define IFXF_USB_CBCTL_WRITE		0
#define IFXF_USB_CBCTL_READ		1
#define IFXF_USB_MAX_PKT_SIZE		1600

CY_FW_DEF(4373, "cyfmac4373");

static const struct ifxf_firmware_mapping ifxf_usb_fwnames[] = {
	CYF_FW_ENTRY(CY_CC_4373_CHIP_ID, 0xFFFFFFFF, 4373)
};

#define TRX_MAGIC		0x30524448	/* "HDR0" */
#define TRX_MAX_OFFSET		3		/* Max number of file offsets */
#define TRX_UNCOMP_IMAGE	0x20		/* Trx holds uncompressed img */
#define TRX_RDL_CHUNK		1500		/* size of each dl transfer */
#define TRX_OFFSETS_DLFWLEN_IDX	0

/* Control messages: bRequest values */
#define DL_GETSTATE	0	/* returns the rdl_state_t struct */
#define DL_CHECK_CRC	1	/* currently unused */
#define DL_GO		2	/* execute downloaded image */
#define DL_START	3	/* initialize dl state */
#define DL_REBOOT	4	/* reboot the device in 2 seconds */
#define DL_GETVER	5	/* returns the bootrom_id_t struct */
#define DL_GO_PROTECTED	6	/* execute the downloaded code and set reset
				 * event to occur in 2 seconds.  It is the
				 * responsibility of the downloaded code to
				 * clear this event
				 */
#define DL_EXEC		7	/* jump to a supplied address */
#define DL_RESETCFG	8	/* To support single enum on dongle
				 * - Not used by bootloader
				 */
#define DL_DEFER_RESP_OK 9	/* Potentially defer the response to setup
				 * if resp unavailable
				 */

/* states */
#define DL_WAITING	0	/* waiting to rx first pkt */
#define DL_READY	1	/* hdr was good, waiting for more of the
				 * compressed image
				 */
#define DL_BAD_HDR	2	/* hdr was corrupted */
#define DL_BAD_CRC	3	/* compressed image was corrupted */
#define DL_RUNNABLE	4	/* download was successful,waiting for go cmd */
#define DL_START_FAIL	5	/* failed to initialize correctly */
#define DL_NVRAM_TOOBIG	6	/* host specified nvram data exceeds DL_NVRAM
				 * value
				 */
#define DL_IMAGE_TOOBIG	7	/* firmware image too big */


struct trx_header_le {
	__le32 magic;		/* "HDR0" */
	__le32 len;		/* Length of file including header */
	__le32 crc32;		/* CRC from flag_version to end of file */
	__le32 flag_version;	/* 0:15 flags, 16:31 version */
	__le32 offsets[TRX_MAX_OFFSET];	/* Offsets of partitions from start of
					 * header
					 */
};

struct rdl_state_le {
	__le32 state;
	__le32 bytes;
};

struct bootrom_id_le {
	__le32 chip;		/* Chip id */
	__le32 chiprev;		/* Chip rev */
	__le32 ramsize;		/* Size of  RAM */
	__le32 remapbase;	/* Current remap base address */
	__le32 boardtype;	/* Type of board */
	__le32 boardrev;	/* Board revision */
};

struct ifxf_usb_image {
	struct list_head list;
	s8 *fwname;
	u8 *image;
	int image_len;
};

struct ifxf_usbdev_info {
	struct ifxf_usbdev bus_pub; /* MUST BE FIRST */
	spinlock_t qlock;
	struct list_head rx_freeq;
	struct list_head rx_postq;
	struct list_head tx_freeq;
	struct list_head tx_postq;
	uint rx_pipe, tx_pipe;

	int rx_low_watermark;
	int tx_low_watermark;
	int tx_high_watermark;
	int tx_freecount;
	bool tx_flowblock;
	spinlock_t tx_flowblock_lock;

	struct ifxf_usbreq *tx_reqs;
	struct ifxf_usbreq *rx_reqs;

	char fw_name[IFXF_FW_NAME_LEN];
	const u8 *image;	/* buffer for combine fw and nvram */
	int image_len;

	struct usb_device *usbdev;
	struct device *dev;
	struct completion dev_init_done;

	int ctl_in_pipe, ctl_out_pipe;
	struct urb *ctl_urb; /* URB for control endpoint */
	struct usb_ctrlrequest ctl_write;
	struct usb_ctrlrequest ctl_read;
	u32 ctl_urb_actual_length;
	int ctl_urb_status;
	int ctl_completed;
	wait_queue_head_t ioctl_resp_wait;
	ulong ctl_op;
	u8 ifnum;

	struct urb *bulk_urb; /* used for FW download */

	struct ifxf_mp_device *settings;
};

static void ifxf_usb_rx_refill(struct ifxf_usbdev_info *devinfo,
				struct ifxf_usbreq  *req);

static struct ifxf_usbdev *ifxf_usb_get_buspub(struct device *dev)
{
	struct ifxf_bus *bus_if = dev_get_drvdata(dev);
	return bus_if->bus_priv.usb;
}

static struct ifxf_usbdev_info *ifxf_usb_get_businfo(struct device *dev)
{
	return ifxf_usb_get_buspub(dev)->devinfo;
}

static int ifxf_usb_ioctl_resp_wait(struct ifxf_usbdev_info *devinfo)
{
	return wait_event_timeout(devinfo->ioctl_resp_wait,
				  devinfo->ctl_completed, IOCTL_RESP_TIMEOUT);
}

static void ifxf_usb_ioctl_resp_wake(struct ifxf_usbdev_info *devinfo)
{
	wake_up(&devinfo->ioctl_resp_wait);
}

static void
ifxf_usb_ctl_complete(struct ifxf_usbdev_info *devinfo, int type, int status)
{
	ifxf_dbg(USB, "Enter, status=%d\n", status);

	if (unlikely(devinfo == NULL))
		return;

	if (type == IFXF_USB_CBCTL_READ) {
		if (status == 0)
			devinfo->bus_pub.stats.rx_ctlpkts++;
		else
			devinfo->bus_pub.stats.rx_ctlerrs++;
	} else if (type == IFXF_USB_CBCTL_WRITE) {
		if (status == 0)
			devinfo->bus_pub.stats.tx_ctlpkts++;
		else
			devinfo->bus_pub.stats.tx_ctlerrs++;
	}

	devinfo->ctl_urb_status = status;
	devinfo->ctl_completed = true;
	ifxf_usb_ioctl_resp_wake(devinfo);
}

static void
ifxf_usb_ctlread_complete(struct urb *urb)
{
	struct ifxf_usbdev_info *devinfo =
		(struct ifxf_usbdev_info *)urb->context;

	ifxf_dbg(USB, "Enter\n");
	devinfo->ctl_urb_actual_length = urb->actual_length;
	ifxf_usb_ctl_complete(devinfo, IFXF_USB_CBCTL_READ,
		urb->status);
}

static void
ifxf_usb_ctlwrite_complete(struct urb *urb)
{
	struct ifxf_usbdev_info *devinfo =
		(struct ifxf_usbdev_info *)urb->context;

	ifxf_dbg(USB, "Enter\n");
	ifxf_usb_ctl_complete(devinfo, IFXF_USB_CBCTL_WRITE,
		urb->status);
}

static int
ifxf_usb_send_ctl(struct ifxf_usbdev_info *devinfo, u8 *buf, int len)
{
	int ret;
	u16 size;

	ifxf_dbg(USB, "Enter\n");
	if (devinfo == NULL || buf == NULL ||
	    len == 0 || devinfo->ctl_urb == NULL)
		return -EINVAL;

	size = len;
	devinfo->ctl_write.wLength = cpu_to_le16p(&size);
	devinfo->ctl_urb->transfer_buffer_length = size;
	devinfo->ctl_urb_status = 0;
	devinfo->ctl_urb_actual_length = 0;

	usb_fill_control_urb(devinfo->ctl_urb,
		devinfo->usbdev,
		devinfo->ctl_out_pipe,
		(unsigned char *) &devinfo->ctl_write,
		buf, size,
		(usb_complete_t)ifxf_usb_ctlwrite_complete,
		devinfo);

	ret = usb_submit_urb(devinfo->ctl_urb, GFP_ATOMIC);
	if (ret < 0)
		ifxf_err("usb_submit_urb failed %d\n", ret);

	return ret;
}

static int
ifxf_usb_recv_ctl(struct ifxf_usbdev_info *devinfo, u8 *buf, int len)
{
	int ret;
	u16 size;

	ifxf_dbg(USB, "Enter\n");
	if ((devinfo == NULL) || (buf == NULL) || (len == 0)
		|| (devinfo->ctl_urb == NULL))
		return -EINVAL;

	size = len;
	devinfo->ctl_read.wLength = cpu_to_le16p(&size);
	devinfo->ctl_urb->transfer_buffer_length = size;

	devinfo->ctl_read.bRequestType = USB_DIR_IN
		| USB_TYPE_CLASS | USB_RECIP_INTERFACE;
	devinfo->ctl_read.bRequest = 1;

	usb_fill_control_urb(devinfo->ctl_urb,
		devinfo->usbdev,
		devinfo->ctl_in_pipe,
		(unsigned char *) &devinfo->ctl_read,
		buf, size,
		(usb_complete_t)ifxf_usb_ctlread_complete,
		devinfo);

	ret = usb_submit_urb(devinfo->ctl_urb, GFP_ATOMIC);
	if (ret < 0)
		ifxf_err("usb_submit_urb failed %d\n", ret);

	return ret;
}

static int ifxf_usb_tx_ctlpkt(struct device *dev, u8 *buf, u32 len)
{
	int err = 0;
	int timeout = 0;
	struct ifxf_usbdev_info *devinfo = ifxf_usb_get_businfo(dev);
	struct usb_interface *intf = to_usb_interface(dev);

	ifxf_dbg(USB, "Enter\n");

	err = usb_autopm_get_interface(intf);
	if (err)
		goto out;

	if (devinfo->bus_pub.state != IFXFMAC_USB_STATE_UP) {
		err = -EIO;
		goto fail;
	}

	if (test_and_set_bit(0, &devinfo->ctl_op)) {
		err = -EIO;
		goto fail;
	}

	devinfo->ctl_completed = false;
	err = ifxf_usb_send_ctl(devinfo, buf, len);
	if (err) {
		ifxf_err("fail %d bytes: %d\n", err, len);
		clear_bit(0, &devinfo->ctl_op);
		goto fail;
	}
	timeout = ifxf_usb_ioctl_resp_wait(devinfo);
	if (!timeout) {
		ifxf_err("Txctl wait timed out\n");
		usb_kill_urb(devinfo->ctl_urb);
		err = -EIO;
		goto fail;
	}
	clear_bit(0, &devinfo->ctl_op);

fail:
	usb_autopm_put_interface(intf);
out:
	return err;
}

static int ifxf_usb_rx_ctlpkt(struct device *dev, u8 *buf, u32 len)
{
	int err = 0;
	int timeout = 0;
	struct ifxf_usbdev_info *devinfo = ifxf_usb_get_businfo(dev);
	struct usb_interface *intf = to_usb_interface(dev);

	ifxf_dbg(USB, "Enter\n");

	err = usb_autopm_get_interface(intf);
	if (err)
		goto out;

	if (devinfo->bus_pub.state != IFXFMAC_USB_STATE_UP) {
		err = -EIO;
		goto fail;
	}

	if (test_and_set_bit(0, &devinfo->ctl_op)) {
		err = -EIO;
		goto fail;
	}

	devinfo->ctl_completed = false;
	err = ifxf_usb_recv_ctl(devinfo, buf, len);
	if (err) {
		ifxf_err("fail %d bytes: %d\n", err, len);
		clear_bit(0, &devinfo->ctl_op);
		goto fail;
	}
	timeout = ifxf_usb_ioctl_resp_wait(devinfo);
	err = devinfo->ctl_urb_status;
	if (!timeout) {
		ifxf_err("rxctl wait timed out\n");
		usb_kill_urb(devinfo->ctl_urb);
		err = -EIO;
		goto fail;
	}
	clear_bit(0, &devinfo->ctl_op);
fail:
	usb_autopm_put_interface(intf);
	if (!err)
		return devinfo->ctl_urb_actual_length;
out:
	return err;
}

static struct ifxf_usbreq *ifxf_usb_deq(struct ifxf_usbdev_info *devinfo,
					  struct list_head *q, int *counter)
{
	unsigned long flags;
	struct ifxf_usbreq  *req;
	spin_lock_irqsave(&devinfo->qlock, flags);
	if (list_empty(q)) {
		spin_unlock_irqrestore(&devinfo->qlock, flags);
		return NULL;
	}
	req = list_entry(q->next, struct ifxf_usbreq, list);
	list_del_init(q->next);
	if (counter)
		(*counter)--;
	spin_unlock_irqrestore(&devinfo->qlock, flags);
	return req;

}

static void ifxf_usb_enq(struct ifxf_usbdev_info *devinfo,
			  struct list_head *q, struct ifxf_usbreq *req,
			  int *counter)
{
	unsigned long flags;
	spin_lock_irqsave(&devinfo->qlock, flags);
	list_add_tail(&req->list, q);
	if (counter)
		(*counter)++;
	spin_unlock_irqrestore(&devinfo->qlock, flags);
}

static struct ifxf_usbreq *
ifxf_usbdev_qinit(struct list_head *q, int qsize)
{
	int i;
	struct ifxf_usbreq *req, *reqs;

	reqs = kcalloc(qsize, sizeof(struct ifxf_usbreq), GFP_ATOMIC);
	if (reqs == NULL)
		return NULL;

	req = reqs;

	for (i = 0; i < qsize; i++) {
		req->urb = usb_alloc_urb(0, GFP_ATOMIC);
		if (!req->urb)
			goto fail;

		INIT_LIST_HEAD(&req->list);
		list_add_tail(&req->list, q);
		req++;
	}
	return reqs;
fail:
	ifxf_err("fail!\n");
	while (!list_empty(q)) {
		req = list_entry(q->next, struct ifxf_usbreq, list);
		if (req)
			usb_free_urb(req->urb);
		list_del(q->next);
	}
	kfree(reqs);
	return NULL;

}

static void ifxf_usb_free_q(struct list_head *q)
{
	struct ifxf_usbreq *req, *next;

	list_for_each_entry_safe(req, next, q, list) {
		if (!req->urb) {
			ifxf_err("bad req\n");
			break;
		}
		usb_free_urb(req->urb);
		list_del_init(&req->list);
	}
}

static void ifxf_usb_del_fromq(struct ifxf_usbdev_info *devinfo,
				struct ifxf_usbreq *req)
{
	unsigned long flags;

	spin_lock_irqsave(&devinfo->qlock, flags);
	list_del_init(&req->list);
	spin_unlock_irqrestore(&devinfo->qlock, flags);
}


static void ifxf_usb_tx_complete(struct urb *urb)
{
	struct ifxf_usbreq *req = (struct ifxf_usbreq *)urb->context;
	struct ifxf_usbdev_info *devinfo = req->devinfo;
	unsigned long flags;

	ifxf_dbg(USB, "Enter, urb->status=%d, skb=%p\n", urb->status,
		  req->skb);
	ifxf_usb_del_fromq(devinfo, req);

	ifxf_proto_bcdc_txcomplete(devinfo->dev, req->skb, urb->status == 0);
	req->skb = NULL;
	ifxf_usb_enq(devinfo, &devinfo->tx_freeq, req, &devinfo->tx_freecount);
	spin_lock_irqsave(&devinfo->tx_flowblock_lock, flags);
	if (devinfo->tx_freecount > devinfo->tx_high_watermark &&
		devinfo->tx_flowblock) {
		ifxf_proto_bcdc_txflowblock(devinfo->dev, false);
		devinfo->tx_flowblock = false;
	}
	spin_unlock_irqrestore(&devinfo->tx_flowblock_lock, flags);
}

static void ifxf_usb_rx_complete(struct urb *urb)
{
	struct ifxf_usbreq  *req = (struct ifxf_usbreq *)urb->context;
	struct ifxf_usbdev_info *devinfo = req->devinfo;
	struct sk_buff *skb;

	ifxf_dbg(USB, "Enter, urb->status=%d\n", urb->status);
	ifxf_usb_del_fromq(devinfo, req);
	skb = req->skb;
	req->skb = NULL;

	/* zero length packets indicate usb "failure". Do not refill */
	if (urb->status != 0 || !urb->actual_length) {
		ifxu_pkt_buf_free_skb(skb);
		ifxf_usb_enq(devinfo, &devinfo->rx_freeq, req, NULL);
		return;
	}

	if (devinfo->bus_pub.state == IFXFMAC_USB_STATE_UP ||
	    devinfo->bus_pub.state == IFXFMAC_USB_STATE_SLEEP) {
		skb_put(skb, urb->actual_length);
		ifxf_rx_frame(devinfo->dev, skb, true, true);
		ifxf_usb_rx_refill(devinfo, req);
		usb_mark_last_busy(urb->dev);
	} else {
		ifxu_pkt_buf_free_skb(skb);
		ifxf_usb_enq(devinfo, &devinfo->rx_freeq, req, NULL);
	}
	return;

}

static void ifxf_usb_rx_refill(struct ifxf_usbdev_info *devinfo,
				struct ifxf_usbreq  *req)
{
	struct sk_buff *skb;
	int ret;

	if (!req || !devinfo)
		return;

	skb = dev_alloc_skb(devinfo->bus_pub.bus_mtu);
	if (!skb) {
		ifxf_usb_enq(devinfo, &devinfo->rx_freeq, req, NULL);
		return;
	}
	req->skb = skb;

	usb_fill_bulk_urb(req->urb, devinfo->usbdev, devinfo->rx_pipe,
			  skb->data, skb_tailroom(skb), ifxf_usb_rx_complete,
			  req);
	req->devinfo = devinfo;
	ifxf_usb_enq(devinfo, &devinfo->rx_postq, req, NULL);

	ret = usb_submit_urb(req->urb, GFP_ATOMIC);
	if (ret) {
		ifxf_usb_del_fromq(devinfo, req);
		ifxu_pkt_buf_free_skb(req->skb);
		req->skb = NULL;
		ifxf_usb_enq(devinfo, &devinfo->rx_freeq, req, NULL);
	}
	return;
}

static void ifxf_usb_rx_fill_all(struct ifxf_usbdev_info *devinfo)
{
	struct ifxf_usbreq *req;

	if (devinfo->bus_pub.state != IFXFMAC_USB_STATE_UP) {
		ifxf_err("bus is not up=%d\n", devinfo->bus_pub.state);
		return;
	}
	while ((req = ifxf_usb_deq(devinfo, &devinfo->rx_freeq, NULL)) != NULL)
		ifxf_usb_rx_refill(devinfo, req);
}

static void
ifxf_usb_state_change(struct ifxf_usbdev_info *devinfo, int state)
{
	struct ifxf_bus *ifxf_bus = devinfo->bus_pub.bus;

	ifxf_dbg(USB, "Enter, current state=%d, new state=%d\n",
		  devinfo->bus_pub.state, state);

	if (devinfo->bus_pub.state == state)
		return;

	devinfo->bus_pub.state = state;

	/* update state of upper layer */
	if (state == IFXFMAC_USB_STATE_DOWN) {
		ifxf_dbg(USB, "DBUS is down\n");
		ifxf_bus_change_state(ifxf_bus, IFXF_BUS_DOWN);
	} else if (state == IFXFMAC_USB_STATE_UP) {
		ifxf_dbg(USB, "DBUS is up\n");
		ifxf_bus_change_state(ifxf_bus, IFXF_BUS_UP);
	} else {
		ifxf_dbg(USB, "DBUS current state=%d\n", state);
	}
}

static int ifxf_usb_tx(struct device *dev, struct sk_buff *skb)
{
	struct ifxf_usbdev_info *devinfo = ifxf_usb_get_businfo(dev);
	struct ifxf_usbreq  *req;
	int ret;
	unsigned long flags;
	struct usb_interface *intf = to_usb_interface(dev);

	ret = usb_autopm_get_interface(intf);
	if (ret)
		goto out;

	ifxf_dbg(USB, "Enter, skb=%p\n", skb);
	if (devinfo->bus_pub.state != IFXFMAC_USB_STATE_UP) {
		ret = -EIO;
		goto fail;
	}

	req = ifxf_usb_deq(devinfo, &devinfo->tx_freeq,
					&devinfo->tx_freecount);
	if (!req) {
		ifxf_err("no req to send\n");
		ret = -ENOMEM;
		goto fail;
	}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0))
	if (devinfo->bus_pub.bus->allow_skborphan)
		skb_orphan(skb);
#endif
	req->skb = skb;
	req->devinfo = devinfo;
	usb_fill_bulk_urb(req->urb, devinfo->usbdev, devinfo->tx_pipe,
			  skb->data, skb->len, ifxf_usb_tx_complete, req);
	req->urb->transfer_flags |= URB_ZERO_PACKET;
	ifxf_usb_enq(devinfo, &devinfo->tx_postq, req, NULL);
	ret = usb_submit_urb(req->urb, GFP_ATOMIC);
	if (ret) {
		ifxf_err("ifxf_usb_tx usb_submit_urb FAILED\n");
		ifxf_usb_del_fromq(devinfo, req);
		req->skb = NULL;
		ifxf_usb_enq(devinfo, &devinfo->tx_freeq, req,
			      &devinfo->tx_freecount);
		goto fail;
	}

	spin_lock_irqsave(&devinfo->tx_flowblock_lock, flags);
	if (devinfo->tx_freecount < devinfo->tx_low_watermark &&
	    !devinfo->tx_flowblock) {
		ifxf_proto_bcdc_txflowblock(dev, true);
		devinfo->tx_flowblock = true;
	}
	spin_unlock_irqrestore(&devinfo->tx_flowblock_lock, flags);

fail:
	usb_autopm_put_interface(intf);
out:
	return ret;
}


static int ifxf_usb_up(struct device *dev)
{
	struct ifxf_usbdev_info *devinfo = ifxf_usb_get_businfo(dev);

	ifxf_dbg(USB, "Enter\n");
	if (devinfo->bus_pub.state == IFXFMAC_USB_STATE_UP)
		return 0;

	/* Success, indicate devinfo is fully up */
	ifxf_usb_state_change(devinfo, IFXFMAC_USB_STATE_UP);

	if (devinfo->ctl_urb) {
		devinfo->ctl_in_pipe = usb_rcvctrlpipe(devinfo->usbdev, 0);
		devinfo->ctl_out_pipe = usb_sndctrlpipe(devinfo->usbdev, 0);

		/* CTL Write */
		devinfo->ctl_write.bRequestType =
			USB_DIR_OUT | USB_TYPE_CLASS | USB_RECIP_INTERFACE;
		devinfo->ctl_write.bRequest = 0;
		devinfo->ctl_write.wValue = cpu_to_le16(0);
		devinfo->ctl_write.wIndex = cpu_to_le16(devinfo->ifnum);

		/* CTL Read */
		devinfo->ctl_read.bRequestType =
			USB_DIR_IN | USB_TYPE_CLASS | USB_RECIP_INTERFACE;
		devinfo->ctl_read.bRequest = 1;
		devinfo->ctl_read.wValue = cpu_to_le16(0);
		devinfo->ctl_read.wIndex = cpu_to_le16(devinfo->ifnum);
	}
	ifxf_usb_rx_fill_all(devinfo);
	return 0;
}

static void ifxf_cancel_all_urbs(struct ifxf_usbdev_info *devinfo)
{
	int i;

	if (devinfo->ctl_urb)
		usb_kill_urb(devinfo->ctl_urb);
	if (devinfo->bulk_urb)
		usb_kill_urb(devinfo->bulk_urb);
	if (devinfo->tx_reqs)
		for (i = 0; i < devinfo->bus_pub.ntxq; i++)
			usb_kill_urb(devinfo->tx_reqs[i].urb);
	if (devinfo->rx_reqs)
		for (i = 0; i < devinfo->bus_pub.nrxq; i++)
			usb_kill_urb(devinfo->rx_reqs[i].urb);
}

static void ifxf_usb_down(struct device *dev)
{
	struct ifxf_usbdev_info *devinfo = ifxf_usb_get_businfo(dev);

	ifxf_dbg(USB, "Enter\n");
	if (devinfo == NULL)
		return;

	if (devinfo->bus_pub.state == IFXFMAC_USB_STATE_DOWN)
		return;

	ifxf_usb_state_change(devinfo, IFXFMAC_USB_STATE_DOWN);

	ifxf_cancel_all_urbs(devinfo);
}

static void
ifxf_usb_sync_complete(struct urb *urb)
{
	struct ifxf_usbdev_info *devinfo =
			(struct ifxf_usbdev_info *)urb->context;

	devinfo->ctl_completed = true;
	ifxf_usb_ioctl_resp_wake(devinfo);
}

static int ifxf_usb_dl_cmd(struct ifxf_usbdev_info *devinfo, u8 cmd,
			    void *buffer, int buflen)
{
	int ret;
	char *tmpbuf;
	u16 size;

	if ((!devinfo) || (devinfo->ctl_urb == NULL))
		return -EINVAL;

	tmpbuf = kmalloc(buflen, GFP_ATOMIC);
	if (!tmpbuf)
		return -ENOMEM;

	size = buflen;
	devinfo->ctl_urb->transfer_buffer_length = size;

	devinfo->ctl_read.wLength = cpu_to_le16p(&size);
	devinfo->ctl_read.bRequestType = USB_DIR_IN | USB_TYPE_VENDOR |
		USB_RECIP_INTERFACE;
	devinfo->ctl_read.bRequest = cmd;

	usb_fill_control_urb(devinfo->ctl_urb,
		devinfo->usbdev,
		usb_rcvctrlpipe(devinfo->usbdev, 0),
		(unsigned char *) &devinfo->ctl_read,
		(void *) tmpbuf, size,
		(usb_complete_t)ifxf_usb_sync_complete, devinfo);

	devinfo->ctl_completed = false;
	ret = usb_submit_urb(devinfo->ctl_urb, GFP_ATOMIC);
	if (ret < 0) {
		ifxf_err("usb_submit_urb failed %d\n", ret);
		goto finalize;
	}

	if (!ifxf_usb_ioctl_resp_wait(devinfo)) {
		usb_kill_urb(devinfo->ctl_urb);
		ret = -ETIMEDOUT;
	} else {
		memcpy(buffer, tmpbuf, buflen);
	}

finalize:
	kfree(tmpbuf);
	return ret;
}

static bool
ifxf_usb_dlneeded(struct ifxf_usbdev_info *devinfo)
{
	struct bootrom_id_le id;
	u32 chipid, chiprev;

	ifxf_dbg(USB, "Enter\n");

	if (devinfo == NULL)
		return false;

	/* Check if firmware downloaded already by querying runtime ID */
	id.chip = cpu_to_le32(0xDEAD);
	ifxf_usb_dl_cmd(devinfo, DL_GETVER, &id, sizeof(id));

	chipid = le32_to_cpu(id.chip);
	chiprev = le32_to_cpu(id.chiprev);

	if ((chipid & 0x4300) == 0x4300)
		ifxf_dbg(USB, "chip %x rev 0x%x\n", chipid, chiprev);
	else
		ifxf_dbg(USB, "chip %d rev 0x%x\n", chipid, chiprev);
	if (chipid == IFXF_POSTBOOT_ID) {
		ifxf_dbg(USB, "firmware already downloaded\n");
		ifxf_usb_dl_cmd(devinfo, DL_RESETCFG, &id, sizeof(id));
		return false;
	} else {
		devinfo->bus_pub.devid = chipid;
		devinfo->bus_pub.chiprev = chiprev;
	}
	return true;
}

static int
ifxf_usb_resetcfg(struct ifxf_usbdev_info *devinfo)
{
	struct bootrom_id_le id;
	u32 loop_cnt;
	int err;

	ifxf_dbg(USB, "Enter\n");

	loop_cnt = 0;
	do {
		mdelay(IFXF_USB_RESET_GETVER_SPINWAIT);
		loop_cnt++;
		id.chip = cpu_to_le32(0xDEAD);       /* Get the ID */
		err = ifxf_usb_dl_cmd(devinfo, DL_GETVER, &id, sizeof(id));
		if ((err) && (err != -ETIMEDOUT))
			return err;
		if (id.chip == cpu_to_le32(IFXF_POSTBOOT_ID))
			break;
	} while (loop_cnt < IFXF_USB_RESET_GETVER_LOOP_CNT);

	if (id.chip == cpu_to_le32(IFXF_POSTBOOT_ID)) {
		ifxf_dbg(USB, "postboot chip 0x%x/rev 0x%x\n",
			  le32_to_cpu(id.chip), le32_to_cpu(id.chiprev));

		ifxf_usb_dl_cmd(devinfo, DL_RESETCFG, &id, sizeof(id));
		return 0;
	} else {
		ifxf_err("Cannot talk to Dongle. Firmware is not UP, %d ms\n",
			  IFXF_USB_RESET_GETVER_SPINWAIT * loop_cnt);
		return -EINVAL;
	}
}


static int
ifxf_usb_dl_send_bulk(struct ifxf_usbdev_info *devinfo, void *buffer, int len)
{
	int ret;

	if ((devinfo == NULL) || (devinfo->bulk_urb == NULL))
		return -EINVAL;

	/* Prepare the URB */
	usb_fill_bulk_urb(devinfo->bulk_urb, devinfo->usbdev,
			  devinfo->tx_pipe, buffer, len,
			  (usb_complete_t)ifxf_usb_sync_complete, devinfo);

	devinfo->bulk_urb->transfer_flags |= URB_ZERO_PACKET;

	devinfo->ctl_completed = false;
	ret = usb_submit_urb(devinfo->bulk_urb, GFP_ATOMIC);
	if (ret) {
		ifxf_err("usb_submit_urb failed %d\n", ret);
		return ret;
	}
	ret = ifxf_usb_ioctl_resp_wait(devinfo);
	return (ret == 0);
}

static int
ifxf_usb_dl_writeimage(struct ifxf_usbdev_info *devinfo, u8 *fw, int fwlen)
{
	unsigned int sendlen, sent, dllen;
	char *bulkchunk = NULL, *dlpos;
	struct rdl_state_le state;
	u32 rdlstate, rdlbytes;
	int err = 0;

	ifxf_dbg(USB, "Enter, fw %p, len %d\n", fw, fwlen);

	bulkchunk = kmalloc(TRX_RDL_CHUNK, GFP_ATOMIC);
	if (bulkchunk == NULL) {
		err = -ENOMEM;
		goto fail;
	}

	/* 1) Prepare USB boot loader for runtime image */
	ifxf_usb_dl_cmd(devinfo, DL_START, &state, sizeof(state));

	rdlstate = le32_to_cpu(state.state);
	rdlbytes = le32_to_cpu(state.bytes);

	/* 2) Check we are in the Waiting state */
	if (rdlstate != DL_WAITING) {
		ifxf_err("Failed to DL_START\n");
		err = -EINVAL;
		goto fail;
	}
	sent = 0;
	dlpos = fw;
	dllen = fwlen;

	/* Get chip id and rev */
	while (rdlbytes != dllen) {
		/* Wait until the usb device reports it received all
		 * the bytes we sent */
		if ((rdlbytes == sent) && (rdlbytes != dllen)) {
			if ((dllen-sent) < TRX_RDL_CHUNK)
				sendlen = dllen-sent;
			else
				sendlen = TRX_RDL_CHUNK;

			/* simply avoid having to send a ZLP by ensuring we
			 * never have an even
			 * multiple of 64
			 */
			if (!(sendlen % 64))
				sendlen -= 4;

			/* send data */
			memcpy(bulkchunk, dlpos, sendlen);
			if (ifxf_usb_dl_send_bulk(devinfo, bulkchunk,
						   sendlen)) {
				ifxf_err("send_bulk failed\n");
				err = -EINVAL;
				goto fail;
			}

			dlpos += sendlen;
			sent += sendlen;
		}
		err = ifxf_usb_dl_cmd(devinfo, DL_GETSTATE, &state,
				       sizeof(state));
		if (err) {
			ifxf_err("DL_GETSTATE Failed\n");
			goto fail;
		}

		rdlstate = le32_to_cpu(state.state);
		rdlbytes = le32_to_cpu(state.bytes);

		/* restart if an error is reported */
		if (rdlstate == DL_BAD_HDR || rdlstate == DL_BAD_CRC) {
			ifxf_err("Bad Hdr or Bad CRC state %d\n",
				  rdlstate);
			err = -EINVAL;
			goto fail;
		}
	}

fail:
	kfree(bulkchunk);
	ifxf_dbg(USB, "Exit, err=%d\n", err);
	return err;
}

static int ifxf_usb_dlstart(struct ifxf_usbdev_info *devinfo, u8 *fw, int len)
{
	int err;

	ifxf_dbg(USB, "Enter\n");

	if (devinfo == NULL)
		return -EINVAL;

	if (devinfo->bus_pub.devid == 0xDEAD)
		return -EINVAL;

	err = ifxf_usb_dl_writeimage(devinfo, fw, len);
	if (err == 0)
		devinfo->bus_pub.state = IFXFMAC_USB_STATE_DL_DONE;
	else
		devinfo->bus_pub.state = IFXFMAC_USB_STATE_DL_FAIL;
	ifxf_dbg(USB, "Exit, err=%d\n", err);

	return err;
}

static int ifxf_usb_dlrun(struct ifxf_usbdev_info *devinfo)
{
	struct rdl_state_le state;

	ifxf_dbg(USB, "Enter\n");
	if (!devinfo)
		return -EINVAL;

	if (devinfo->bus_pub.devid == 0xDEAD)
		return -EINVAL;

	/* Check we are runnable */
	state.state = 0;
	ifxf_usb_dl_cmd(devinfo, DL_GETSTATE, &state, sizeof(state));

	/* Start the image */
	if (state.state == cpu_to_le32(DL_RUNNABLE)) {
		if (ifxf_usb_dl_cmd(devinfo, DL_GO, &state, sizeof(state)))
			return -ENODEV;
		if (ifxf_usb_resetcfg(devinfo))
			return -ENODEV;
		/* The Dongle may go for re-enumeration. */
	} else {
		ifxf_err("Dongle not runnable\n");
		return -EINVAL;
	}
	ifxf_dbg(USB, "Exit\n");
	return 0;
}

static int
ifxf_usb_fw_download(struct ifxf_usbdev_info *devinfo)
{
	int err;
	struct usb_interface *intf;

	ifxf_dbg(USB, "Enter\n");
	if (!devinfo) {
		err = -ENODEV;
		goto out;
	}

	if (!devinfo->image) {
		ifxf_err("No firmware!\n");
		err = -ENOENT;
		goto out;
	}

	intf = to_usb_interface(devinfo->dev);
	err = usb_autopm_get_interface(intf);
	if (err)
		goto out;

	err = ifxf_usb_dlstart(devinfo,
		(u8 *)devinfo->image, devinfo->image_len);
	if (err == 0)
		err = ifxf_usb_dlrun(devinfo);

	usb_autopm_put_interface(intf);
out:
	return err;
}


static void ifxf_usb_detach(struct ifxf_usbdev_info *devinfo)
{
	ifxf_dbg(USB, "Enter, devinfo %p\n", devinfo);

	/* free the URBS */
	ifxf_usb_free_q(&devinfo->rx_freeq);
	ifxf_usb_free_q(&devinfo->tx_freeq);

	usb_free_urb(devinfo->ctl_urb);
	usb_free_urb(devinfo->bulk_urb);

	kfree(devinfo->tx_reqs);
	kfree(devinfo->rx_reqs);

	if (devinfo->settings)
		ifxf_release_module_param(devinfo->settings);
}


static int check_file(const u8 *headers)
{
	struct trx_header_le *trx;
	int actual_len = -1;

	ifxf_dbg(USB, "Enter\n");
	/* Extract trx header */
	trx = (struct trx_header_le *) headers;
	if (trx->magic != cpu_to_le32(TRX_MAGIC))
		return -1;

	headers += sizeof(struct trx_header_le);

	if (le32_to_cpu(trx->flag_version) & TRX_UNCOMP_IMAGE) {
		actual_len = le32_to_cpu(trx->offsets[TRX_OFFSETS_DLFWLEN_IDX]);
		return actual_len + sizeof(struct trx_header_le);
	}
	return -1;
}


static
struct ifxf_usbdev *ifxf_usb_attach(struct ifxf_usbdev_info *devinfo,
				      int nrxq, int ntxq)
{
	ifxf_dbg(USB, "Enter\n");

	devinfo->bus_pub.nrxq = nrxq;
	devinfo->rx_low_watermark = nrxq / 2;
	devinfo->bus_pub.devinfo = devinfo;
	devinfo->bus_pub.ntxq = ntxq;
	devinfo->bus_pub.state = IFXFMAC_USB_STATE_DOWN;

	/* flow control when too many tx urbs posted */
	devinfo->tx_low_watermark = ntxq / 4;
	devinfo->tx_high_watermark = devinfo->tx_low_watermark * 3;
	devinfo->bus_pub.bus_mtu = IFXF_USB_MAX_PKT_SIZE;

	/* Initialize other structure content */
	init_waitqueue_head(&devinfo->ioctl_resp_wait);

	/* Initialize the spinlocks */
	spin_lock_init(&devinfo->qlock);
	spin_lock_init(&devinfo->tx_flowblock_lock);

	INIT_LIST_HEAD(&devinfo->rx_freeq);
	INIT_LIST_HEAD(&devinfo->rx_postq);

	INIT_LIST_HEAD(&devinfo->tx_freeq);
	INIT_LIST_HEAD(&devinfo->tx_postq);

	devinfo->tx_flowblock = false;

	devinfo->rx_reqs = ifxf_usbdev_qinit(&devinfo->rx_freeq, nrxq);
	if (!devinfo->rx_reqs)
		goto error;

	devinfo->tx_reqs = ifxf_usbdev_qinit(&devinfo->tx_freeq, ntxq);
	if (!devinfo->tx_reqs)
		goto error;
	devinfo->tx_freecount = ntxq;

	devinfo->ctl_urb = usb_alloc_urb(0, GFP_ATOMIC);
	if (!devinfo->ctl_urb)
		goto error;
	devinfo->bulk_urb = usb_alloc_urb(0, GFP_ATOMIC);
	if (!devinfo->bulk_urb)
		goto error;

	return &devinfo->bus_pub;

error:
	ifxf_err("failed!\n");
	ifxf_usb_detach(devinfo);
	return NULL;
}

static int ifxf_usb_get_blob(struct device *dev, const struct firmware **fw,
			      enum ifxf_blob_type type)
{
	/* No blobs for USB devices... */
	return -ENOENT;
}

static const struct ifxf_bus_ops ifxf_usb_bus_ops = {
	.preinit = ifxf_usb_up,
	.stop = ifxf_usb_down,
	.txdata = ifxf_usb_tx,
	.txctl = ifxf_usb_tx_ctlpkt,
	.rxctl = ifxf_usb_rx_ctlpkt,
	.get_blob = ifxf_usb_get_blob,
};

#define IFXF_USB_FW_CODE	0

static void ifxf_usb_probe_phase2(struct device *dev, int ret,
				   struct ifxf_fw_request *fwreq)
{
	struct ifxf_bus *bus = dev_get_drvdata(dev);
	struct ifxf_usbdev_info *devinfo = bus->bus_priv.usb->devinfo;
	const struct firmware *fw;

	if (ret)
		goto error;

	ifxf_dbg(USB, "Start fw downloading\n");

	fw = fwreq->items[IFXF_USB_FW_CODE].binary;
	kfree(fwreq);

	ret = check_file(fw->data);
	if (ret < 0) {
		ifxf_err("invalid firmware\n");
		release_firmware(fw);
		goto error;
	}

	devinfo->image = fw->data;
	devinfo->image_len = fw->size;

	ret = ifxf_usb_fw_download(devinfo);
	release_firmware(fw);
	if (ret)
		goto error;

	ret = ifxf_alloc(devinfo->dev, devinfo->settings);
	if (ret)
		goto error;

	if (IFXF_FWCON_ON()) {
		ret = ifxf_fwlog_attach(devinfo->dev);
		if (ret)
			goto error;
	}

	/* Attach to the common driver interface */
	ret = ifxf_attach(devinfo->dev, true);
	if (ret)
		goto error;

	complete(&devinfo->dev_init_done);
	return;
error:
	ifxf_dbg(TRACE, "failed: dev=%s, err=%d\n", dev_name(dev), ret);
	complete(&devinfo->dev_init_done);
	device_release_driver(dev);
}

static struct ifxf_fw_request *
ifxf_usb_prepare_fw_request(struct ifxf_usbdev_info *devinfo)
{
	struct ifxf_fw_request *fwreq;
	struct ifxf_fw_name fwnames[] = {
		{ ".bin", devinfo->fw_name },
	};

	fwreq = ifxf_fw_alloc_request(devinfo->bus_pub.devid,
				       devinfo->bus_pub.chiprev,
				       ifxf_usb_fwnames,
				       ARRAY_SIZE(ifxf_usb_fwnames),
				       fwnames, ARRAY_SIZE(fwnames));
	if (!fwreq)
		return NULL;

	fwreq->items[IFXF_USB_FW_CODE].type = IFXF_FW_TYPE_BINARY;

	return fwreq;
}

static int ifxf_usb_probe_cb(struct ifxf_usbdev_info *devinfo)
{
	struct ifxf_bus *bus = NULL;
	struct ifxf_usbdev *bus_pub = NULL;
	struct device *dev = devinfo->dev;
	struct ifxf_fw_request *fwreq;
	int ret;

	ifxf_dbg(USB, "Enter\n");
	bus_pub = ifxf_usb_attach(devinfo, IFXF_USB_NRXQ, IFXF_USB_NTXQ);
	if (!bus_pub)
		return -ENODEV;

	bus = kzalloc(sizeof(struct ifxf_bus), GFP_ATOMIC);
	if (!bus) {
		ret = -ENOMEM;
		goto fail;
	}

	bus->dev = dev;
	bus_pub->bus = bus;
	bus->bus_priv.usb = bus_pub;
	dev_set_drvdata(dev, bus);
	bus->ops = &ifxf_usb_bus_ops;
	bus->proto_type = IFXF_PROTO_BCDC;
	bus->always_use_fws_queue = true;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0))
	bus->allow_skborphan = true;
#endif
#ifdef CONFIG_PM
	bus->wowl_supported = true;
#endif

	devinfo->settings = ifxf_get_module_param(bus->dev, IFXF_BUSTYPE_USB,
						   bus_pub->devid,
						   bus_pub->chiprev);
	if (!devinfo->settings) {
		ret = -ENOMEM;
		goto fail;
	}

	if (!ifxf_usb_dlneeded(devinfo)) {
		ret = ifxf_alloc(devinfo->dev, devinfo->settings);
		if (ret)
			goto fail;

		if (IFXF_FWCON_ON()) {
			ret = ifxf_fwlog_attach(devinfo->dev);
			if (ret)
				goto fail;
		}

		ret = ifxf_attach(devinfo->dev, true);
		if (ret)
			goto fail;

		/* we are done */
		complete(&devinfo->dev_init_done);
		return 0;
	}
	bus->chip = bus_pub->devid;
	bus->chiprev = bus_pub->chiprev;

	fwreq = ifxf_usb_prepare_fw_request(devinfo);
	if (!fwreq) {
		ret = -ENOMEM;
		goto fail;
	}

	/* request firmware here */
	ret = ifxf_fw_get_firmwares(dev, fwreq, ifxf_usb_probe_phase2);
	if (ret) {
		ifxf_err("firmware request failed: %d\n", ret);
		kfree(fwreq);
		goto fail;
	}

	return 0;

fail:
	/* Release resources in reverse order */
	ifxf_free(devinfo->dev);
	kfree(bus);
	ifxf_usb_detach(devinfo);
	return ret;
}

static void
ifxf_usb_disconnect_cb(struct ifxf_usbdev_info *devinfo)
{
	if (!devinfo)
		return;
	ifxf_dbg(USB, "Enter, bus_pub %p\n", devinfo);

	ifxf_detach(devinfo->dev);
	ifxf_free(devinfo->dev);
	kfree(devinfo->bus_pub.bus);
	ifxf_usb_detach(devinfo);
}

static int
ifxf_usb_probe(struct usb_interface *intf, const struct usb_device_id *id)
{
	struct usb_device *usb = interface_to_usbdev(intf);
	struct ifxf_usbdev_info *devinfo;
	struct usb_interface_descriptor	*desc;
	struct usb_endpoint_descriptor *endpoint;
	int ret = 0;
	u32 num_of_eps;
	u8 endpoint_num, ep;

	ifxf_dbg(USB, "Enter 0x%04x:0x%04x\n", id->idVendor, id->idProduct);

	devinfo = kzalloc(sizeof(*devinfo), GFP_ATOMIC);
	if (devinfo == NULL)
		return -ENOMEM;

	devinfo->usbdev = usb;
	devinfo->dev = &usb->dev;
	/* Init completion, to protect for disconnect while still loading.
	 * Necessary because of the asynchronous firmware load construction
	 */
	init_completion(&devinfo->dev_init_done);

	usb_set_intfdata(intf, devinfo);

	intf->needs_remote_wakeup = 1;

	/* Check that the device supports only one configuration */
	if (usb->descriptor.bNumConfigurations != 1) {
		ifxf_err("Number of configurations: %d not supported\n",
			  usb->descriptor.bNumConfigurations);
		ret = -ENODEV;
		goto fail;
	}

	if ((usb->descriptor.bDeviceClass != USB_CLASS_VENDOR_SPEC) &&
	    (usb->descriptor.bDeviceClass != USB_CLASS_MISC) &&
	    (usb->descriptor.bDeviceClass != USB_CLASS_WIRELESS_CONTROLLER)) {
		ifxf_err("Device class: 0x%x not supported\n",
			  usb->descriptor.bDeviceClass);
		ret = -ENODEV;
		goto fail;
	}

	desc = &intf->cur_altsetting->desc;
	if ((desc->bInterfaceClass != USB_CLASS_VENDOR_SPEC) ||
	    (desc->bInterfaceSubClass != 2) ||
	    (desc->bInterfaceProtocol != 0xff)) {
		ifxf_err("non WLAN interface %d: 0x%x:0x%x:0x%x\n",
			  desc->bInterfaceNumber, desc->bInterfaceClass,
			  desc->bInterfaceSubClass, desc->bInterfaceProtocol);
		ret = -ENODEV;
		goto fail;
	}

	num_of_eps = desc->bNumEndpoints;
	for (ep = 0; ep < num_of_eps; ep++) {
		endpoint = &intf->cur_altsetting->endpoint[ep].desc;
		endpoint_num = usb_endpoint_num(endpoint);
		if (!usb_endpoint_xfer_bulk(endpoint))
			continue;
		if (usb_endpoint_dir_in(endpoint)) {
			if (!devinfo->rx_pipe)
				devinfo->rx_pipe =
					usb_rcvbulkpipe(usb, endpoint_num);
		} else {
			if (!devinfo->tx_pipe)
				devinfo->tx_pipe =
					usb_sndbulkpipe(usb, endpoint_num);
		}
	}
	if (devinfo->rx_pipe == 0) {
		ifxf_err("No RX (in) Bulk EP found\n");
		ret = -ENODEV;
		goto fail;
	}
	if (devinfo->tx_pipe == 0) {
		ifxf_err("No TX (out) Bulk EP found\n");
		ret = -ENODEV;
		goto fail;
	}

	devinfo->ifnum = desc->bInterfaceNumber;

	if (usb->speed == USB_SPEED_SUPER_PLUS)
		ifxf_dbg(USB, "Infineon super speed plus USB WLAN interface detected\n");
	else if (usb->speed == USB_SPEED_SUPER)
		ifxf_dbg(USB, "Infineon super speed USB WLAN interface detected\n");
	else if (usb->speed == USB_SPEED_HIGH)
		ifxf_dbg(USB, "Infineon high speed USB WLAN interface detected\n");
	else
		ifxf_dbg(USB, "Infineon full speed USB WLAN interface detected\n");

	ret = ifxf_usb_probe_cb(devinfo);
	if (ret)
		goto fail;

	/* Success */
	return 0;

fail:
	complete(&devinfo->dev_init_done);
	kfree(devinfo);
	usb_set_intfdata(intf, NULL);
	return ret;
}

static void
ifxf_usb_disconnect(struct usb_interface *intf)
{
	struct ifxf_usbdev_info *devinfo;

	ifxf_dbg(USB, "Enter\n");
	devinfo = (struct ifxf_usbdev_info *)usb_get_intfdata(intf);

	if (devinfo) {
		wait_for_completion(&devinfo->dev_init_done);
		/* Make sure that devinfo still exists. Firmware probe routines
		 * may have released the device and cleared the intfdata.
		 */
		if (!usb_get_intfdata(intf))
			goto done;

		ifxf_usb_disconnect_cb(devinfo);
		kfree(devinfo);
	}
done:
	ifxf_dbg(USB, "Exit\n");
}

/*
 * only need to signal the bus being down and update the state.
 */
static int ifxf_usb_suspend(struct usb_interface *intf, pm_message_t state)
{
	struct usb_device *usb = interface_to_usbdev(intf);
	struct ifxf_usbdev_info *devinfo = ifxf_usb_get_businfo(&usb->dev);
	struct ifxf_bus *bus;
	struct ifxf_cfg80211_info *config;
	int retry = IFXF_PM_WAIT_MAXRETRY;

	ifxf_dbg(USB, "Enter\n");

	bus = devinfo->bus_pub.bus;
	config = bus->drvr->config;
	while (retry &&
	       config->pm_state == IFXF_CFG80211_PM_STATE_SUSPENDING) {
		usleep_range(10000, 20000);
		retry--;
	}
	if (!retry && config->pm_state == IFXF_CFG80211_PM_STATE_SUSPENDING)
		ifxf_err("timed out wait for cfg80211 suspended\n");

	devinfo->bus_pub.state = IFXFMAC_USB_STATE_SLEEP;
	ifxf_cancel_all_urbs(devinfo);
	device_set_wakeup_enable(devinfo->dev, true);
	return 0;
}

/*
 * (re-) start the bus.
 */
static int ifxf_usb_resume(struct usb_interface *intf)
{
	struct usb_device *usb = interface_to_usbdev(intf);
	struct ifxf_usbdev_info *devinfo = ifxf_usb_get_businfo(&usb->dev);

	ifxf_dbg(USB, "Enter\n");

	devinfo->bus_pub.state = IFXFMAC_USB_STATE_UP;
	ifxf_usb_rx_fill_all(devinfo);
	device_set_wakeup_enable(devinfo->dev, false);
	return 0;
}

static int ifxf_usb_reset_resume(struct usb_interface *intf)
{
	struct usb_device *usb = interface_to_usbdev(intf);
	struct ifxf_usbdev_info *devinfo = ifxf_usb_get_businfo(&usb->dev);
	struct ifxf_fw_request *fwreq;
	int ret;

	ifxf_dbg(USB, "Enter\n");

	fwreq = ifxf_usb_prepare_fw_request(devinfo);
	if (!fwreq)
		return -ENOMEM;

	ret = ifxf_fw_get_firmwares(&usb->dev, fwreq, ifxf_usb_probe_phase2);
	if (ret < 0)
		kfree(fwreq);

	return ret;
}

#define IFXF_USB_DEVICE_LEGACY(dev_id) \
	{ USB_DEVICE(BRCM_USB_VENDOR_ID_BROADCOM, dev_id) }

#define IFXF_USB_DEVICE(dev_id)	\
	{ USB_DEVICE(CY_USB_VENDOR_ID_CYPRESS, dev_id) }

static const struct usb_device_id ifxf_usb_devid_table[] = {
	IFXF_USB_DEVICE(CY_USB_4373_DEVICE_ID),
	/* special entry for device with firmware loaded and running */
	IFXF_USB_DEVICE_LEGACY(BRCM_USB_BCMFW_DEVICE_ID),
	IFXF_USB_DEVICE(CY_USB_4373_DEVICE_ID),
	{ /* end: all zeroes */ }
};

MODULE_DEVICE_TABLE(usb, ifxf_usb_devid_table);

static struct usb_driver ifxf_usbdrvr = {
	.name = KBUILD_MODNAME,
	.probe = ifxf_usb_probe,
	.disconnect = ifxf_usb_disconnect,
	.id_table = ifxf_usb_devid_table,
	.suspend = ifxf_usb_suspend,
	.resume = ifxf_usb_resume,
	.reset_resume = ifxf_usb_reset_resume,
	.supports_autosuspend = true,
	.disable_hub_initiated_lpm = 1,
};

static int ifxf_usb_reset_device(struct device *dev, void *notused)
{
	/* device past is the usb interface so we
	 * need to use parent here.
	 */
	ifxf_dev_reset(dev->parent);
	return 0;
}

void ifxf_usb_exit(void)
{
	struct device_driver *drv = &ifxf_usbdrvr.drvwrap.driver;
	int ret;

	ifxf_dbg(USB, "Enter\n");
	ret = driver_for_each_device(drv, NULL, NULL,
				     ifxf_usb_reset_device);
	if (ret)
		ifxf_err("failed to reset all usb devices %d\n", ret);

	usb_deregister(&ifxf_usbdrvr);
}

int ifxf_usb_register(void)
{
	ifxf_dbg(USB, "Enter\n");
	return usb_register(&ifxf_usbdrvr);
}
