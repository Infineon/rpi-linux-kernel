// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2010 Broadcom Corporation
 */
/* ****************** SDIO CARD Interface Functions **************************/

#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/pci.h>
#include <linux/pci_ids.h>
#include <linux/sched.h>
#include <linux/completion.h>
#include <linux/interrupt.h>
#include <linux/scatterlist.h>
#include <linux/mmc/sdio.h>
#include <linux/mmc/core.h>
#include <linux/mmc/sdio_func.h>
#include <linux/mmc/card.h>
#include <linux/mmc/host.h>
#include <linux/pm_runtime.h>
#include <linux/suspend.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/acpi.h>
#include <net/cfg80211.h>

#include <defs.h>
#include <ifx_hw_ids.h>
#include <ifxu_utils.h>
#include <ifxu_wifi.h>
#include <chipcommon.h>
#include <soc.h>
#include "chip.h"
#include "bus.h"
#include "debug.h"
#include "sdio.h"
#include "core.h"
#include "common.h"
#include "cfg80211.h"

#define SDIOH_API_ACCESS_RETRY_LIMIT	2

#define DMA_ALIGN_MASK	0x03

#define SDIO_FUNC1_BLOCKSIZE		64
#define SDIO_FUNC2_BLOCKSIZE		512
#define SDIO_4373_FUNC2_BLOCKSIZE	128
#define SDIO_435X_FUNC2_BLOCKSIZE	256
#define SDIO_89459_FUNC2_BLOCKSIZE	256
#define SDIO_CYW55572_FUNC2_BLOCKSIZE	256

/* Maximum milliseconds to wait for F2 to come up */
#define SDIO_WAIT_F2RDY	3000

#define IFXF_DEFAULT_RXGLOM_SIZE	32  /* max rx frames in glom chain */

struct ifxf_sdiod_freezer {
	atomic_t freezing;
	atomic_t thread_count;
	u32 frozen_count;
	wait_queue_head_t thread_freeze;
	struct completion resumed;
};

static irqreturn_t ifxf_sdiod_oob_irqhandler(int irq, void *dev_id)
{
	struct ifxf_bus *bus_if = dev_get_drvdata(dev_id);
	struct ifxf_sdio_dev *sdiodev = bus_if->bus_priv.sdio;

	ifxf_dbg(INTR, "OOB intr triggered\n");

	/* out-of-band interrupt is level-triggered which won't
	 * be cleared until dpc
	 */
	if (sdiodev->irq_en) {
		disable_irq_nosync(irq);
		sdiodev->irq_en = false;
	}

	ifxf_sdio_isr(sdiodev->bus, true);

	return IRQ_HANDLED;
}

static void ifxf_sdiod_ib_irqhandler(struct sdio_func *func)
{
	struct ifxf_bus *bus_if = dev_get_drvdata(&func->dev);
	struct ifxf_sdio_dev *sdiodev = bus_if->bus_priv.sdio;

	ifxf_dbg(INTR, "IB intr triggered\n");

	ifxf_sdio_isr(sdiodev->bus, false);
}

/* dummy handler for SDIO function 2 interrupt */
static void ifxf_sdiod_dummy_irqhandler(struct sdio_func *func)
{
}

int ifxf_sdiod_intr_register(struct ifxf_sdio_dev *sdiodev)
{
	struct ifxfmac_sdio_pd *pdata;
	int ret = 0;
	u8 data;
	u32 addr, gpiocontrol;

	pdata = &sdiodev->settings->bus.sdio;
	if (pdata->oob_irq_supported) {
		ifxf_dbg(SDIO, "Enter, register OOB IRQ %d\n",
			  pdata->oob_irq_nr);
		spin_lock_init(&sdiodev->irq_en_lock);
		sdiodev->irq_en = true;

		ret = request_irq(pdata->oob_irq_nr, ifxf_sdiod_oob_irqhandler,
				  pdata->oob_irq_flags, "ifxf_oob_intr",
				  &sdiodev->func1->dev);
		if (ret != 0) {
			ifxf_err("request_irq failed %d\n", ret);
			return ret;
		}
		sdiodev->oob_irq_requested = true;

		ret = enable_irq_wake(pdata->oob_irq_nr);
		if (ret != 0) {
			ifxf_err("enable_irq_wake failed %d\n", ret);
			return ret;
		}
		disable_irq_wake(pdata->oob_irq_nr);

		sdio_claim_host(sdiodev->func1);

		if (sdiodev->bus_if->chip == CY_CC_43362_CHIP_ID) {
			/* assign GPIO to SDIO core */
			addr = ifxf_chip_enum_base(sdiodev->func1->device);
			addr = CORE_CC_REG(addr, gpiocontrol);
			gpiocontrol = ifxf_sdiod_readl(sdiodev, addr, &ret);
			gpiocontrol |= 0x2;
			ifxf_sdiod_writel(sdiodev, addr, gpiocontrol, &ret);

			ifxf_sdiod_writeb(sdiodev, SBSDIO_GPIO_SELECT,
					   0xf, &ret);
			ifxf_sdiod_writeb(sdiodev, SBSDIO_GPIO_OUT, 0, &ret);
			ifxf_sdiod_writeb(sdiodev, SBSDIO_GPIO_EN, 0x2, &ret);
		}

		/* must configure SDIO_CCCR_IENx to enable irq */
		data = ifxf_sdiod_func0_rb(sdiodev, SDIO_CCCR_IENx, &ret);
		data |= SDIO_CCCR_IEN_FUNC1 | SDIO_CCCR_IEN_FUNC2 |
			SDIO_CCCR_IEN_FUNC0;
		ifxf_sdiod_func0_wb(sdiodev, SDIO_CCCR_IENx, data, &ret);

		/* redirect, configure and enable io for interrupt signal */
		data = SDIO_CCCR_IFX_SEPINT_MASK | SDIO_CCCR_IFX_SEPINT_OE;
		if (pdata->oob_irq_flags & IRQF_TRIGGER_HIGH)
			data |= SDIO_CCCR_IFX_SEPINT_ACT_HI;
		ifxf_sdiod_func0_wb(sdiodev, SDIO_CCCR_IFX_SEPINT,
				     data, &ret);
		sdio_release_host(sdiodev->func1);
	} else {
		ifxf_dbg(SDIO, "Entering\n");
		sdio_claim_host(sdiodev->func1);
		sdio_claim_irq(sdiodev->func1, ifxf_sdiod_ib_irqhandler);
		sdio_claim_irq(sdiodev->func2, ifxf_sdiod_dummy_irqhandler);
		sdio_release_host(sdiodev->func1);
		sdiodev->sd_irq_requested = true;
	}

	return 0;
}

void ifxf_sdiod_intr_unregister(struct ifxf_sdio_dev *sdiodev)
{

	ifxf_dbg(SDIO, "Entering oob=%d sd=%d\n",
		  sdiodev->oob_irq_requested,
		  sdiodev->sd_irq_requested);

	if (sdiodev->oob_irq_requested) {
		struct ifxfmac_sdio_pd *pdata;

		pdata = &sdiodev->settings->bus.sdio;
		sdio_claim_host(sdiodev->func1);
		ifxf_sdiod_func0_wb(sdiodev, SDIO_CCCR_IFX_SEPINT, 0, NULL);
		ifxf_sdiod_func0_wb(sdiodev, SDIO_CCCR_IENx, 0, NULL);
		sdio_release_host(sdiodev->func1);

		sdiodev->oob_irq_requested = false;
		free_irq(pdata->oob_irq_nr, &sdiodev->func1->dev);
		sdiodev->irq_en = false;
		sdiodev->oob_irq_requested = false;
	}

	if (sdiodev->sd_irq_requested) {
		sdio_claim_host(sdiodev->func1);
		sdio_release_irq(sdiodev->func2);
		sdio_release_irq(sdiodev->func1);
		sdio_release_host(sdiodev->func1);
		sdiodev->sd_irq_requested = false;
	}
}

void ifxf_sdiod_change_state(struct ifxf_sdio_dev *sdiodev,
			      enum ifxf_sdiod_state state)
{
	if (sdiodev->state == IFXF_SDIOD_NOMEDIUM ||
	    state == sdiodev->state)
		return;

	ifxf_dbg(TRACE, "%d -> %d\n", sdiodev->state, state);
	switch (sdiodev->state) {
	case IFXF_SDIOD_DATA:
		/* any other state means bus interface is down */
		ifxf_bus_change_state(sdiodev->bus_if, IFXF_BUS_DOWN);
		break;
	case IFXF_SDIOD_DOWN:
		/* transition from DOWN to DATA means bus interface is up */
		if (state == IFXF_SDIOD_DATA)
			ifxf_bus_change_state(sdiodev->bus_if, IFXF_BUS_UP);
		break;
	default:
		break;
	}
	sdiodev->state = state;
}

static int ifxf_sdiod_set_backplane_window(struct ifxf_sdio_dev *sdiodev,
					    u32 addr)
{
	u32 v, bar0 = addr & SBSDIO_SBWINDOW_MASK;
	int err = 0, i;

	if (bar0 == sdiodev->sbwad)
		return 0;

	v = bar0 >> 8;

	for (i = 0 ; i < 3 && !err ; i++, v >>= 8)
		ifxf_sdiod_writeb(sdiodev, SBSDIO_FUNC1_SBADDRLOW + i,
				   v & 0xff, &err);

	if (!err)
		sdiodev->sbwad = bar0;

	return err;
}

u32 ifxf_sdiod_readl(struct ifxf_sdio_dev *sdiodev, u32 addr, int *ret)
{
	u32 data = 0;
	int retval;

	retval = ifxf_sdiod_set_backplane_window(sdiodev, addr);
	if (retval)
		goto out;

	addr &= SBSDIO_SB_OFT_ADDR_MASK;
	addr |= SBSDIO_SB_ACCESS_2_4B_FLAG;

	data = sdio_readl(sdiodev->func1, addr, &retval);

out:
	if (ret)
		*ret = retval;

	return data;
}

void ifxf_sdiod_writel(struct ifxf_sdio_dev *sdiodev, u32 addr,
			u32 data, int *ret)
{
	int retval;

	retval = ifxf_sdiod_set_backplane_window(sdiodev, addr);
	if (retval)
		goto out;

	addr &= SBSDIO_SB_OFT_ADDR_MASK;
	addr |= SBSDIO_SB_ACCESS_2_4B_FLAG;

	sdio_writel(sdiodev->func1, data, addr, &retval);

out:
	if (ret)
		*ret = retval;
}

static int ifxf_sdiod_skbuff_read(struct ifxf_sdio_dev *sdiodev,
				   struct sdio_func *func, u32 addr,
				   struct sk_buff *skb)
{
	unsigned int req_sz;
	int err;

	/* Single skb use the standard mmc interface */
	req_sz = skb->len + 3;
	req_sz &= (uint)~3;

	switch (func->num) {
	case SDIO_FUNC_1:
		err = sdio_memcpy_fromio(func, ((u8 *)(skb->data)), addr,
					 req_sz);
		break;
	case SDIO_FUNC_2:
		err = sdio_readsb(func, ((u8 *)(skb->data)), addr, req_sz);
		break;
	default:
		/* bail out as things are really fishy here */
		WARN(1, "invalid sdio function number: %d\n", func->num);
		err = -ENOMEDIUM;
	}

	if (err == -ENOMEDIUM)
		ifxf_sdiod_change_state(sdiodev, IFXF_SDIOD_NOMEDIUM);

	return err;
}

static int ifxf_sdiod_skbuff_write(struct ifxf_sdio_dev *sdiodev,
				    struct sdio_func *func, u32 addr,
				    struct sk_buff *skb)
{
	unsigned int req_sz;
	int err;

	/* Single skb use the standard mmc interface */
	req_sz = skb->len + 3;
	req_sz &= (uint)~3;

	err = sdio_memcpy_toio(func, addr, ((u8 *)(skb->data)), req_sz);

	if (err == -ENOMEDIUM)
		ifxf_sdiod_change_state(sdiodev, IFXF_SDIOD_NOMEDIUM);

	return err;
}

static int mmc_submit_one(struct mmc_data *md, struct mmc_request *mr,
			  struct mmc_command *mc, int sg_cnt, int req_sz,
			  int func_blk_sz, u32 *addr,
			  struct ifxf_sdio_dev *sdiodev,
			  struct sdio_func *func, int write)
{
	int ret;

	md->sg_len = sg_cnt;
	md->blocks = req_sz / func_blk_sz;
	mc->arg |= (*addr & 0x1FFFF) << 9;	/* address */
	mc->arg |= md->blocks & 0x1FF;	/* block count */
	/* incrementing addr for function 1 */
	if (func->num == SDIO_FUNC_1)
		*addr += req_sz;

	mmc_set_data_timeout(md, func->card);
	mmc_wait_for_req(func->card->host, mr);

	ret = mc->error ? mc->error : md->error;
	if (ret == -ENOMEDIUM) {
		ifxf_sdiod_change_state(sdiodev, IFXF_SDIOD_NOMEDIUM);
	} else if (ret != 0) {
		ifxf_err("CMD53 sg block %s failed %d\n",
			  write ? "write" : "read", ret);
		ret = -EIO;
	}

	return ret;
}

/**
 * ifxf_sdiod_sglist_rw - SDIO interface function for block data access
 * @sdiodev: ifxfmac sdio device
 * @func: SDIO function
 * @write: direction flag
 * @addr: dongle memory address as source/destination
 * @pktlist: skb buffer head pointer
 *
 * This function takes the respbonsibility as the interface function to MMC
 * stack for block data access. It assumes that the skb passed down by the
 * caller has already been padded and aligned.
 */
static int ifxf_sdiod_sglist_rw(struct ifxf_sdio_dev *sdiodev,
				 struct sdio_func *func,
				 bool write, u32 addr,
				 struct sk_buff_head *pktlist)
{
	unsigned int req_sz, func_blk_sz, sg_cnt, sg_data_sz, pkt_offset;
	unsigned int max_req_sz, src_offset, dst_offset;
	unsigned char *pkt_data, *orig_data, *dst_data;
	struct sk_buff_head local_list, *target_list;
	struct sk_buff *pkt_next = NULL, *src;
	unsigned short max_seg_cnt;
	struct mmc_request mmc_req;
	struct mmc_command mmc_cmd;
	struct mmc_data mmc_dat;
	struct scatterlist *sgl;
	int ret = 0;

	if (!pktlist->qlen)
		return -EINVAL;

	target_list = pktlist;
	/* for host with broken sg support, prepare a page aligned list */
	__skb_queue_head_init(&local_list);
	if (!write && sdiodev->settings->bus.sdio.broken_sg_support) {
		req_sz = 0;
		skb_queue_walk(pktlist, pkt_next)
			req_sz += pkt_next->len;
		req_sz = ALIGN(req_sz, func->cur_blksize);
		while (req_sz > PAGE_SIZE) {
			pkt_next = ifxu_pkt_buf_get_skb(PAGE_SIZE);
			if (pkt_next == NULL) {
				ret = -ENOMEM;
				goto exit;
			}
			__skb_queue_tail(&local_list, pkt_next);
			req_sz -= PAGE_SIZE;
		}
		pkt_next = ifxu_pkt_buf_get_skb(req_sz);
		if (pkt_next == NULL) {
			ret = -ENOMEM;
			goto exit;
		}
		__skb_queue_tail(&local_list, pkt_next);
		target_list = &local_list;
	}

	func_blk_sz = func->cur_blksize;
	max_req_sz = sdiodev->max_request_size;
	max_seg_cnt = min_t(unsigned short, sdiodev->max_segment_count,
			    target_list->qlen);

	memset(&mmc_req, 0, sizeof(struct mmc_request));
	memset(&mmc_cmd, 0, sizeof(struct mmc_command));
	memset(&mmc_dat, 0, sizeof(struct mmc_data));

	mmc_dat.sg = sdiodev->sgtable.sgl;
	mmc_dat.blksz = func_blk_sz;
	mmc_dat.flags = write ? MMC_DATA_WRITE : MMC_DATA_READ;
	mmc_cmd.opcode = SD_IO_RW_EXTENDED;
	mmc_cmd.arg = write ? 1<<31 : 0;	/* write flag  */
	mmc_cmd.arg |= (func->num & 0x7) << 28;	/* SDIO func num */
	mmc_cmd.arg |= 1 << 27;			/* block mode */
	/* for function 1 the addr will be incremented */
	mmc_cmd.arg |= (func->num == SDIO_FUNC_1) ? 1 << 26 : 0;
	mmc_cmd.flags = MMC_RSP_SPI_R5 | MMC_RSP_R5 | MMC_CMD_ADTC;
	mmc_req.cmd = &mmc_cmd;
	mmc_req.data = &mmc_dat;

	req_sz = 0;
	sg_cnt = 0;
	sgl = sdiodev->sgtable.sgl;
	skb_queue_walk(target_list, pkt_next) {
		pkt_offset = 0;
		while (pkt_offset < pkt_next->len) {
			pkt_data = pkt_next->data + pkt_offset;
			sg_data_sz = pkt_next->len - pkt_offset;
			if (sg_data_sz > sdiodev->max_segment_size)
				sg_data_sz = sdiodev->max_segment_size;
			if (sg_data_sz > max_req_sz - req_sz)
				sg_data_sz = max_req_sz - req_sz;

			sg_set_buf(sgl, pkt_data, sg_data_sz);
			sg_cnt++;

			sgl = sg_next(sgl);
			req_sz += sg_data_sz;
			pkt_offset += sg_data_sz;
			if (req_sz >= max_req_sz || sg_cnt >= max_seg_cnt) {
				ret = mmc_submit_one(&mmc_dat, &mmc_req, &mmc_cmd,
						     sg_cnt, req_sz, func_blk_sz,
						     &addr, sdiodev, func, write);
				if (ret)
					goto exit_queue_walk;
				req_sz = 0;
				sg_cnt = 0;
				sgl = sdiodev->sgtable.sgl;
			}
		}
	}
	if (sg_cnt)
		ret = mmc_submit_one(&mmc_dat, &mmc_req, &mmc_cmd,
				     sg_cnt, req_sz, func_blk_sz,
				     &addr, sdiodev, func, write);
exit_queue_walk:
	if (!write && sdiodev->settings->bus.sdio.broken_sg_support) {
		src = __skb_peek(&local_list);
		src_offset = 0;
		skb_queue_walk(pktlist, pkt_next) {
			dst_offset = 0;

			/* This is safe because we must have enough SKB data
			 * in the local list to cover everything in pktlist.
			 */
			while (1) {
				req_sz = pkt_next->len - dst_offset;
				if (req_sz > src->len - src_offset)
					req_sz = src->len - src_offset;

				orig_data = src->data + src_offset;
				dst_data = pkt_next->data + dst_offset;
				memcpy(dst_data, orig_data, req_sz);

				src_offset += req_sz;
				if (src_offset == src->len) {
					src_offset = 0;
					src = skb_peek_next(src, &local_list);
				}
				dst_offset += req_sz;
				if (dst_offset == pkt_next->len)
					break;
			}
		}
	}

exit:
	sg_init_table(sdiodev->sgtable.sgl, sdiodev->sgtable.orig_nents);
	while ((pkt_next = __skb_dequeue(&local_list)) != NULL)
		ifxu_pkt_buf_free_skb(pkt_next);

	return ret;
}

int ifxf_sdiod_recv_buf(struct ifxf_sdio_dev *sdiodev, u8 *buf, uint nbytes)
{
	struct sk_buff *mypkt;
	int err;

	mypkt = ifxu_pkt_buf_get_skb(nbytes);
	if (!mypkt) {
		ifxf_err("ifxu_pkt_buf_get_skb failed: len %d\n",
			  nbytes);
		return -EIO;
	}

	err = ifxf_sdiod_recv_pkt(sdiodev, mypkt);
	if (!err)
		memcpy(buf, mypkt->data, nbytes);

	ifxu_pkt_buf_free_skb(mypkt);
	return err;
}

int ifxf_sdiod_recv_pkt(struct ifxf_sdio_dev *sdiodev, struct sk_buff *pkt)
{
	u32 addr = sdiodev->cc_core->base;
	int err = 0;

	ifxf_dbg(SDIO, "addr = 0x%x, size = %d\n", addr, pkt->len);

	err = ifxf_sdiod_set_backplane_window(sdiodev, addr);
	if (err)
		goto done;

	addr &= SBSDIO_SB_OFT_ADDR_MASK;
	addr |= SBSDIO_SB_ACCESS_2_4B_FLAG;

	err = ifxf_sdiod_skbuff_read(sdiodev, sdiodev->func2, addr, pkt);

done:
	return err;
}

int ifxf_sdiod_recv_chain(struct ifxf_sdio_dev *sdiodev,
			   struct sk_buff_head *pktq, uint totlen)
{
	struct sk_buff *glom_skb = NULL;
	struct sk_buff *skb;
	u32 addr = sdiodev->cc_core->base;
	int err = 0;

	ifxf_dbg(SDIO, "addr = 0x%x, size = %d\n",
		  addr, pktq->qlen);

	err = ifxf_sdiod_set_backplane_window(sdiodev, addr);
	if (err)
		goto done;

	addr &= SBSDIO_SB_OFT_ADDR_MASK;
	addr |= SBSDIO_SB_ACCESS_2_4B_FLAG;

	if (pktq->qlen == 1)
		err = ifxf_sdiod_skbuff_read(sdiodev, sdiodev->func2, addr,
					      __skb_peek(pktq));
	else if (!sdiodev->sg_support) {
		glom_skb = ifxu_pkt_buf_get_skb(totlen);
		if (!glom_skb)
			return -ENOMEM;
		err = ifxf_sdiod_skbuff_read(sdiodev, sdiodev->func2, addr,
					      glom_skb);
		if (err)
			goto done;

		skb_queue_walk(pktq, skb) {
			memcpy(skb->data, glom_skb->data, skb->len);
			skb_pull(glom_skb, skb->len);
		}
	} else
		err = ifxf_sdiod_sglist_rw(sdiodev, sdiodev->func2, false,
					    addr, pktq);

done:
	ifxu_pkt_buf_free_skb(glom_skb);
	return err;
}

int ifxf_sdiod_send_buf(struct ifxf_sdio_dev *sdiodev, u8 *buf, uint nbytes)
{
	struct sk_buff *mypkt;
	u32 addr = sdiodev->cc_core->base;
	int err;

	mypkt = ifxu_pkt_buf_get_skb(nbytes);

	if (!mypkt) {
		ifxf_err("ifxu_pkt_buf_get_skb failed: len %d\n",
			  nbytes);
		return -EIO;
	}

	memcpy(mypkt->data, buf, nbytes);

	err = ifxf_sdiod_set_backplane_window(sdiodev, addr);
	if (err)
		goto out;

	addr &= SBSDIO_SB_OFT_ADDR_MASK;
	addr |= SBSDIO_SB_ACCESS_2_4B_FLAG;

	err = ifxf_sdiod_skbuff_write(sdiodev, sdiodev->func2, addr, mypkt);
out:
	ifxu_pkt_buf_free_skb(mypkt);

	return err;
}

int ifxf_sdiod_send_pkt(struct ifxf_sdio_dev *sdiodev,
			 struct sk_buff_head *pktq)
{
	struct sk_buff *skb;
	u32 addr = sdiodev->cc_core->base;
	int err;

	ifxf_dbg(SDIO, "addr = 0x%x, size = %d\n", addr, pktq->qlen);

	err = ifxf_sdiod_set_backplane_window(sdiodev, addr);
	if (err)
		return err;

	addr &= SBSDIO_SB_OFT_ADDR_MASK;
	addr |= SBSDIO_SB_ACCESS_2_4B_FLAG;

	if (pktq->qlen == 1 || !sdiodev->sg_support) {
		skb_queue_walk(pktq, skb) {
			err = ifxf_sdiod_skbuff_write(sdiodev, sdiodev->func2,
						       addr, skb);
			if (err)
				break;
		}
	} else {
		err = ifxf_sdiod_sglist_rw(sdiodev, sdiodev->func2, true,
					    addr, pktq);
	}

	return err;
}

int
ifxf_sdiod_ramrw(struct ifxf_sdio_dev *sdiodev, bool write, u32 address,
		  u8 *data, uint size)
{
	int err = 0;
	struct sk_buff *pkt;
	u32 sdaddr;
	uint dsize;

	dsize = min_t(uint, SBSDIO_SB_OFT_ADDR_LIMIT, size);
	pkt = __dev_alloc_skb(dsize, GFP_KERNEL);
	if (!pkt) {
		ifxf_err("dev_alloc_skb failed: len %d\n", dsize);
		return -EIO;
	}
	pkt->priority = 0;

	/* Determine initial transfer parameters */
	sdaddr = address & SBSDIO_SB_OFT_ADDR_MASK;
	if ((sdaddr + size) & SBSDIO_SBWINDOW_MASK)
		dsize = (SBSDIO_SB_OFT_ADDR_LIMIT - sdaddr);
	else
		dsize = size;

	sdio_claim_host(sdiodev->func1);

	/* Do the transfer(s) */
	while (size) {
		/* Set the backplane window to include the start address */
		err = ifxf_sdiod_set_backplane_window(sdiodev, address);
		if (err)
			break;

		ifxf_dbg(SDIO, "%s %d bytes at offset 0x%08x in window 0x%08x\n",
			  write ? "write" : "read", dsize,
			  sdaddr, address & SBSDIO_SBWINDOW_MASK);

		sdaddr &= SBSDIO_SB_OFT_ADDR_MASK;
		sdaddr |= SBSDIO_SB_ACCESS_2_4B_FLAG;

		skb_put(pkt, dsize);

		if (write) {
			memcpy(pkt->data, data, dsize);
			err = ifxf_sdiod_skbuff_write(sdiodev, sdiodev->func1,
						       sdaddr, pkt);
		} else {
			err = ifxf_sdiod_skbuff_read(sdiodev, sdiodev->func1,
						      sdaddr, pkt);
		}

		if (err) {
			ifxf_err("membytes transfer failed\n");
			break;
		}
		if (!write)
			memcpy(data, pkt->data, dsize);
		skb_trim(pkt, 0);

		/* Adjust for next transfer (if any) */
		size -= dsize;
		if (size) {
			data += dsize;
			address += dsize;
			sdaddr = 0;
			dsize = min_t(uint, SBSDIO_SB_OFT_ADDR_LIMIT, size);
		}
	}

	dev_kfree_skb(pkt);

	sdio_release_host(sdiodev->func1);

	return err;
}

int ifxf_sdiod_abort(struct ifxf_sdio_dev *sdiodev, struct sdio_func *func)
{
	ifxf_dbg(SDIO, "Enter\n");

	/* Issue abort cmd52 command through F0 */
	ifxf_sdiod_func0_wb(sdiodev, SDIO_CCCR_ABORT, func->num, NULL);

	ifxf_dbg(SDIO, "Exit\n");
	return 0;
}

void ifxf_sdiod_sgtable_alloc(struct ifxf_sdio_dev *sdiodev)
{
	struct sdio_func *func;
	struct mmc_host *host;
	uint max_blocks;
	uint nents;
	int err;

	func = sdiodev->func2;
	host = func->card->host;
	sdiodev->sg_support = host->max_segs > 1;
	max_blocks = min_t(uint, host->max_blk_count, 511u);
	sdiodev->max_request_size = min_t(uint, host->max_req_size,
					  max_blocks * func->cur_blksize);
	sdiodev->max_segment_count = min_t(uint, host->max_segs,
					   SG_MAX_SINGLE_ALLOC);
	sdiodev->max_segment_size = host->max_seg_size;

	if (!sdiodev->sg_support)
		return;

	nents = max_t(uint, IFXF_DEFAULT_RXGLOM_SIZE,
		      sdiodev->settings->bus.sdio.txglomsz);
	nents += (nents >> 4) + 1;

	WARN_ON(nents > sdiodev->max_segment_count);

	ifxf_dbg(TRACE, "nents=%d\n", nents);
	err = sg_alloc_table(&sdiodev->sgtable, nents, GFP_KERNEL);
	if (err < 0) {
		ifxf_err("allocation failed: disable scatter-gather");
		sdiodev->sg_support = false;
	}

	sdiodev->txglomsz = sdiodev->settings->bus.sdio.txglomsz;
}

static int ifxf_sdiod_freezer_attach(struct ifxf_sdio_dev *sdiodev)
{
	if (!IS_ENABLED(CONFIG_PM_SLEEP))
		return 0;

	sdiodev->freezer = kzalloc(sizeof(*sdiodev->freezer), GFP_KERNEL);
	if (!sdiodev->freezer)
		return -ENOMEM;
	atomic_set(&sdiodev->freezer->thread_count, 0);
	atomic_set(&sdiodev->freezer->freezing, 0);
	init_waitqueue_head(&sdiodev->freezer->thread_freeze);
	init_completion(&sdiodev->freezer->resumed);
	return 0;
}

static void ifxf_sdiod_freezer_detach(struct ifxf_sdio_dev *sdiodev)
{
	if (sdiodev->freezer) {
		WARN_ON(atomic_read(&sdiodev->freezer->freezing));
		kfree(sdiodev->freezer);
		sdiodev->freezer = NULL;
	}
}

static int ifxf_sdiod_freezer_on(struct ifxf_sdio_dev *sdiodev)
{
	atomic_t *expect = &sdiodev->freezer->thread_count;
	int res = 0;

	sdiodev->freezer->frozen_count = 0;
	reinit_completion(&sdiodev->freezer->resumed);
	atomic_set(&sdiodev->freezer->freezing, 1);
	ifxf_sdio_trigger_dpc(sdiodev->bus);
	wait_event(sdiodev->freezer->thread_freeze,
		   atomic_read(expect) == sdiodev->freezer->frozen_count);
	sdio_claim_host(sdiodev->func1);
	res = ifxf_sdio_sleep(sdiodev->bus, true);
	sdio_release_host(sdiodev->func1);
	return res;
}

static void ifxf_sdiod_freezer_off(struct ifxf_sdio_dev *sdiodev)
{
	sdio_claim_host(sdiodev->func1);
	ifxf_sdio_sleep(sdiodev->bus, false);
	sdio_release_host(sdiodev->func1);
	atomic_set(&sdiodev->freezer->freezing, 0);
	complete_all(&sdiodev->freezer->resumed);
}

bool ifxf_sdiod_freezing(struct ifxf_sdio_dev *sdiodev)
{
	return IS_ENABLED(CONFIG_PM_SLEEP) &&
		atomic_read(&sdiodev->freezer->freezing);
}

void ifxf_sdiod_try_freeze(struct ifxf_sdio_dev *sdiodev)
{
	if (!ifxf_sdiod_freezing(sdiodev))
		return;
	sdiodev->freezer->frozen_count++;
	wake_up(&sdiodev->freezer->thread_freeze);
	wait_for_completion(&sdiodev->freezer->resumed);
}

void ifxf_sdiod_freezer_count(struct ifxf_sdio_dev *sdiodev)
{
	if (IS_ENABLED(CONFIG_PM_SLEEP))
		atomic_inc(&sdiodev->freezer->thread_count);
}

void ifxf_sdiod_freezer_uncount(struct ifxf_sdio_dev *sdiodev)
{
	if (IS_ENABLED(CONFIG_PM_SLEEP))
		atomic_dec(&sdiodev->freezer->thread_count);
}

int ifxf_sdiod_remove(struct ifxf_sdio_dev *sdiodev)
{
	sdiodev->state = IFXF_SDIOD_DOWN;
	if (sdiodev->bus) {
		ifxf_sdio_remove(sdiodev->bus);
		sdiodev->bus = NULL;
	}

	ifxf_sdiod_freezer_detach(sdiodev);

	/* Disable functions 2 then 1. */
	sdio_claim_host(sdiodev->func1);
	sdio_disable_func(sdiodev->func2);
	sdio_disable_func(sdiodev->func1);
	sdio_release_host(sdiodev->func1);

	sg_free_table(&sdiodev->sgtable);
	sdiodev->sbwad = 0;

	pm_runtime_allow(sdiodev->func1->card->host->parent);
	return 0;
}

static void ifxf_sdiod_host_fixup(struct mmc_host *host)
{
	/* runtime-pm powers off the device */
	pm_runtime_forbid(host->parent);
	/* avoid removal detection upon resume */
	host->caps |= MMC_CAP_NONREMOVABLE;
}

int ifxf_sdiod_probe(struct ifxf_sdio_dev *sdiodev)
{
	int ret = 0;
	unsigned int f2_blksz = SDIO_FUNC2_BLOCKSIZE;

	sdio_claim_host(sdiodev->func1);

	ret = sdio_set_block_size(sdiodev->func1, SDIO_FUNC1_BLOCKSIZE);
	if (ret) {
		ifxf_err("Failed to set F1 blocksize\n");
		sdio_release_host(sdiodev->func1);
		return ret;
	}
	switch (sdiodev->func2->device) {
	case SDIO_DEVICE_ID_BROADCOM_CYPRESS_4373:
		f2_blksz = SDIO_4373_FUNC2_BLOCKSIZE;
		break;
	case SDIO_DEVICE_ID_BROADCOM_4359:
	case SDIO_DEVICE_ID_BROADCOM_4354:
	case SDIO_DEVICE_ID_BROADCOM_4356:
		f2_blksz = SDIO_435X_FUNC2_BLOCKSIZE;
		break;
	case SDIO_DEVICE_ID_BROADCOM_CYPRESS_89459:
	case SDIO_DEVICE_ID_CYPRESS_54590:
	case SDIO_DEVICE_ID_CYPRESS_54591:
	case SDIO_DEVICE_ID_CYPRESS_54594:
		f2_blksz = SDIO_89459_FUNC2_BLOCKSIZE;
		break;
	case SDIO_DEVICE_ID_CYPRESS_55572:
	case SDIO_DEVICE_ID_CYPRESS_55500:
		f2_blksz = SDIO_CYW55572_FUNC2_BLOCKSIZE;
		break;
	default:
		break;
	}

	ret = sdio_set_block_size(sdiodev->func2, f2_blksz);
	if (ret) {
		ifxf_err("Failed to set F2 blocksize\n");
		sdio_release_host(sdiodev->func1);
		return ret;
	} else {
		ifxf_dbg(SDIO, "set F2 blocksize to %d\n", f2_blksz);
	}

	/* increase F2 timeout */
	sdiodev->func2->enable_timeout = SDIO_WAIT_F2RDY;

	/* Enable Function 1 */
	ret = sdio_enable_func(sdiodev->func1);
	sdio_release_host(sdiodev->func1);
	if (ret) {
		ifxf_err("Failed to enable F1: err=%d\n", ret);
		goto out;
	}

	ret = ifxf_sdiod_freezer_attach(sdiodev);
	if (ret)
		goto out;

	/* try to attach to the target device */
	sdiodev->bus = ifxf_sdio_probe(sdiodev);
	if (!sdiodev->bus) {
		ret = -ENODEV;
		goto out;
	}
	ifxf_sdiod_host_fixup(sdiodev->func2->card->host);
out:
	if (ret)
		ifxf_sdiod_remove(sdiodev);

	return ret;
}

#define IFXF_SDIO_DEVICE_LEGACY(dev_id)	\
	{SDIO_DEVICE(SDIO_VENDOR_ID_BROADCOM, dev_id)}

#define IFXF_SDIO_DEVICE(dev_id)	\
	{SDIO_DEVICE(SDIO_VENDOR_ID_CYPRESS, dev_id)}

/* devices we support, null terminated */
static const struct sdio_device_id ifxf_sdmmc_ids[] = {
	IFXF_SDIO_DEVICE_LEGACY(SDIO_DEVICE_ID_BROADCOM_43340),
	IFXF_SDIO_DEVICE_LEGACY(SDIO_DEVICE_ID_BROADCOM_43362),
	IFXF_SDIO_DEVICE_LEGACY(SDIO_DEVICE_ID_BROADCOM_43364),
	IFXF_SDIO_DEVICE_LEGACY(SDIO_DEVICE_ID_BROADCOM_4335_4339),
	IFXF_SDIO_DEVICE_LEGACY(SDIO_DEVICE_ID_BROADCOM_4339),
	IFXF_SDIO_DEVICE_LEGACY(SDIO_DEVICE_ID_BROADCOM_43430),
	IFXF_SDIO_DEVICE_LEGACY(SDIO_DEVICE_ID_BROADCOM_4345),
	IFXF_SDIO_DEVICE_LEGACY(SDIO_DEVICE_ID_BROADCOM_43455),
	IFXF_SDIO_DEVICE_LEGACY(SDIO_DEVICE_ID_BROADCOM_4354),
	IFXF_SDIO_DEVICE_LEGACY(SDIO_DEVICE_ID_BROADCOM_4356),
	IFXF_SDIO_DEVICE_LEGACY(SDIO_DEVICE_ID_BROADCOM_4359),
	IFXF_SDIO_DEVICE_LEGACY(SDIO_DEVICE_ID_BROADCOM_CYPRESS_43439),
	IFXF_SDIO_DEVICE_LEGACY(SDIO_DEVICE_ID_BROADCOM_CYPRESS_4373),
	IFXF_SDIO_DEVICE_LEGACY(SDIO_DEVICE_ID_BROADCOM_CYPRESS_43012),
	IFXF_SDIO_DEVICE_LEGACY(SDIO_DEVICE_ID_BROADCOM_CYPRESS_43439),
	IFXF_SDIO_DEVICE_LEGACY(SDIO_DEVICE_ID_BROADCOM_CYPRESS_89459),
	IFXF_SDIO_DEVICE(SDIO_DEVICE_ID_CYPRESS_43439),
	IFXF_SDIO_DEVICE(SDIO_DEVICE_ID_CYPRESS_54590),
	IFXF_SDIO_DEVICE(SDIO_DEVICE_ID_CYPRESS_54591),
	IFXF_SDIO_DEVICE(SDIO_DEVICE_ID_CYPRESS_54594),
	IFXF_SDIO_DEVICE(SDIO_DEVICE_ID_CYPRESS_55572),
	IFXF_SDIO_DEVICE(SDIO_DEVICE_ID_CYPRESS_55500),
	{ /* end: all zeroes */ }
};
MODULE_DEVICE_TABLE(sdio, ifxf_sdmmc_ids);


static void ifxf_sdiod_acpi_set_power_manageable(struct device *dev,
						  int val)
{
#if IS_ENABLED(CONFIG_ACPI)
	struct acpi_device *adev;

	adev = ACPI_COMPANION(dev);
	if (adev)
		adev->flags.power_manageable = 0;
#endif
}

static int ifxf_ops_sdio_probe(struct sdio_func *func,
				const struct sdio_device_id *id)
{
	int err;
	struct ifxf_sdio_dev *sdiodev;
	struct ifxf_bus *bus_if;
	struct device *dev;

	ifxf_dbg(SDIO, "Enter\n");
	ifxf_dbg(SDIO, "Class=%x\n", func->class);
	ifxf_dbg(SDIO, "sdio vendor ID: 0x%04x\n", func->vendor);
	ifxf_dbg(SDIO, "sdio device ID: 0x%04x\n", func->device);
	ifxf_dbg(SDIO, "Function#: %d\n", func->num);

	dev = &func->dev;

	/* Set MMC_QUIRK_LENIENT_FN0 for this card */
	func->card->quirks |= MMC_QUIRK_LENIENT_FN0;

	/* prohibit ACPI power management for this device */
	ifxf_sdiod_acpi_set_power_manageable(dev, 0);

	/* Consume func num 1 but dont do anything with it. */
	if (func->num == SDIO_FUNC_1)
		return 0;

	/* Ignore anything but func 2 */
	if (func->num != SDIO_FUNC_2)
		return -ENODEV;

	bus_if = kzalloc(sizeof(struct ifxf_bus), GFP_KERNEL);
	if (!bus_if)
		return -ENOMEM;
	sdiodev = kzalloc(sizeof(struct ifxf_sdio_dev), GFP_KERNEL);
	if (!sdiodev) {
		kfree(bus_if);
		return -ENOMEM;
	}

	/* store refs to functions used. mmc_card does
	 * not hold the F0 function pointer.
	 */
	sdiodev->func1 = func->card->sdio_func[0];
	sdiodev->func2 = func;

	sdiodev->bus_if = bus_if;
	bus_if->bus_priv.sdio = sdiodev;
	bus_if->proto_type = IFXF_PROTO_BCDC;
	dev_set_drvdata(&func->dev, bus_if);
	dev_set_drvdata(&sdiodev->func1->dev, bus_if);
	sdiodev->dev = &sdiodev->func1->dev;
	dev_set_drvdata(&sdiodev->func2->dev, bus_if);

	ifxf_sdiod_change_state(sdiodev, IFXF_SDIOD_DOWN);

	ifxf_dbg(SDIO, "F2 found, calling ifxf_sdiod_probe...\n");
	err = ifxf_sdiod_probe(sdiodev);
	if (err) {
		ifxf_err("F2 error, probe failed %d...\n", err);
		goto fail;
	}

	ifxf_dbg(SDIO, "F2 init completed...\n");
	return 0;

fail:
	dev_set_drvdata(&func->dev, NULL);
	dev_set_drvdata(&sdiodev->func1->dev, NULL);
	dev_set_drvdata(&sdiodev->func2->dev, NULL);
	kfree(sdiodev);
	kfree(bus_if);
	return err;
}

static void ifxf_ops_sdio_remove(struct sdio_func *func)
{
	struct ifxf_bus *bus_if;
	struct ifxf_sdio_dev *sdiodev;

	ifxf_dbg(SDIO, "Enter\n");
	ifxf_dbg(SDIO, "sdio vendor ID: 0x%04x\n", func->vendor);
	ifxf_dbg(SDIO, "sdio device ID: 0x%04x\n", func->device);
	ifxf_dbg(SDIO, "Function: %d\n", func->num);

	bus_if = dev_get_drvdata(&func->dev);
	if (bus_if) {
		sdiodev = bus_if->bus_priv.sdio;

		/* start by unregistering irqs */
		ifxf_sdiod_intr_unregister(sdiodev);

		if (func->num != SDIO_FUNC_1)
			return;

		/* only proceed with rest of cleanup if func 1 */
		ifxf_sdiod_remove(sdiodev);

		dev_set_drvdata(&sdiodev->func1->dev, NULL);
		dev_set_drvdata(&sdiodev->func2->dev, NULL);

		kfree(bus_if);
		kfree(sdiodev);
	}

	ifxf_dbg(SDIO, "Exit\n");
}

void ifxf_sdio_wowl_config(struct device *dev, bool enabled)
{
	struct ifxf_bus *bus_if = dev_get_drvdata(dev);
	struct ifxf_sdio_dev *sdiodev = bus_if->bus_priv.sdio;
	mmc_pm_flag_t pm_caps = sdio_get_host_pm_caps(sdiodev->func1);

	/* Power must be preserved to be able to support WOWL. */
	if (!(pm_caps & MMC_PM_KEEP_POWER))
		goto notsup;

	if (sdiodev->settings->bus.sdio.oob_irq_supported ||
	    pm_caps & MMC_PM_WAKE_SDIO_IRQ) {
		sdiodev->wowl_enabled = enabled;
		ifxf_dbg(SDIO, "Configuring WOWL, enabled=%d\n", enabled);
		return;
	}

notsup:
	ifxf_dbg(SDIO, "WOWL not supported\n");
}

static int ifxf_ops_sdio_suspend(struct device *dev)
{
	struct sdio_func *func;
	struct ifxf_bus *bus_if;
	struct ifxf_sdio_dev *sdiodev;
	mmc_pm_flag_t sdio_flags;
	struct ifxf_cfg80211_info *config;
	int retry = IFXF_PM_WAIT_MAXRETRY;
	int ret = 0;

	func = container_of(dev, struct sdio_func, dev);
	bus_if = dev_get_drvdata(dev);
	config = bus_if->drvr->config;

	ifxf_dbg(SDIO, "Enter: F%d\n", func->num);

	while (retry &&
	       config->pm_state == IFXF_CFG80211_PM_STATE_SUSPENDING) {
		usleep_range(10000, 20000);
		retry--;
	}
	if (!retry && config->pm_state == IFXF_CFG80211_PM_STATE_SUSPENDING)
		ifxf_err("timed out wait for cfg80211 suspended\n");

	if (func->num != SDIO_FUNC_1)
		return 0;

	sdiodev = bus_if->bus_priv.sdio;

	if (sdiodev->wowl_enabled) {
		ifxf_sdiod_freezer_on(sdiodev);
		ifxf_sdio_wd_timer(sdiodev->bus, 0);

		sdio_flags = MMC_PM_KEEP_POWER;
		if (sdiodev->settings->bus.sdio.oob_irq_supported)
			enable_irq_wake(sdiodev->settings->bus.sdio.oob_irq_nr);
		else
			sdio_flags |= MMC_PM_WAKE_SDIO_IRQ;

		if (sdio_set_host_pm_flags(sdiodev->func1, sdio_flags))
			ifxf_err("Failed to set pm_flags %x\n", sdio_flags);

	} else {
		/* power will be cut so remove device, probe again in resume */
		ifxf_sdiod_intr_unregister(sdiodev);
		ret = ifxf_sdiod_remove(sdiodev);
		if (ret)
			ifxf_err("Failed to remove device on suspend\n");
	}

	return ret;
}

static int ifxf_ops_sdio_resume(struct device *dev)
{
	struct ifxf_bus *bus_if = dev_get_drvdata(dev);
	struct ifxf_sdio_dev *sdiodev = bus_if->bus_priv.sdio;
	struct sdio_func *func = container_of(dev, struct sdio_func, dev);
	int ret = 0;

	ifxf_dbg(SDIO, "Enter: F%d\n", func->num);
	if (func->num != SDIO_FUNC_2)
		return 0;

	if (!sdiodev->wowl_enabled) {
		/* bus was powered off and device removed, probe again */
		ret = ifxf_sdiod_probe(sdiodev);
		if (ret)
			ifxf_err("Failed to probe device on resume\n");
	} else {
		if (sdiodev->settings->bus.sdio.oob_irq_supported)
			disable_irq_wake(sdiodev->settings->bus.sdio.oob_irq_nr);

		ifxf_sdiod_freezer_off(sdiodev);
	}

	return ret;
}

static DEFINE_SIMPLE_DEV_PM_OPS(ifxf_sdio_pm_ops,
				ifxf_ops_sdio_suspend,
				ifxf_ops_sdio_resume);

static struct sdio_driver ifxf_sdmmc_driver = {
	.probe = ifxf_ops_sdio_probe,
	.remove = ifxf_ops_sdio_remove,
	.name = KBUILD_MODNAME,
	.id_table = ifxf_sdmmc_ids,
	.drv = {
		.owner = THIS_MODULE,
		.pm = pm_sleep_ptr(&ifxf_sdio_pm_ops),
		.coredump = ifxf_dev_coredump,
	},
};

int ifxf_sdio_register(void)
{
	return sdio_register_driver(&ifxf_sdmmc_driver);
}

void ifxf_sdio_exit(void)
{
	ifxf_dbg(SDIO, "Enter\n");

	sdio_unregister_driver(&ifxf_sdmmc_driver);
}

