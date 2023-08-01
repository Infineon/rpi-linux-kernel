// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2014 Broadcom Corporation
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/firmware.h>
#include <linux/pci.h>
#include <linux/vmalloc.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/bcma/bcma.h>
#include <linux/sched.h>
#include <linux/io.h>
#include <linux/sched/signal.h>
#include <linux/kthread.h>
#include <asm/unaligned.h>

#include <soc.h>
#include <chipcommon.h>
#include <ifxu_utils.h>
#include <ifxu_wifi.h>
#include <ifx_hw_ids.h>

/* Custom ifxf_err() that takes bus arg and passes it further */
#define ifxf_err(bus, fmt, ...)					\
	do {								\
		if (IS_ENABLED(CONFIG_IFXDBG) ||			\
		    IS_ENABLED(CONFIG_IFX_TRACING) ||			\
		    net_ratelimit())					\
			__ifxf_err(bus, __func__, fmt, ##__VA_ARGS__);	\
	} while (0)

#include "debug.h"
#include "bus.h"
#include "commonring.h"
#include "msgbuf.h"
#include "pcie.h"
#include "firmware.h"
#include "chip.h"
#include "core.h"
#include "common.h"
#include "cfg80211.h"
#include "trxhdr.h"


enum ifxf_pcie_state {
	IFXFMAC_PCIE_STATE_DOWN,
	IFXFMAC_PCIE_STATE_UP
};

CY_FW_DEF(4356, "cyfmac4356-pcie");
CY_FW_DEF(43570, "cyfmac43570-pcie");
CY_FW_DEF(4359, "cyfmac4359-pcie");
CY_FW_DEF(4355, "cyfmac54591-pcie");
CY_FW_TRXSE_DEF(55572, "cyfmac55572-pcie");
CY_FW_DEF(4373, "cyfmac4373-pcie");

static const struct ifxf_firmware_mapping ifxf_pcie_fwnames[] = {
	CYF_FW_ENTRY(CY_CC_4356_CHIP_ID, 0xFFFFFFFF, 4356),
	CYF_FW_ENTRY(CY_CC_43570_CHIP_ID, 0xFFFFFFFF, 43570),
	CYF_FW_ENTRY(CY_CC_4359_CHIP_ID, 0xFFFFFFFF, 4359),
	CYF_FW_ENTRY(CY_CC_89459_CHIP_ID, 0xFFFFFFFF, 4355),
	CYF_FW_ENTRY(CY_CC_55572_CHIP_ID, 0xFFFFFFFF, 55572),
	CYF_FW_ENTRY(CY_CC_4373_CHIP_ID, 0xFFFFFFFF, 4373),
};

#define IFXF_PCIE_READ_SHARED_TIMEOUT	5000 /* msec */
#define IFXF_PCIE_FW_UP_TIMEOUT		5000 /* msec */

#define IFXF_PCIE_REG_MAP_SIZE			(32 * 1024)

/* backplane addres space accessed by BAR0 */
#define	IFXF_PCIE_BAR0_WINDOW			0x80
#define IFXF_PCIE_BAR0_REG_SIZE		0x1000
#define	IFXF_PCIE_BAR0_WRAPPERBASE		0x70

#define IFXF_PCIE_BAR0_WRAPBASE_DMP_OFFSET	0x1000
#define IFXF_PCIE_BAR0_PCIE_ENUM_OFFSET	0x2000
#define IFXF_CYW55572_PCIE_BAR0_PCIE_ENUM_OFFSET	0x3000

#define IFXF_PCIE_ARMCR4REG_BANKIDX		0x40
#define IFXF_PCIE_ARMCR4REG_BANKPDA		0x4C

#define IFXF_PCIE_REG_INTSTATUS		0x90
#define IFXF_PCIE_REG_INTMASK			0x94
#define IFXF_PCIE_REG_SBMBX			0x98

#define IFXF_PCIE_REG_LINK_STATUS_CTRL		0xBC

#define IFXF_PCIE_PCIE2REG_INTMASK		0x24
#define IFXF_PCIE_PCIE2REG_MAILBOXINT		0x48
#define IFXF_PCIE_PCIE2REG_MAILBOXMASK		0x4C
#define IFXF_PCIE_PCIE2REG_CONFIGADDR		0x120
#define IFXF_PCIE_PCIE2REG_CONFIGDATA		0x124
#define IFXF_PCIE_PCIE2REG_H2D_MAILBOX_0	0x140
#define IFXF_PCIE_PCIE2REG_H2D_MAILBOX_1	0x144
#define IFXF_PCIE_PCIE2REG_DAR_D2H_MSG_0	0xA80
#define IFXF_PCIE_PCIE2REG_DAR_H2D_MSG_0	0xA90

#define IFXF_PCIE_64_PCIE2REG_INTMASK		0xC14
#define IFXF_PCIE_64_PCIE2REG_MAILBOXINT	0xC30
#define IFXF_PCIE_64_PCIE2REG_MAILBOXMASK	0xC34
#define IFXF_PCIE_64_PCIE2REG_H2D_MAILBOX_0	0xA20
#define IFXF_PCIE_64_PCIE2REG_H2D_MAILBOX_1	0xA24

#define IFXF_PCIE2_INTA			0x01
#define IFXF_PCIE2_INTB			0x02

#define IFXF_PCIE_INT_0			0x01
#define IFXF_PCIE_INT_1			0x02
#define IFXF_PCIE_INT_DEF			(IFXF_PCIE_INT_0 | \
						 IFXF_PCIE_INT_1)

#define IFXF_PCIE_MB_INT_FN0_0			0x0100
#define IFXF_PCIE_MB_INT_FN0_1			0x0200
#define	IFXF_PCIE_MB_INT_D2H0_DB0		0x10000
#define	IFXF_PCIE_MB_INT_D2H0_DB1		0x20000
#define	IFXF_PCIE_MB_INT_D2H1_DB0		0x40000
#define	IFXF_PCIE_MB_INT_D2H1_DB1		0x80000
#define	IFXF_PCIE_MB_INT_D2H2_DB0		0x100000
#define	IFXF_PCIE_MB_INT_D2H2_DB1		0x200000
#define	IFXF_PCIE_MB_INT_D2H3_DB0		0x400000
#define	IFXF_PCIE_MB_INT_D2H3_DB1		0x800000

#define IFXF_PCIE_MB_INT_FN0			(IFXF_PCIE_MB_INT_FN0_0 | \
						 IFXF_PCIE_MB_INT_FN0_1)
#define IFXF_PCIE_MB_INT_D2H_DB		(IFXF_PCIE_MB_INT_D2H0_DB0 | \
						 IFXF_PCIE_MB_INT_D2H0_DB1 | \
						 IFXF_PCIE_MB_INT_D2H1_DB0 | \
						 IFXF_PCIE_MB_INT_D2H1_DB1 | \
						 IFXF_PCIE_MB_INT_D2H2_DB0 | \
						 IFXF_PCIE_MB_INT_D2H2_DB1 | \
						 IFXF_PCIE_MB_INT_D2H3_DB0 | \
						 IFXF_PCIE_MB_INT_D2H3_DB1)

#define	IFXF_PCIE_64_MB_INT_D2H0_DB0		0x1
#define	IFXF_PCIE_64_MB_INT_D2H0_DB1		0x2
#define	IFXF_PCIE_64_MB_INT_D2H1_DB0		0x4
#define	IFXF_PCIE_64_MB_INT_D2H1_DB1		0x8
#define	IFXF_PCIE_64_MB_INT_D2H2_DB0		0x10
#define	IFXF_PCIE_64_MB_INT_D2H2_DB1		0x20
#define	IFXF_PCIE_64_MB_INT_D2H3_DB0		0x40
#define	IFXF_PCIE_64_MB_INT_D2H3_DB1		0x80
#define	IFXF_PCIE_64_MB_INT_D2H4_DB0		0x100
#define	IFXF_PCIE_64_MB_INT_D2H4_DB1		0x200
#define	IFXF_PCIE_64_MB_INT_D2H5_DB0		0x400
#define	IFXF_PCIE_64_MB_INT_D2H5_DB1		0x800
#define	IFXF_PCIE_64_MB_INT_D2H6_DB0		0x1000
#define	IFXF_PCIE_64_MB_INT_D2H6_DB1		0x2000
#define	IFXF_PCIE_64_MB_INT_D2H7_DB0		0x4000
#define	IFXF_PCIE_64_MB_INT_D2H7_DB1		0x8000

#define IFXF_PCIE_64_MB_INT_D2H_DB		(IFXF_PCIE_64_MB_INT_D2H0_DB0 | \
						 IFXF_PCIE_64_MB_INT_D2H0_DB1 | \
						 IFXF_PCIE_64_MB_INT_D2H1_DB0 | \
						 IFXF_PCIE_64_MB_INT_D2H1_DB1 | \
						 IFXF_PCIE_64_MB_INT_D2H2_DB0 | \
						 IFXF_PCIE_64_MB_INT_D2H2_DB1 | \
						 IFXF_PCIE_64_MB_INT_D2H3_DB0 | \
						 IFXF_PCIE_64_MB_INT_D2H3_DB1 | \
						 IFXF_PCIE_64_MB_INT_D2H4_DB0 | \
						 IFXF_PCIE_64_MB_INT_D2H4_DB1 | \
						 IFXF_PCIE_64_MB_INT_D2H5_DB0 | \
						 IFXF_PCIE_64_MB_INT_D2H5_DB1 | \
						 IFXF_PCIE_64_MB_INT_D2H6_DB0 | \
						 IFXF_PCIE_64_MB_INT_D2H6_DB1 | \
						 IFXF_PCIE_64_MB_INT_D2H7_DB0 | \
						 IFXF_PCIE_64_MB_INT_D2H7_DB1)

#define IFXF_PCIE_SHARED_VERSION_6		6
#define IFXF_PCIE_SHARED_VERSION_7		7
#define IFXF_PCIE_MIN_SHARED_VERSION		5
#define IFXF_PCIE_MAX_SHARED_VERSION		IFXF_PCIE_SHARED_VERSION_7
#define IFXF_PCIE_SHARED_VERSION_MASK		0x00FF
#define IFXF_PCIE_SHARED_DMA_INDEX		0x10000
#define IFXF_PCIE_SHARED_DMA_2B_IDX		0x100000
#define IFXF_PCIE_SHARED_USE_MAILBOX		0x2000000
#define IFXF_PCIE_SHARED_HOSTRDY_DB1		0x10000000

#define IFXF_PCIE_FLAGS_HTOD_SPLIT		0x4000
#define IFXF_PCIE_FLAGS_DTOH_SPLIT		0x8000

#define IFXF_SHARED_MAX_RXBUFPOST_OFFSET	34
#define IFXF_SHARED_RING_BASE_OFFSET		52
#define IFXF_SHARED_RX_DATAOFFSET_OFFSET	36
#define IFXF_SHARED_CONSOLE_ADDR_OFFSET	20
#define IFXF_SHARED_HTOD_MB_DATA_ADDR_OFFSET	40
#define IFXF_SHARED_DTOH_MB_DATA_ADDR_OFFSET	44
#define IFXF_SHARED_RING_INFO_ADDR_OFFSET	48
#define IFXF_SHARED_DMA_SCRATCH_LEN_OFFSET	52
#define IFXF_SHARED_DMA_SCRATCH_ADDR_OFFSET	56
#define IFXF_SHARED_DMA_RINGUPD_LEN_OFFSET	64
#define IFXF_SHARED_DMA_RINGUPD_ADDR_OFFSET	68
#define IFXF_SHARED_HOST_CAP_OFFSET		84

#define IFXF_RING_H2D_RING_COUNT_OFFSET	0
#define IFXF_RING_D2H_RING_COUNT_OFFSET	1
#define IFXF_RING_H2D_RING_MEM_OFFSET		4
#define IFXF_RING_H2D_RING_STATE_OFFSET	8

#define IFXF_RING_MEM_BASE_ADDR_OFFSET		8
#define IFXF_RING_MAX_ITEM_OFFSET		4
#define IFXF_RING_LEN_ITEMS_OFFSET		6
#define IFXF_RING_MEM_SZ			16
#define IFXF_RING_STATE_SZ			8

#define IFXF_DEF_MAX_RXBUFPOST			255

#define IFXF_HOSTCAP_H2D_ENABLE_HOSTRDY	0x400
#define IFXF_HOSTCAP_DS_NO_OOB_DW			0x1000

#define IFXF_CONSOLE_BUFADDR_OFFSET		8
#define IFXF_CONSOLE_BUFSIZE_OFFSET		12
#define IFXF_CONSOLE_WRITEIDX_OFFSET		16

#define IFXF_DMA_D2H_SCRATCH_BUF_LEN		8
#define IFXF_DMA_D2H_RINGUPD_BUF_LEN		1024

#define IFXF_D2H_DEV_D3_ACK			0x00000001
#define IFXF_D2H_DEV_DS_ENTER_REQ		0x00000002
#define IFXF_D2H_DEV_DS_EXIT_NOTE		0x00000004
#define IFXF_D2H_DEV_FWHALT			0x10000000

#define IFXF_H2D_HOST_D3_INFORM		0x00000001
#define IFXF_H2D_HOST_DS_ACK			0x00000002
#define IFXF_H2D_HOST_D0_INFORM_IN_USE		0x00000008
#define IFXF_H2D_HOST_D0_INFORM		0x00000010

#define IFXF_PCIE_MBDATA_TIMEOUT		msecs_to_jiffies(2000)

#define IFXF_PCIE_CFGREG_STATUS_CMD		0x4
#define IFXF_PCIE_CFGREG_PM_CSR		0x4C
#define IFXF_PCIE_CFGREG_MSI_CAP		0x58
#define IFXF_PCIE_CFGREG_MSI_ADDR_L		0x5C
#define IFXF_PCIE_CFGREG_MSI_ADDR_H		0x60
#define IFXF_PCIE_CFGREG_MSI_DATA		0x64
#define IFXF_PCIE_CFGREG_REVID			0x6C
#define IFXF_PCIE_CFGREG_LINK_STATUS_CTRL	0xBC
#define IFXF_PCIE_CFGREG_LINK_STATUS_CTRL2	0xDC
#define IFXF_PCIE_CFGREG_RBAR_CTRL		0x228
#define IFXF_PCIE_CFGREG_PML1_SUB_CTRL1	0x248
#define IFXF_PCIE_CFGREG_REG_BAR2_CONFIG	0x4E0
#define IFXF_PCIE_CFGREG_REG_BAR3_CONFIG	0x4F4
#define IFXF_PCIE_CFGREG_REVID_SECURE_MODE	BIT(31)
#define IFXF_PCIE_LINK_STATUS_CTRL_ASPM_ENAB	3

/* Magic number at a magic location to find RAM size */
#define IFXF_RAMSIZE_MAGIC			0x534d4152	/* SMAR */
#define IFXF_RAMSIZE_OFFSET			0x6c

#define IFXF_ENTROPY_SEED_LEN		64u
#define IFXF_ENTROPY_NONCE_LEN		16u
#define IFXF_ENTROPY_HOST_LEN		(IFXF_ENTROPY_SEED_LEN + \
					 IFXF_ENTROPY_NONCE_LEN)
#define IFXF_NVRAM_OFFSET_TCM		4u
#define IFXF_NVRAM_COMPRS_FACTOR	4u
#define IFXF_NVRAM_RNG_SIGNATURE	0xFEEDC0DEu

struct ifxf_rand_metadata {
	u32 signature;
	u32 count;
};

struct ifxf_pcie_console {
	u32 base_addr;
	u32 buf_addr;
	u32 bufsize;
	u32 read_idx;
	u8 log_str[256];
	u8 log_idx;
};

struct ifxf_pcie_shared_info {
	u32 tcm_base_address;
	u32 flags;
	struct ifxf_pcie_ringbuf *commonrings[IFXF_NROF_COMMON_MSGRINGS];
	struct ifxf_pcie_ringbuf *flowrings;
	u16 max_rxbufpost;
	u16 max_flowrings;
	u16 max_submissionrings;
	u16 max_completionrings;
	u32 rx_dataoffset;
	u32 htod_mb_data_addr;
	u32 dtoh_mb_data_addr;
	u32 ring_info_addr;
	struct ifxf_pcie_console console;
	void *scratch;
	dma_addr_t scratch_dmahandle;
	void *ringupd;
	dma_addr_t ringupd_dmahandle;
	u8 version;
};

struct ifxf_pcie_core_info {
	u32 base;
	u32 wrapbase;
};

#define IFXF_OTP_MAX_PARAM_LEN 16

struct ifxf_otp_params {
	char module[IFXF_OTP_MAX_PARAM_LEN];
	char vendor[IFXF_OTP_MAX_PARAM_LEN];
	char version[IFXF_OTP_MAX_PARAM_LEN];
	bool valid;
};

struct ifxf_pciedev_info {
	enum ifxf_pcie_state state;
	bool in_irq;
	struct pci_dev *pdev;
	char fw_name[IFXF_FW_NAME_LEN];
	char nvram_name[IFXF_FW_NAME_LEN];
	char clm_name[IFXF_FW_NAME_LEN];
	const struct firmware *clm_fw;
	const struct ifxf_pcie_reginfo *reginfo;
	void __iomem *regs;
	void __iomem *tcm;
	u32 ram_base;
	u32 ram_size;
	struct ifxf_chip *ci;
	u32 coreid;
	struct ifxf_pcie_shared_info shared;
	u8 hostready;
	bool use_mailbox;
	bool use_d0_inform;
	wait_queue_head_t mbdata_resp_wait;
	bool mbdata_completed;
	bool irq_allocated;
	bool wowl_enabled;
	u8 dma_idx_sz;
	void *idxbuf;
	u32 idxbuf_sz;
	dma_addr_t idxbuf_dmahandle;
	u16 (*read_ptr)(struct ifxf_pciedev_info *devinfo, u32 mem_offset);
	void (*write_ptr)(struct ifxf_pciedev_info *devinfo, u32 mem_offset,
			  u16 value);
	struct ifxf_mp_device *settings;
	struct ifxf_otp_params otp;
	ulong bar1_size;
#ifdef DEBUG
	u32 console_interval;
	bool console_active;
	struct timer_list timer;
#endif
};

struct ifxf_pcie_ringbuf {
	struct ifxf_commonring commonring;
	dma_addr_t dma_handle;
	u32 w_idx_addr;
	u32 r_idx_addr;
	struct ifxf_pciedev_info *devinfo;
	u8 id;
};

/**
 * struct ifxf_pcie_dhi_ringinfo - dongle/host interface shared ring info
 *
 * @ringmem: dongle memory pointer to ring memory location
 * @h2d_w_idx_ptr: h2d ring write indices dongle memory pointers
 * @h2d_r_idx_ptr: h2d ring read indices dongle memory pointers
 * @d2h_w_idx_ptr: d2h ring write indices dongle memory pointers
 * @d2h_r_idx_ptr: d2h ring read indices dongle memory pointers
 * @h2d_w_idx_hostaddr: h2d ring write indices host memory pointers
 * @h2d_r_idx_hostaddr: h2d ring read indices host memory pointers
 * @d2h_w_idx_hostaddr: d2h ring write indices host memory pointers
 * @d2h_r_idx_hostaddr: d2h ring reaD indices host memory pointers
 * @max_flowrings: maximum number of tx flow rings supported.
 * @max_submissionrings: maximum number of submission rings(h2d) supported.
 * @max_completionrings: maximum number of completion rings(d2h) supported.
 */
struct ifxf_pcie_dhi_ringinfo {
	__le32			ringmem;
	__le32			h2d_w_idx_ptr;
	__le32			h2d_r_idx_ptr;
	__le32			d2h_w_idx_ptr;
	__le32			d2h_r_idx_ptr;
	struct msgbuf_buf_addr	h2d_w_idx_hostaddr;
	struct msgbuf_buf_addr	h2d_r_idx_hostaddr;
	struct msgbuf_buf_addr	d2h_w_idx_hostaddr;
	struct msgbuf_buf_addr	d2h_r_idx_hostaddr;
	__le16			max_flowrings;
	__le16			max_submissionrings;
	__le16			max_completionrings;
};

static const u32 ifxf_ring_max_item[IFXF_NROF_COMMON_MSGRINGS] = {
	IFXF_H2D_MSGRING_CONTROL_SUBMIT_MAX_ITEM,
	IFXF_H2D_MSGRING_RXPOST_SUBMIT_MAX_ITEM,
	IFXF_D2H_MSGRING_CONTROL_COMPLETE_MAX_ITEM,
	IFXF_D2H_MSGRING_TX_COMPLETE_MAX_ITEM,
	IFXF_D2H_MSGRING_RX_COMPLETE_MAX_ITEM
};

static const u32 ifxf_ring_itemsize_pre_v7[IFXF_NROF_COMMON_MSGRINGS] = {
	IFXF_H2D_MSGRING_CONTROL_SUBMIT_ITEMSIZE,
	IFXF_H2D_MSGRING_RXPOST_SUBMIT_ITEMSIZE,
	IFXF_D2H_MSGRING_CONTROL_COMPLETE_ITEMSIZE,
	IFXF_D2H_MSGRING_TX_COMPLETE_ITEMSIZE_PRE_V7,
	IFXF_D2H_MSGRING_RX_COMPLETE_ITEMSIZE_PRE_V7
};

static const u32 ifxf_ring_itemsize[IFXF_NROF_COMMON_MSGRINGS] = {
	IFXF_H2D_MSGRING_CONTROL_SUBMIT_ITEMSIZE,
	IFXF_H2D_MSGRING_RXPOST_SUBMIT_ITEMSIZE,
	IFXF_D2H_MSGRING_CONTROL_COMPLETE_ITEMSIZE,
	IFXF_D2H_MSGRING_TX_COMPLETE_ITEMSIZE,
	IFXF_D2H_MSGRING_RX_COMPLETE_ITEMSIZE
};

struct ifxf_pcie_reginfo {
	u32 intmask;
	u32 mailboxint;
	u32 mailboxmask;
	u32 h2d_mailbox_0;
	u32 h2d_mailbox_1;
	u32 int_d2h_db;
	u32 int_fn0;
};

static const struct ifxf_pcie_reginfo ifxf_reginfo_default = {
	.intmask = IFXF_PCIE_PCIE2REG_INTMASK,
	.mailboxint = IFXF_PCIE_PCIE2REG_MAILBOXINT,
	.mailboxmask = IFXF_PCIE_PCIE2REG_MAILBOXMASK,
	.h2d_mailbox_0 = IFXF_PCIE_PCIE2REG_H2D_MAILBOX_0,
	.h2d_mailbox_1 = IFXF_PCIE_PCIE2REG_H2D_MAILBOX_1,
	.int_d2h_db = IFXF_PCIE_MB_INT_D2H_DB,
	.int_fn0 = IFXF_PCIE_MB_INT_FN0,
};

static const struct ifxf_pcie_reginfo ifxf_reginfo_64 = {
	.intmask = IFXF_PCIE_64_PCIE2REG_INTMASK,
	.mailboxint = IFXF_PCIE_64_PCIE2REG_MAILBOXINT,
	.mailboxmask = IFXF_PCIE_64_PCIE2REG_MAILBOXMASK,
	.h2d_mailbox_0 = IFXF_PCIE_64_PCIE2REG_H2D_MAILBOX_0,
	.h2d_mailbox_1 = IFXF_PCIE_64_PCIE2REG_H2D_MAILBOX_1,
	.int_d2h_db = IFXF_PCIE_64_MB_INT_D2H_DB,
	.int_fn0 = 0,
};

static void ifxf_pcie_setup(struct device *dev, int ret,
			     struct ifxf_fw_request *fwreq);
static struct ifxf_fw_request *
ifxf_pcie_prepare_fw_request(struct ifxf_pciedev_info *devinfo);
static void ifxf_pcie_bus_console_init(struct ifxf_pciedev_info *devinfo);
static void ifxf_pcie_bus_console_read(struct ifxf_pciedev_info *devinfo,
					bool error);

static void
ifxf_pcie_fwcon_timer(struct ifxf_pciedev_info *devinfo, bool active);
static void ifxf_pcie_debugfs_create(struct device *dev);

#ifdef CONFIG_IFXFMAC_PCIE_BARWIN_SZ
DEFINE_RAW_SPINLOCK(pcie_lock);
#endif /* CONFIG_IFXFMAC_PCIE_BARWIN_SZ */

static u16
ifxf_pcie_read_reg16(struct ifxf_pciedev_info *devinfo, u32 reg_offset)
{
	void __iomem *address = devinfo->regs + reg_offset;

	return ioread16(address);
}

static u32
ifxf_pcie_read_reg32(struct ifxf_pciedev_info *devinfo, u32 reg_offset)
{
	void __iomem *address = devinfo->regs + reg_offset;

	return (ioread32(address));
}


static void
ifxf_pcie_write_reg32(struct ifxf_pciedev_info *devinfo, u32 reg_offset,
		       u32 value)
{
	void __iomem *address = devinfo->regs + reg_offset;

	iowrite32(value, address);
}


static u8
ifxf_pcie_read_tcm8(struct ifxf_pciedev_info *devinfo, u32 mem_offset)
{
	struct pci_dev *pdev = devinfo->pdev;
	struct ifxf_bus *bus = dev_get_drvdata(&pdev->dev);
	void __iomem *address = devinfo->tcm + mem_offset;
#ifdef CONFIG_IFXFMAC_PCIE_BARWIN_SZ
	unsigned long flags;
	u8 value;

	raw_spin_lock_irqsave(&pcie_lock, flags);
	if ((address - devinfo->tcm) >= devinfo->bar1_size) {
		pci_write_config_dword(devinfo->pdev, BCMA_PCI_BAR1_WIN,
				       devinfo->bar1_size);
		address = address - devinfo->bar1_size;
	}
	value = ioread8(address);
	pci_write_config_dword(devinfo->pdev, BCMA_PCI_BAR1_WIN, 0x0);
	raw_spin_unlock_irqrestore(&pcie_lock, flags);

	return value;
#else
	if ((address - devinfo->tcm) >= devinfo->bar1_size) {
		ifxf_err(bus,
			  "mem_offset:%d exceeds device size=%ld\n",
			  mem_offset, devinfo->bar1_size);
		return -EINVAL;
	}

	return (ioread8(address));
#endif /* CONFIG_IFXFMAC_PCIE_BARWIN_SZ */
}


static u16
ifxf_pcie_read_tcm16(struct ifxf_pciedev_info *devinfo, u32 mem_offset)
{
	struct pci_dev *pdev = devinfo->pdev;
	struct ifxf_bus *bus = dev_get_drvdata(&pdev->dev);
	void __iomem *address = devinfo->tcm + mem_offset;
#ifdef CONFIG_IFXFMAC_PCIE_BARWIN_SZ
	u16 value;
	unsigned long flags;

	raw_spin_lock_irqsave(&pcie_lock, flags);
	if ((address - devinfo->tcm) >= devinfo->bar1_size) {
		pci_write_config_dword(devinfo->pdev, BCMA_PCI_BAR1_WIN,
				       devinfo->bar1_size);
		address = address - devinfo->bar1_size;
	}
	value = ioread16(address);
	pci_write_config_dword(devinfo->pdev, BCMA_PCI_BAR1_WIN, 0x0);
	raw_spin_unlock_irqrestore(&pcie_lock, flags);

	return value;
#else
	if ((address - devinfo->tcm) >= devinfo->bar1_size) {
		ifxf_err(bus, "mem_offset:%d exceeds device size=%ld\n",
				mem_offset, devinfo->bar1_size);
		return -EINVAL;
	}

	return (ioread16(address));
#endif /* CONFIG_IFXFMAC_PCIE_BARWIN_SZ */
}


static void
ifxf_pcie_write_tcm16(struct ifxf_pciedev_info *devinfo, u32 mem_offset,
		       u16 value)
{
	struct pci_dev *pdev = devinfo->pdev;
	struct ifxf_bus *bus = dev_get_drvdata(&pdev->dev);
	void __iomem *address = devinfo->tcm + mem_offset;
#ifdef CONFIG_IFXFMAC_PCIE_BARWIN_SZ
	unsigned long flags;

	raw_spin_lock_irqsave(&pcie_lock, flags);
	if ((address - devinfo->tcm) >= devinfo->bar1_size) {
		pci_write_config_dword(devinfo->pdev, BCMA_PCI_BAR1_WIN,
				       devinfo->bar1_size);
		address = address - devinfo->bar1_size;
	}

	iowrite16(value, address);
	pci_write_config_dword(devinfo->pdev, BCMA_PCI_BAR1_WIN, 0x0);
	raw_spin_unlock_irqrestore(&pcie_lock, flags);
#else
	if ((address - devinfo->tcm) >= devinfo->bar1_size) {
		ifxf_err(bus, "mem_offset:%d exceeds device size=%ld\n",
				mem_offset, devinfo->bar1_size);
		return;
	}

	iowrite16(value, address);
#endif /* CONFIG_IFXFMAC_PCIE_BARWIN_SZ */
}


static u16
ifxf_pcie_read_idx(struct ifxf_pciedev_info *devinfo, u32 mem_offset)
{
	u16 *address = devinfo->idxbuf + mem_offset;

	return (*(address));
}


static void
ifxf_pcie_write_idx(struct ifxf_pciedev_info *devinfo, u32 mem_offset,
		     u16 value)
{
	u16 *address = devinfo->idxbuf + mem_offset;

	*(address) = value;
}


static u32
ifxf_pcie_read_tcm32(struct ifxf_pciedev_info *devinfo, u32 mem_offset)
{
	struct pci_dev *pdev = devinfo->pdev;
	struct ifxf_bus *bus = dev_get_drvdata(&pdev->dev);
	void __iomem *address = devinfo->tcm + mem_offset;
#ifdef CONFIG_IFXFMAC_PCIE_BARWIN_SZ
	u32 value;
	unsigned long flags;

	raw_spin_lock_irqsave(&pcie_lock, flags);
	if ((address - devinfo->tcm) >= devinfo->bar1_size) {
		pci_write_config_dword(devinfo->pdev, BCMA_PCI_BAR1_WIN,
				       devinfo->bar1_size);
		address = address - devinfo->bar1_size;
	}
	value = ioread32(address);
	pci_write_config_dword(devinfo->pdev, BCMA_PCI_BAR1_WIN, 0x0);
	raw_spin_unlock_irqrestore(&pcie_lock, flags);

	return value;
#else
	if ((address - devinfo->tcm) >= devinfo->bar1_size) {
		ifxf_err(bus, "mem_offset:%d exceeds device size=%ld\n",
			  mem_offset, devinfo->bar1_size);
		return -EINVAL;
	}

	return (ioread32(address));
#endif /* CONFIG_IFXFMAC_PCIE_BARWIN_SZ */
}


static void
ifxf_pcie_write_tcm32(struct ifxf_pciedev_info *devinfo, u32 mem_offset,
		       u32 value)
{
	struct pci_dev *pdev = devinfo->pdev;
	struct ifxf_bus *bus = dev_get_drvdata(&pdev->dev);
	void __iomem *address = devinfo->tcm + mem_offset;
#ifdef CONFIG_IFXFMAC_PCIE_BARWIN_SZ
	unsigned long flags;

	raw_spin_lock_irqsave(&pcie_lock, flags);
	if ((address - devinfo->tcm) >= devinfo->bar1_size) {
		pci_write_config_dword(devinfo->pdev, BCMA_PCI_BAR1_WIN,
				       devinfo->bar1_size);
		address = address - devinfo->bar1_size;
	}
	iowrite32(value, address);
	pci_write_config_dword(devinfo->pdev, BCMA_PCI_BAR1_WIN, 0x0);
	raw_spin_unlock_irqrestore(&pcie_lock, flags);
#else
	if ((address - devinfo->tcm) >= devinfo->bar1_size) {
		ifxf_err(bus, "mem_offset:%d exceeds device size=%ld\n",
			  mem_offset, devinfo->bar1_size);
		return;
	}

	iowrite32(value, address);
#endif /* CONFIG_IFXFMAC_PCIE_BARWIN_SZ */
}


static u32
ifxf_pcie_read_ram32(struct ifxf_pciedev_info *devinfo, u32 mem_offset)
{
	struct pci_dev *pdev = devinfo->pdev;
	struct ifxf_bus *bus = dev_get_drvdata(&pdev->dev);
	void __iomem *address = devinfo->tcm + devinfo->ci->rambase
		+ mem_offset;
#ifdef CONFIG_IFXFMAC_PCIE_BARWIN_SZ
	u32 value;
	unsigned long flags;

	raw_spin_lock_irqsave(&pcie_lock, flags);
	if ((address - devinfo->tcm) >= devinfo->bar1_size) {
		pci_write_config_dword(devinfo->pdev, BCMA_PCI_BAR1_WIN,
				       devinfo->bar1_size);
		address = address - devinfo->bar1_size;
	}
	value = ioread32(address);
	pci_write_config_dword(devinfo->pdev, BCMA_PCI_BAR1_WIN, 0x0);
	raw_spin_unlock_irqrestore(&pcie_lock, flags);

	return value;
#else
	if ((address - devinfo->tcm) >= devinfo->bar1_size) {
		ifxf_err(bus, "mem_offset:%d exceeds device size=%ld\n",
			  mem_offset, devinfo->bar1_size);
		return -EINVAL;
	}

	return (ioread32(address));
#endif /* CONFIG_IFXFMAC_PCIE_BARWIN_SZ */
}


static void
ifxf_pcie_write_ram32(struct ifxf_pciedev_info *devinfo, u32 mem_offset,
		       u32 value)
{
	struct pci_dev *pdev = devinfo->pdev;
	struct ifxf_bus *bus = dev_get_drvdata(&pdev->dev);
	void __iomem *address = devinfo->tcm + devinfo->ci->rambase
		+ mem_offset;
#ifdef CONFIG_IFXFMAC_PCIE_BARWIN_SZ
	unsigned long flags;

	raw_spin_lock_irqsave(&pcie_lock, flags);
	if ((address - devinfo->tcm) >= devinfo->bar1_size) {
		pci_write_config_dword(devinfo->pdev, BCMA_PCI_BAR1_WIN,
				       devinfo->bar1_size);
		address = address - devinfo->bar1_size;
	}
	iowrite32(value, address);
	pci_write_config_dword(devinfo->pdev, BCMA_PCI_BAR1_WIN, 0x0);
	raw_spin_unlock_irqrestore(&pcie_lock, flags);
#else
	if ((address - devinfo->tcm) >= devinfo->bar1_size) {
		ifxf_err(bus, "mem_offset:%d exceeds device size=%ld\n",
			  mem_offset, devinfo->bar1_size);
		return;
	}

	iowrite32(value, address);
#endif /* CONFIG_IFXFMAC_PCIE_BARWIN_SZ */
}


static void
ifxf_pcie_copy_mem_todev(struct ifxf_pciedev_info *devinfo, u32 mem_offset,
			  void *srcaddr, u32 len)
{
	struct pci_dev *pdev = devinfo->pdev;
	struct ifxf_bus *bus = dev_get_drvdata(&pdev->dev);
	void __iomem *address = devinfo->tcm + mem_offset;
	__le32 *src32;
	__le16 *src16;
	u8 *src8;
#ifdef CONFIG_IFXFMAC_PCIE_BARWIN_SZ
	unsigned long flags;
#endif /* CONFIG_IFXFMAC_PCIE_BARWIN_SZ */

	if (((ulong)address & 4) || ((ulong)srcaddr & 4) || (len & 4)) {
		if (((ulong)address & 2) || ((ulong)srcaddr & 2) || (len & 2)) {
			src8 = (u8 *)srcaddr;
			while (len) {
#ifdef CONFIG_IFXFMAC_PCIE_BARWIN_SZ
				raw_spin_lock_irqsave(&pcie_lock, flags);
				if ((address - devinfo->tcm) >=
				    devinfo->bar1_size) {
					pci_write_config_dword
						(devinfo->pdev,
						 BCMA_PCI_BAR1_WIN,
						 devinfo->bar1_size);
					address = address -
						devinfo->bar1_size;
				} else
#endif /* CONFIG_IFXFMAC_PCIE_BARWIN_SZ */
				if ((address - devinfo->tcm) >=
				     devinfo->bar1_size) {
					ifxf_err(bus,
						  "mem_offset:%d exceeds device size=%ld\n",
						  mem_offset, devinfo->bar1_size);
					return;
				}
				iowrite8(*src8, address);
#ifdef CONFIG_IFXFMAC_PCIE_BARWIN_SZ
				raw_spin_unlock_irqrestore(&pcie_lock, flags);
#endif /* CONFIG_IFXFMAC_PCIE_BARWIN_SZ */
				address++;
				src8++;
				len--;
			}
		} else {
			len = len / 2;
			src16 = (__le16 *)srcaddr;
			while (len) {
#ifdef CONFIG_IFXFMAC_PCIE_BARWIN_SZ
				raw_spin_lock_irqsave(&pcie_lock, flags);
				if ((address - devinfo->tcm) >=
					devinfo->bar1_size) {
					pci_write_config_dword
						(devinfo->pdev,
						BCMA_PCI_BAR1_WIN,
						devinfo->bar1_size);
					address = address -
						devinfo->bar1_size;
				} else
#endif /* CONFIG_IFXFMAC_PCIE_BARWIN_SZ */
				if ((address - devinfo->tcm) >=
				     devinfo->bar1_size) {
					ifxf_err(bus,
						  "mem_offset:%d exceeds device size=%ld\n",
						  mem_offset, devinfo->bar1_size);
					return;
				}
				iowrite16(le16_to_cpu(*src16), address);
#ifdef CONFIG_IFXFMAC_PCIE_BARWIN_SZ
				raw_spin_unlock_irqrestore(&pcie_lock, flags);
#endif /* CONFIG_IFXFMAC_PCIE_BARWIN_SZ */
				address += 2;
				src16++;
				len--;
			}
		}
	} else {
		len = len / 4;
		src32 = (__le32 *)srcaddr;
		while (len) {
#ifdef CONFIG_IFXFMAC_PCIE_BARWIN_SZ
			raw_spin_lock_irqsave(&pcie_lock, flags);
			if ((address - devinfo->tcm) >=
			    devinfo->bar1_size) {
				pci_write_config_dword
					(devinfo->pdev,
					 BCMA_PCI_BAR1_WIN,
					 devinfo->bar1_size);
				address = address - devinfo->bar1_size;
			} else
#endif /* CONFIG_IFXFMAC_PCIE_BARWIN_SZ */
			if ((address - devinfo->tcm) >=
				devinfo->bar1_size) {
				ifxf_err(bus,
					  "mem_offset:%d exceeds device size=%ld\n",
					  mem_offset, devinfo->bar1_size);
				return;
			}
			iowrite32(le32_to_cpu(*src32), address);
#ifdef CONFIG_IFXFMAC_PCIE_BARWIN_SZ
			raw_spin_unlock_irqrestore(&pcie_lock, flags);
#endif /* CONFIG_IFXFMAC_PCIE_BARWIN_SZ */
			address += 4;
			src32++;
			len--;
		}
	}
#ifdef CONFIG_IFXFMAC_PCIE_BARWIN_SZ
	pci_write_config_dword(devinfo->pdev, BCMA_PCI_BAR1_WIN, 0x0);
#endif /* CONFIG_IFXFMAC_PCIE_BARWIN_SZ */
}


static void
ifxf_pcie_copy_dev_tomem(struct ifxf_pciedev_info *devinfo, u32 mem_offset,
			  void *dstaddr, u32 len)
{
	struct pci_dev *pdev = devinfo->pdev;
	struct ifxf_bus *bus = dev_get_drvdata(&pdev->dev);
	void __iomem *address = devinfo->tcm + mem_offset;
	__le32 *dst32;
	__le16 *dst16;
	u8 *dst8;
#ifdef CONFIG_IFXFMAC_PCIE_BARWIN_SZ
	unsigned long flags;
#endif /* CONFIG_IFXFMAC_PCIE_BARWIN_SZ */

	if (((ulong)address & 4) || ((ulong)dstaddr & 4) || (len & 4)) {
		if (((ulong)address & 2) || ((ulong)dstaddr & 2) || (len & 2)) {
			dst8 = (u8 *)dstaddr;
			while (len) {
#ifdef CONFIG_IFXFMAC_PCIE_BARWIN_SZ
				raw_spin_lock_irqsave(&pcie_lock, flags);
				if ((address - devinfo->tcm) >=
				    devinfo->bar1_size) {
					pci_write_config_dword
						(devinfo->pdev,
						BCMA_PCI_BAR1_WIN,
						devinfo->bar1_size);
					address = address -
						devinfo->bar1_size;
				} else
#endif /* CONFIG_IFXFMAC_PCIE_BARWIN_SZ */
				if ((address - devinfo->tcm) >=
					devinfo->bar1_size) {
					ifxf_err(bus,
						  "mem_offset:%d exceeds device size=%ld\n",
						  mem_offset, devinfo->bar1_size);
					return;
				}
				*dst8 = ioread8(address);
#ifdef CONFIG_IFXFMAC_PCIE_BARWIN_SZ
				raw_spin_unlock_irqrestore(&pcie_lock, flags);
#endif /* CONFIG_IFXFMAC_PCIE_BARWIN_SZ */
				address++;
				dst8++;
				len--;
			}
		} else {
			len = len / 2;
			dst16 = (__le16 *)dstaddr;
			while (len) {
#ifdef CONFIG_IFXFMAC_PCIE_BARWIN_SZ
				raw_spin_lock_irqsave(&pcie_lock, flags);
				if ((address - devinfo->tcm) >=
				    devinfo->bar1_size) {
					pci_write_config_dword
						(devinfo->pdev,
						BCMA_PCI_BAR1_WIN,
						devinfo->bar1_size);
					address = address -
						devinfo->bar1_size;
				} else
#endif /* CONFIG_IFXFMAC_PCIE_BARWIN_SZ */
				if ((address - devinfo->tcm) >=
					devinfo->bar1_size) {
					ifxf_err(bus,
						  "mem_offset:%d exceeds device size=%ld\n",
						  mem_offset, devinfo->bar1_size);
					return;
				}
				*dst16 = cpu_to_le16(ioread16(address));
#ifdef CONFIG_IFXFMAC_PCIE_BARWIN_SZ
				raw_spin_unlock_irqrestore(&pcie_lock, flags);
#endif /* CONFIG_IFXFMAC_PCIE_BARWIN_SZ */
				address += 2;
				dst16++;
				len--;
			}
		}
	} else {
		len = len / 4;
		dst32 = (__le32 *)dstaddr;
		while (len) {
#ifdef CONFIG_IFXFMAC_PCIE_BARWIN_SZ
			raw_spin_lock_irqsave(&pcie_lock, flags);
			if ((address - devinfo->tcm) >=
			    devinfo->bar1_size) {
				pci_write_config_dword
					(devinfo->pdev,
					BCMA_PCI_BAR1_WIN,
					devinfo->bar1_size);
				address = address - devinfo->bar1_size;
			} else
#endif /* CONFIG_IFXFMAC_PCIE_BARWIN_SZ */
			if ((address - devinfo->tcm) >=
				devinfo->bar1_size) {
				ifxf_err(bus,
					  "mem_offset:%d exceeds device size=%ld\n",
					  mem_offset, devinfo->bar1_size);
				return;
			}
			*dst32 = cpu_to_le32(ioread32(address));
#ifdef CONFIG_IFXFMAC_PCIE_BARWIN_SZ
			raw_spin_unlock_irqrestore(&pcie_lock, flags);
#endif /* CONFIG_IFXFMAC_PCIE_BARWIN_SZ */
			address += 4;
			dst32++;
			len--;
		}
	}
#ifdef CONFIG_IFXFMAC_PCIE_BARWIN_SZ
	pci_write_config_dword(devinfo->pdev, BCMA_PCI_BAR1_WIN, 0x0);
#endif /* CONFIG_IFXFMAC_PCIE_BARWIN_SZ */
}


#define READCC32(devinfo, reg) ifxf_pcie_read_reg32(devinfo, \
		CHIPCREGOFFS(reg))
#define WRITECC32(devinfo, reg, value) ifxf_pcie_write_reg32(devinfo, \
		CHIPCREGOFFS(reg), value)


static void
ifxf_pcie_select_core(struct ifxf_pciedev_info *devinfo, u16 coreid)
{
	const struct pci_dev *pdev = devinfo->pdev;
	struct ifxf_bus *bus = dev_get_drvdata(&pdev->dev);
	struct ifxf_core *core;
	u32 bar0_win;

	core = ifxf_chip_get_core(devinfo->ci, coreid);
	if (core) {
		bar0_win = core->base;
		pci_write_config_dword(pdev, IFXF_PCIE_BAR0_WINDOW, bar0_win);
		if (pci_read_config_dword(pdev, IFXF_PCIE_BAR0_WINDOW,
					  &bar0_win) == 0) {
			if (bar0_win != core->base) {
				bar0_win = core->base;
				pci_write_config_dword(pdev,
						       IFXF_PCIE_BAR0_WINDOW,
						       bar0_win);
			}
		}
	} else {
		ifxf_err(bus, "Unsupported core selected %x\n", coreid);
	}
}


static void ifxf_pcie_reset_device(struct ifxf_pciedev_info *devinfo)
{
	struct ifxf_core *core;
	u16 cfg_offset[] = { IFXF_PCIE_CFGREG_STATUS_CMD,
			     IFXF_PCIE_CFGREG_PM_CSR,
			     IFXF_PCIE_CFGREG_MSI_CAP,
			     IFXF_PCIE_CFGREG_MSI_ADDR_L,
			     IFXF_PCIE_CFGREG_MSI_ADDR_H,
			     IFXF_PCIE_CFGREG_MSI_DATA,
#ifdef CONFIG_IFXFMAC_PCIE_BARWIN_SZ
			     BCMA_PCI_BAR1_WIN,
#endif /* CONFIG_IFXFMAC_PCIE_BARWIN_SZ */
			     IFXF_PCIE_CFGREG_LINK_STATUS_CTRL2,
			     IFXF_PCIE_CFGREG_RBAR_CTRL,
			     IFXF_PCIE_CFGREG_PML1_SUB_CTRL1,
			     IFXF_PCIE_CFGREG_REG_BAR2_CONFIG,
			     IFXF_PCIE_CFGREG_REG_BAR3_CONFIG };
	u32 i;
	u32 val;
	u32 lsc;

	if (!devinfo->ci)
		return;

	/* Disable ASPM */
	ifxf_pcie_select_core(devinfo, BCMA_CORE_PCIE2);
	pci_read_config_dword(devinfo->pdev, IFXF_PCIE_REG_LINK_STATUS_CTRL,
			      &lsc);
	val = lsc & (~IFXF_PCIE_LINK_STATUS_CTRL_ASPM_ENAB);
	pci_write_config_dword(devinfo->pdev, IFXF_PCIE_REG_LINK_STATUS_CTRL,
			       val);

	/* Watchdog reset */
	if (devinfo->ci->blhs)
		devinfo->ci->blhs->init(devinfo->ci);
	ifxf_pcie_select_core(devinfo, BCMA_CORE_CHIPCOMMON);
	WRITECC32(devinfo, watchdog, 4);
	msleep(100);
	if (devinfo->ci->blhs)
		if (devinfo->ci->blhs->post_wdreset(devinfo->ci))
			return;


	/* Restore ASPM */
	ifxf_pcie_select_core(devinfo, BCMA_CORE_PCIE2);
	pci_write_config_dword(devinfo->pdev, IFXF_PCIE_REG_LINK_STATUS_CTRL,
			       lsc);

	core = ifxf_chip_get_core(devinfo->ci, BCMA_CORE_PCIE2);
	if (core->rev <= 13) {
		for (i = 0; i < ARRAY_SIZE(cfg_offset); i++) {
			ifxf_pcie_write_reg32(devinfo,
					       IFXF_PCIE_PCIE2REG_CONFIGADDR,
					       cfg_offset[i]);
			val = ifxf_pcie_read_reg32(devinfo,
				IFXF_PCIE_PCIE2REG_CONFIGDATA);
			ifxf_dbg(PCIE, "config offset 0x%04x, value 0x%04x\n",
				  cfg_offset[i], val);
			ifxf_pcie_write_reg32(devinfo,
					       IFXF_PCIE_PCIE2REG_CONFIGDATA,
					       val);
		}
	}
}


static void ifxf_pcie_attach(struct ifxf_pciedev_info *devinfo)
{
	u32 config;

	/* BAR1 window may not be sized properly */
	ifxf_pcie_select_core(devinfo, BCMA_CORE_PCIE2);
	ifxf_pcie_write_reg32(devinfo, IFXF_PCIE_PCIE2REG_CONFIGADDR, 0x4e0);
	config = ifxf_pcie_read_reg32(devinfo, IFXF_PCIE_PCIE2REG_CONFIGDATA);
	ifxf_pcie_write_reg32(devinfo, IFXF_PCIE_PCIE2REG_CONFIGDATA, config);

	device_wakeup_enable(&devinfo->pdev->dev);
}


static int ifxf_pcie_bus_readshared(struct ifxf_pciedev_info *devinfo,
				     u32 nvram_csm)
{
	struct ifxf_bus *bus = dev_get_drvdata(&devinfo->pdev->dev);
	u32 loop_counter;
	u32 addr_le;
	u32 addr = 0;

	loop_counter = IFXF_PCIE_READ_SHARED_TIMEOUT / 50;
	while ((addr == 0 || addr == nvram_csm) && (loop_counter)) {
		msleep(50);
		addr_le = ifxf_pcie_read_ram32(devinfo,
						devinfo->ci->ramsize - 4);
		addr = le32_to_cpu(addr_le);
		loop_counter--;
	}
	if (addr == 0 || addr == nvram_csm || addr < devinfo->ci->rambase ||
	    addr >= devinfo->ci->rambase + devinfo->ci->ramsize) {
		ifxf_err(bus, "Invalid shared RAM address 0x%08x\n", addr);
		return -ENODEV;
	}
	devinfo->shared.tcm_base_address = addr;
	ifxf_dbg(PCIE, "Shared RAM addr: 0x%08x\n", addr);

	ifxf_pcie_bus_console_init(devinfo);
	return 0;
}

static int ifxf_pcie_enter_download_state(struct ifxf_pciedev_info *devinfo)
{
	struct ifxf_bus *bus = dev_get_drvdata(&devinfo->pdev->dev);
	int err = 0;

	if (devinfo->ci->blhs) {
		err = devinfo->ci->blhs->prep_fwdl(devinfo->ci);
		if (err) {
			ifxf_err(bus, "FW download preparation failed");
			return err;
		}

		if (!ifxf_pcie_bus_readshared(devinfo, 0))
			ifxf_pcie_bus_console_read(devinfo, false);
	}

	return err;
}


static int ifxf_pcie_exit_download_state(struct ifxf_pciedev_info *devinfo,
					  u32 resetintr)
{
	if (devinfo->ci->blhs) {
		ifxf_pcie_bus_console_read(devinfo, false);
		devinfo->ci->blhs->post_nvramdl(devinfo->ci);
	} else {
		if (!ifxf_chip_set_active(devinfo->ci, resetintr))
			return -EIO;
	}

	return 0;
}


static int
ifxf_pcie_send_mb_data(struct ifxf_pciedev_info *devinfo, u32 htod_mb_data)
{
	struct ifxf_pcie_shared_info *shared;
	struct ifxf_bus *bus;
	int err;
	struct ifxf_core *core;
	u32 addr;
	u32 cur_htod_mb_data;
	u32 i;

	shared = &devinfo->shared;
	bus = dev_get_drvdata(&devinfo->pdev->dev);
	if (shared->version >= IFXF_PCIE_SHARED_VERSION_6 &&
	    !devinfo->use_mailbox) {
		err = ifxf_msgbuf_tx_mbdata(bus->drvr, htod_mb_data);
		if (err) {
			ifxf_err(bus, "sendimg mbdata failed err=%d\n", err);
			return err;
		}
	} else {
		addr = shared->htod_mb_data_addr;
		cur_htod_mb_data = ifxf_pcie_read_tcm32(devinfo, addr);

		if (cur_htod_mb_data != 0)
			ifxf_dbg(PCIE, "MB transaction is already pending 0x%04x\n",
				  cur_htod_mb_data);

		i = 0;
		while (cur_htod_mb_data != 0) {
			msleep(10);
			i++;
			if (i > 100)
				return -EIO;
			cur_htod_mb_data = ifxf_pcie_read_tcm32(devinfo, addr);
		}

		ifxf_pcie_write_tcm32(devinfo, addr, htod_mb_data);
		pci_write_config_dword(devinfo->pdev, IFXF_PCIE_REG_SBMBX, 1);

		/* Send mailbox interrupt twice as a hardware workaround */
		core = ifxf_chip_get_core(devinfo->ci, BCMA_CORE_PCIE2);
		if (core->rev <= 13)
			pci_write_config_dword(devinfo->pdev,
					       IFXF_PCIE_REG_SBMBX, 1);
	}
	return 0;
}


static u32 ifxf_pcie_read_mb_data(struct ifxf_pciedev_info *devinfo)
{
	struct ifxf_pcie_shared_info *shared;
	u32 addr;
	u32 dtoh_mb_data;

	shared = &devinfo->shared;
	addr = shared->dtoh_mb_data_addr;
	dtoh_mb_data = ifxf_pcie_read_tcm32(devinfo, addr);
	ifxf_pcie_write_tcm32(devinfo, addr, 0);
	return dtoh_mb_data;
}

void ifxf_pcie_handle_mb_data(struct ifxf_bus *bus_if, u32 d2h_mb_data)
{
	struct ifxf_pciedev *buspub = bus_if->bus_priv.pcie;
	struct ifxf_pciedev_info *devinfo = buspub->devinfo;

	ifxf_dbg(INFO, "D2H_MB_DATA: 0x%04x\n", d2h_mb_data);

	if (d2h_mb_data & IFXF_D2H_DEV_DS_ENTER_REQ) {
		ifxf_dbg(INFO, "D2H_MB_DATA: DEEP SLEEP REQ\n");
		ifxf_pcie_send_mb_data(devinfo, IFXF_H2D_HOST_DS_ACK);
		ifxf_dbg(INFO, "D2H_MB_DATA: sent DEEP SLEEP ACK\n");
	}

	if (d2h_mb_data & IFXF_D2H_DEV_DS_EXIT_NOTE)
		ifxf_dbg(INFO, "D2H_MB_DATA: DEEP SLEEP EXIT\n");
	if (d2h_mb_data & IFXF_D2H_DEV_D3_ACK) {
		ifxf_dbg(INFO, "D2H_MB_DATA: D3 ACK\n");
		devinfo->mbdata_completed = true;
		wake_up(&devinfo->mbdata_resp_wait);
	}

	if (d2h_mb_data & IFXF_D2H_DEV_FWHALT) {
		ifxf_dbg(INFO, "D2H_MB_DATA: FW HALT\n");
		ifxf_fw_crashed(&devinfo->pdev->dev);
	}
}

static void ifxf_pcie_bus_console_init(struct ifxf_pciedev_info *devinfo)
{
	struct ifxf_pcie_shared_info *shared;
	struct ifxf_pcie_console *console;
	u32 buf_addr;
	u32 addr;

	shared = &devinfo->shared;
	console = &shared->console;
	addr = shared->tcm_base_address + IFXF_SHARED_CONSOLE_ADDR_OFFSET;
	console->base_addr = ifxf_pcie_read_tcm32(devinfo, addr);

	addr = console->base_addr + IFXF_CONSOLE_BUFADDR_OFFSET;
	buf_addr = ifxf_pcie_read_tcm32(devinfo, addr);
	/* reset console index when buffer address is updated */
	if (console->buf_addr != buf_addr) {
		console->buf_addr = buf_addr;
		console->read_idx = 0;
	}
	addr = console->base_addr + IFXF_CONSOLE_BUFSIZE_OFFSET;
	console->bufsize = ifxf_pcie_read_tcm32(devinfo, addr);

	ifxf_dbg(FWCON, "Console: base %x, buf %x, size %d\n",
		  console->base_addr, console->buf_addr, console->bufsize);
}

/**
 * ifxf_pcie_bus_console_read - reads firmware messages
 *
 * @devinfo: pointer to the device data structure
 * @error: specifies if error has occurred (prints messages unconditionally)
 */
static void ifxf_pcie_bus_console_read(struct ifxf_pciedev_info *devinfo,
					bool error)
{
	struct pci_dev *pdev = devinfo->pdev;
	struct ifxf_bus *bus = dev_get_drvdata(&pdev->dev);
	struct ifxf_pcie_console *console;
	u32 addr;
	u8 ch;
	u32 newidx;

	if (!error && !IFXF_FWCON_ON())
		return;

	console = &devinfo->shared.console;
	if (!console->base_addr)
		return;
	addr = console->base_addr + IFXF_CONSOLE_WRITEIDX_OFFSET;
	newidx = ifxf_pcie_read_tcm32(devinfo, addr);
	while (newidx != console->read_idx) {
		addr = console->buf_addr + console->read_idx;
		ch = ifxf_pcie_read_tcm8(devinfo, addr);
		console->read_idx++;
		if (console->read_idx == console->bufsize)
			console->read_idx = 0;
		if (ch == '\r')
			continue;
		console->log_str[console->log_idx] = ch;
		console->log_idx++;
		if ((ch != '\n') &&
		    (console->log_idx == (sizeof(console->log_str) - 2))) {
			ch = '\n';
			console->log_str[console->log_idx] = ch;
			console->log_idx++;
		}
		if (ch == '\n') {
			console->log_str[console->log_idx] = 0;
			if (error)
				__ifxf_err(bus, __func__, "CONSOLE: %s",
					    console->log_str);
			else
				pr_debug("CONSOLE: %s", console->log_str);
			console->log_idx = 0;
		}
	}
}


static void ifxf_pcie_intr_disable(struct ifxf_pciedev_info *devinfo)
{
	ifxf_pcie_write_reg32(devinfo, devinfo->reginfo->mailboxmask, 0);
}


static void ifxf_pcie_intr_enable(struct ifxf_pciedev_info *devinfo)
{
	ifxf_pcie_write_reg32(devinfo, devinfo->reginfo->mailboxmask,
			       devinfo->reginfo->int_d2h_db |
			       devinfo->reginfo->int_fn0);
}

static void ifxf_pcie_hostready(struct ifxf_pciedev_info *devinfo)
{
	if (devinfo->shared.flags & IFXF_PCIE_SHARED_HOSTRDY_DB1)
		ifxf_pcie_write_reg32(devinfo,
				       devinfo->reginfo->h2d_mailbox_1, 1);
}

static irqreturn_t ifxf_pcie_quick_check_isr(int irq, void *arg)
{
	struct ifxf_pciedev_info *devinfo = (struct ifxf_pciedev_info *)arg;

	if (ifxf_pcie_read_reg32(devinfo, devinfo->reginfo->mailboxint)) {
		ifxf_pcie_intr_disable(devinfo);
		ifxf_dbg(PCIE, "Enter\n");
		return IRQ_WAKE_THREAD;
	}
	return IRQ_NONE;
}


static irqreturn_t ifxf_pcie_isr_thread(int irq, void *arg)
{
	struct ifxf_pciedev_info *devinfo = (struct ifxf_pciedev_info *)arg;
	u32 status;
	u32 d2h_mbdata;
	struct pci_dev *pdev = devinfo->pdev;
	struct ifxf_bus *bus = dev_get_drvdata(&pdev->dev);

	devinfo->in_irq = true;
	status = ifxf_pcie_read_reg32(devinfo, devinfo->reginfo->mailboxint);
	ifxf_dbg(PCIE, "Enter %x\n", status);
	if (status) {
		ifxf_pcie_write_reg32(devinfo, devinfo->reginfo->mailboxint,
				       status);
		if (status & devinfo->reginfo->int_fn0) {
			d2h_mbdata = ifxf_pcie_read_mb_data(devinfo);
			ifxf_pcie_handle_mb_data(bus, d2h_mbdata);
		}
		if (status & devinfo->reginfo->int_d2h_db) {
			if (devinfo->state == IFXFMAC_PCIE_STATE_UP)
				ifxf_proto_msgbuf_rx_trigger(
							&devinfo->pdev->dev);
		}
	}
	ifxf_pcie_bus_console_read(devinfo, false);
	if (devinfo->state == IFXFMAC_PCIE_STATE_UP)
		ifxf_pcie_intr_enable(devinfo);
	devinfo->in_irq = false;
	return IRQ_HANDLED;
}


static int ifxf_pcie_request_irq(struct ifxf_pciedev_info *devinfo)
{
	struct pci_dev *pdev = devinfo->pdev;
	struct ifxf_bus *bus = dev_get_drvdata(&pdev->dev);

	ifxf_pcie_intr_disable(devinfo);

	ifxf_dbg(PCIE, "Enter\n");

	pci_enable_msi(pdev);
	if (request_threaded_irq(pdev->irq, ifxf_pcie_quick_check_isr,
				 ifxf_pcie_isr_thread, IRQF_SHARED,
				 "ifxf_pcie_intr", devinfo)) {
		pci_disable_msi(pdev);
		ifxf_err(bus, "Failed to request IRQ %d\n", pdev->irq);
		return -EIO;
	}
	devinfo->irq_allocated = true;
	return 0;
}


static void ifxf_pcie_release_irq(struct ifxf_pciedev_info *devinfo)
{
	struct pci_dev *pdev = devinfo->pdev;
	struct ifxf_bus *bus = dev_get_drvdata(&pdev->dev);
	u32 status;
	u32 count;

	if (!devinfo->irq_allocated)
		return;

	ifxf_pcie_intr_disable(devinfo);
	free_irq(pdev->irq, devinfo);
	pci_disable_msi(pdev);

	msleep(50);
	count = 0;
	while ((devinfo->in_irq) && (count < 20)) {
		msleep(50);
		count++;
	}
	if (devinfo->in_irq)
		ifxf_err(bus, "Still in IRQ (processing) !!!\n");

	status = ifxf_pcie_read_reg32(devinfo, devinfo->reginfo->mailboxint);
	ifxf_pcie_write_reg32(devinfo, devinfo->reginfo->mailboxint, status);

	devinfo->irq_allocated = false;
}


static int ifxf_pcie_ring_mb_write_rptr(void *ctx)
{
	struct ifxf_pcie_ringbuf *ring = (struct ifxf_pcie_ringbuf *)ctx;
	struct ifxf_pciedev_info *devinfo = ring->devinfo;
	struct ifxf_commonring *commonring = &ring->commonring;

	if (devinfo->state != IFXFMAC_PCIE_STATE_UP)
		return -EIO;

	ifxf_dbg(PCIE, "W r_ptr %d (%d), ring %d\n", commonring->r_ptr,
		  commonring->w_ptr, ring->id);

	devinfo->write_ptr(devinfo, ring->r_idx_addr, commonring->r_ptr);

	return 0;
}


static int ifxf_pcie_ring_mb_write_wptr(void *ctx)
{
	struct ifxf_pcie_ringbuf *ring = (struct ifxf_pcie_ringbuf *)ctx;
	struct ifxf_pciedev_info *devinfo = ring->devinfo;
	struct ifxf_commonring *commonring = &ring->commonring;

	if (devinfo->state != IFXFMAC_PCIE_STATE_UP)
		return -EIO;

	ifxf_dbg(PCIE, "W w_ptr %d (%d), ring %d\n", commonring->w_ptr,
		  commonring->r_ptr, ring->id);

	devinfo->write_ptr(devinfo, ring->w_idx_addr, commonring->w_ptr);

	return 0;
}


static int ifxf_pcie_ring_mb_ring_bell(void *ctx)
{
	struct ifxf_pcie_ringbuf *ring = (struct ifxf_pcie_ringbuf *)ctx;
	struct ifxf_pciedev_info *devinfo = ring->devinfo;

	if (devinfo->state != IFXFMAC_PCIE_STATE_UP)
		return -EIO;

	ifxf_dbg(PCIE, "RING !\n");
	/* Any arbitrary value will do, lets use 1 */
	ifxf_pcie_write_reg32(devinfo, devinfo->reginfo->h2d_mailbox_0, 1);

	return 0;
}


static int ifxf_pcie_ring_mb_update_rptr(void *ctx)
{
	struct ifxf_pcie_ringbuf *ring = (struct ifxf_pcie_ringbuf *)ctx;
	struct ifxf_pciedev_info *devinfo = ring->devinfo;
	struct ifxf_commonring *commonring = &ring->commonring;

	if (devinfo->state != IFXFMAC_PCIE_STATE_UP)
		return -EIO;

	commonring->r_ptr = devinfo->read_ptr(devinfo, ring->r_idx_addr);

	ifxf_dbg(PCIE, "R r_ptr %d (%d), ring %d\n", commonring->r_ptr,
		  commonring->w_ptr, ring->id);

	return 0;
}


static int ifxf_pcie_ring_mb_update_wptr(void *ctx)
{
	struct ifxf_pcie_ringbuf *ring = (struct ifxf_pcie_ringbuf *)ctx;
	struct ifxf_pciedev_info *devinfo = ring->devinfo;
	struct ifxf_commonring *commonring = &ring->commonring;

	if (devinfo->state != IFXFMAC_PCIE_STATE_UP)
		return -EIO;

	commonring->w_ptr = devinfo->read_ptr(devinfo, ring->w_idx_addr);

	ifxf_dbg(PCIE, "R w_ptr %d (%d), ring %d\n", commonring->w_ptr,
		  commonring->r_ptr, ring->id);

	return 0;
}


static void *
ifxf_pcie_init_dmabuffer_for_device(struct ifxf_pciedev_info *devinfo,
				     u32 size, u32 tcm_dma_phys_addr,
				     dma_addr_t *dma_handle)
{
	void *ring;
	u64 address;

	ring = dma_alloc_coherent(&devinfo->pdev->dev, size, dma_handle,
				  GFP_KERNEL);
	if (!ring)
		return NULL;

	address = (u64)*dma_handle;
	ifxf_pcie_write_tcm32(devinfo, tcm_dma_phys_addr,
			       address & 0xffffffff);
	ifxf_pcie_write_tcm32(devinfo, tcm_dma_phys_addr + 4, address >> 32);

	return (ring);
}


static struct ifxf_pcie_ringbuf *
ifxf_pcie_alloc_dma_and_ring(struct ifxf_pciedev_info *devinfo, u32 ring_id,
			      u32 tcm_ring_phys_addr)
{
	void *dma_buf;
	dma_addr_t dma_handle;
	struct ifxf_pcie_ringbuf *ring;
	u32 size;
	u32 addr;
	const u32 *ring_itemsize_array;

	if (devinfo->shared.version < IFXF_PCIE_SHARED_VERSION_7)
		ring_itemsize_array = ifxf_ring_itemsize_pre_v7;
	else
		ring_itemsize_array = ifxf_ring_itemsize;

	size = ifxf_ring_max_item[ring_id] * ring_itemsize_array[ring_id];
	dma_buf = ifxf_pcie_init_dmabuffer_for_device(devinfo, size,
			tcm_ring_phys_addr + IFXF_RING_MEM_BASE_ADDR_OFFSET,
			&dma_handle);
	if (!dma_buf)
		return NULL;

	addr = tcm_ring_phys_addr + IFXF_RING_MAX_ITEM_OFFSET;
	ifxf_pcie_write_tcm16(devinfo, addr, ifxf_ring_max_item[ring_id]);
	addr = tcm_ring_phys_addr + IFXF_RING_LEN_ITEMS_OFFSET;
	ifxf_pcie_write_tcm16(devinfo, addr, ring_itemsize_array[ring_id]);

	ring = kzalloc(sizeof(*ring), GFP_KERNEL);
	if (!ring) {
		dma_free_coherent(&devinfo->pdev->dev, size, dma_buf,
				  dma_handle);
		return NULL;
	}
	ifxf_commonring_config(&ring->commonring, ifxf_ring_max_item[ring_id],
				ring_itemsize_array[ring_id], dma_buf);
	ring->dma_handle = dma_handle;
	ring->devinfo = devinfo;
	ifxf_commonring_register_cb(&ring->commonring,
				     ifxf_pcie_ring_mb_ring_bell,
				     ifxf_pcie_ring_mb_update_rptr,
				     ifxf_pcie_ring_mb_update_wptr,
				     ifxf_pcie_ring_mb_write_rptr,
				     ifxf_pcie_ring_mb_write_wptr, ring);

	return (ring);
}


static void ifxf_pcie_release_ringbuffer(struct device *dev,
					  struct ifxf_pcie_ringbuf *ring)
{
	void *dma_buf;
	u32 size;

	if (!ring)
		return;

	dma_buf = ring->commonring.buf_addr;
	if (dma_buf) {
		size = ring->commonring.depth * ring->commonring.item_len;
		dma_free_coherent(dev, size, dma_buf, ring->dma_handle);
	}
	kfree(ring);
}


static void ifxf_pcie_release_ringbuffers(struct ifxf_pciedev_info *devinfo)
{
	u32 i;

	for (i = 0; i < IFXF_NROF_COMMON_MSGRINGS; i++) {
		ifxf_pcie_release_ringbuffer(&devinfo->pdev->dev,
					      devinfo->shared.commonrings[i]);
		devinfo->shared.commonrings[i] = NULL;
	}
	kfree(devinfo->shared.flowrings);
	devinfo->shared.flowrings = NULL;
	if (devinfo->idxbuf) {
		dma_free_coherent(&devinfo->pdev->dev,
				  devinfo->idxbuf_sz,
				  devinfo->idxbuf,
				  devinfo->idxbuf_dmahandle);
		devinfo->idxbuf = NULL;
	}
}


static int ifxf_pcie_init_ringbuffers(struct ifxf_pciedev_info *devinfo)
{
	struct ifxf_bus *bus = dev_get_drvdata(&devinfo->pdev->dev);
	struct ifxf_pcie_ringbuf *ring;
	struct ifxf_pcie_ringbuf *rings;
	u32 d2h_w_idx_ptr;
	u32 d2h_r_idx_ptr;
	u32 h2d_w_idx_ptr;
	u32 h2d_r_idx_ptr;
	u32 ring_mem_ptr;
	u32 i;
	u64 address;
	u32 bufsz;
	u8 idx_offset;
	struct ifxf_pcie_dhi_ringinfo ringinfo;
	u16 max_flowrings;
	u16 max_submissionrings;
	u16 max_completionrings;
#ifdef CONFIG_IFXFMAC_PCIE_BARWIN_SZ
	ifxf_pcie_copy_dev_tomem(devinfo, devinfo->shared.ring_info_addr,
				  &ringinfo, sizeof(ringinfo));
#else
	memcpy_fromio(&ringinfo, devinfo->tcm + devinfo->shared.ring_info_addr,
		      sizeof(ringinfo));
#endif /* CONFIG_IFXFMAC_PCIE_BARWIN_SZ */

	if (devinfo->shared.version >= 6) {
		max_submissionrings = le16_to_cpu(ringinfo.max_submissionrings);
		max_flowrings = le16_to_cpu(ringinfo.max_flowrings);
		max_completionrings = le16_to_cpu(ringinfo.max_completionrings);
	} else {
		max_submissionrings = le16_to_cpu(ringinfo.max_flowrings);
		max_flowrings = max_submissionrings -
				IFXF_NROF_H2D_COMMON_MSGRINGS;
		max_completionrings = IFXF_NROF_D2H_COMMON_MSGRINGS;
	}
	if (max_flowrings > 256) {
		ifxf_err(bus, "invalid max_flowrings(%d)\n", max_flowrings);
		return -EIO;
	}

	if (devinfo->dma_idx_sz != 0) {
		bufsz = (max_submissionrings + max_completionrings) *
			devinfo->dma_idx_sz * 2;
		devinfo->idxbuf = dma_alloc_coherent(&devinfo->pdev->dev, bufsz,
						     &devinfo->idxbuf_dmahandle,
						     GFP_KERNEL);
		if (!devinfo->idxbuf)
			devinfo->dma_idx_sz = 0;
	}

	if (devinfo->dma_idx_sz == 0) {
		d2h_w_idx_ptr = le32_to_cpu(ringinfo.d2h_w_idx_ptr);
		d2h_r_idx_ptr = le32_to_cpu(ringinfo.d2h_r_idx_ptr);
		h2d_w_idx_ptr = le32_to_cpu(ringinfo.h2d_w_idx_ptr);
		h2d_r_idx_ptr = le32_to_cpu(ringinfo.h2d_r_idx_ptr);
		idx_offset = sizeof(u32);
		devinfo->write_ptr = ifxf_pcie_write_tcm16;
		devinfo->read_ptr = ifxf_pcie_read_tcm16;
		ifxf_dbg(PCIE, "Using TCM indices\n");
	} else {
		memset(devinfo->idxbuf, 0, bufsz);
		devinfo->idxbuf_sz = bufsz;
		idx_offset = devinfo->dma_idx_sz;
		devinfo->write_ptr = ifxf_pcie_write_idx;
		devinfo->read_ptr = ifxf_pcie_read_idx;

		h2d_w_idx_ptr = 0;
		address = (u64)devinfo->idxbuf_dmahandle;
		ringinfo.h2d_w_idx_hostaddr.low_addr =
			cpu_to_le32(address & 0xffffffff);
		ringinfo.h2d_w_idx_hostaddr.high_addr =
			cpu_to_le32(address >> 32);

		h2d_r_idx_ptr = h2d_w_idx_ptr +
				max_submissionrings * idx_offset;
		address += max_submissionrings * idx_offset;
		ringinfo.h2d_r_idx_hostaddr.low_addr =
			cpu_to_le32(address & 0xffffffff);
		ringinfo.h2d_r_idx_hostaddr.high_addr =
			cpu_to_le32(address >> 32);

		d2h_w_idx_ptr = h2d_r_idx_ptr +
				max_submissionrings * idx_offset;
		address += max_submissionrings * idx_offset;
		ringinfo.d2h_w_idx_hostaddr.low_addr =
			cpu_to_le32(address & 0xffffffff);
		ringinfo.d2h_w_idx_hostaddr.high_addr =
			cpu_to_le32(address >> 32);

		d2h_r_idx_ptr = d2h_w_idx_ptr +
				max_completionrings * idx_offset;
		address += max_completionrings * idx_offset;
		ringinfo.d2h_r_idx_hostaddr.low_addr =
			cpu_to_le32(address & 0xffffffff);
		ringinfo.d2h_r_idx_hostaddr.high_addr =
			cpu_to_le32(address >> 32);

#ifdef CONFIG_IFXFMAC_PCIE_BARWIN_SZ
		ifxf_pcie_copy_mem_todev(devinfo,
					  devinfo->shared.ring_info_addr,
					  &ringinfo, sizeof(ringinfo));
#else
		memcpy_toio(devinfo->tcm + devinfo->shared.ring_info_addr,
			    &ringinfo, sizeof(ringinfo));
#endif /* CONFIG_IFXFMAC_PCIE_BARWIN_SZ */
		ifxf_dbg(PCIE, "Using host memory indices\n");
	}

	ring_mem_ptr = le32_to_cpu(ringinfo.ringmem);

	for (i = 0; i < IFXF_NROF_H2D_COMMON_MSGRINGS; i++) {
		ring = ifxf_pcie_alloc_dma_and_ring(devinfo, i, ring_mem_ptr);
		if (!ring)
			goto fail;
		ring->w_idx_addr = h2d_w_idx_ptr;
		ring->r_idx_addr = h2d_r_idx_ptr;
		ring->id = i;
		devinfo->shared.commonrings[i] = ring;

		h2d_w_idx_ptr += idx_offset;
		h2d_r_idx_ptr += idx_offset;
		ring_mem_ptr += IFXF_RING_MEM_SZ;
	}

	for (i = IFXF_NROF_H2D_COMMON_MSGRINGS;
	     i < IFXF_NROF_COMMON_MSGRINGS; i++) {
		ring = ifxf_pcie_alloc_dma_and_ring(devinfo, i, ring_mem_ptr);
		if (!ring)
			goto fail;
		ring->w_idx_addr = d2h_w_idx_ptr;
		ring->r_idx_addr = d2h_r_idx_ptr;
		ring->id = i;
		devinfo->shared.commonrings[i] = ring;

		d2h_w_idx_ptr += idx_offset;
		d2h_r_idx_ptr += idx_offset;
		ring_mem_ptr += IFXF_RING_MEM_SZ;
	}

	devinfo->shared.max_flowrings = max_flowrings;
	devinfo->shared.max_submissionrings = max_submissionrings;
	devinfo->shared.max_completionrings = max_completionrings;
	rings = kcalloc(max_flowrings, sizeof(*ring), GFP_KERNEL);
	if (!rings)
		goto fail;

	ifxf_dbg(PCIE, "Nr of flowrings is %d\n", max_flowrings);

	for (i = 0; i < max_flowrings; i++) {
		ring = &rings[i];
		ring->devinfo = devinfo;
		ring->id = i + IFXF_H2D_MSGRING_FLOWRING_IDSTART;
		ifxf_commonring_register_cb(&ring->commonring,
					     ifxf_pcie_ring_mb_ring_bell,
					     ifxf_pcie_ring_mb_update_rptr,
					     ifxf_pcie_ring_mb_update_wptr,
					     ifxf_pcie_ring_mb_write_rptr,
					     ifxf_pcie_ring_mb_write_wptr,
					     ring);
		ring->w_idx_addr = h2d_w_idx_ptr;
		ring->r_idx_addr = h2d_r_idx_ptr;
		h2d_w_idx_ptr += idx_offset;
		h2d_r_idx_ptr += idx_offset;
	}
	devinfo->shared.flowrings = rings;

	return 0;

fail:
	ifxf_err(bus, "Allocating ring buffers failed\n");
	ifxf_pcie_release_ringbuffers(devinfo);
	return -ENOMEM;
}


static void
ifxf_pcie_release_scratchbuffers(struct ifxf_pciedev_info *devinfo)
{
	if (devinfo->shared.scratch)
		dma_free_coherent(&devinfo->pdev->dev,
				  IFXF_DMA_D2H_SCRATCH_BUF_LEN,
				  devinfo->shared.scratch,
				  devinfo->shared.scratch_dmahandle);
	if (devinfo->shared.ringupd)
		dma_free_coherent(&devinfo->pdev->dev,
				  IFXF_DMA_D2H_RINGUPD_BUF_LEN,
				  devinfo->shared.ringupd,
				  devinfo->shared.ringupd_dmahandle);
}

static int ifxf_pcie_init_scratchbuffers(struct ifxf_pciedev_info *devinfo)
{
	struct ifxf_bus *bus = dev_get_drvdata(&devinfo->pdev->dev);
	u64 address;
	u32 addr;

	devinfo->shared.scratch =
		dma_alloc_coherent(&devinfo->pdev->dev,
				   IFXF_DMA_D2H_SCRATCH_BUF_LEN,
				   &devinfo->shared.scratch_dmahandle,
				   GFP_KERNEL);
	if (!devinfo->shared.scratch)
		goto fail;

	addr = devinfo->shared.tcm_base_address +
	       IFXF_SHARED_DMA_SCRATCH_ADDR_OFFSET;
	address = (u64)devinfo->shared.scratch_dmahandle;
	ifxf_pcie_write_tcm32(devinfo, addr, address & 0xffffffff);
	ifxf_pcie_write_tcm32(devinfo, addr + 4, address >> 32);
	addr = devinfo->shared.tcm_base_address +
	       IFXF_SHARED_DMA_SCRATCH_LEN_OFFSET;
	ifxf_pcie_write_tcm32(devinfo, addr, IFXF_DMA_D2H_SCRATCH_BUF_LEN);

	devinfo->shared.ringupd =
		dma_alloc_coherent(&devinfo->pdev->dev,
				   IFXF_DMA_D2H_RINGUPD_BUF_LEN,
				   &devinfo->shared.ringupd_dmahandle,
				   GFP_KERNEL);
	if (!devinfo->shared.ringupd)
		goto fail;

	addr = devinfo->shared.tcm_base_address +
	       IFXF_SHARED_DMA_RINGUPD_ADDR_OFFSET;
	address = (u64)devinfo->shared.ringupd_dmahandle;
	ifxf_pcie_write_tcm32(devinfo, addr, address & 0xffffffff);
	ifxf_pcie_write_tcm32(devinfo, addr + 4, address >> 32);
	addr = devinfo->shared.tcm_base_address +
	       IFXF_SHARED_DMA_RINGUPD_LEN_OFFSET;
	ifxf_pcie_write_tcm32(devinfo, addr, IFXF_DMA_D2H_RINGUPD_BUF_LEN);
	return 0;

fail:
	ifxf_err(bus, "Allocating scratch buffers failed\n");
	ifxf_pcie_release_scratchbuffers(devinfo);
	return -ENOMEM;
}


static void ifxf_pcie_down(struct device *dev)
{
	struct ifxf_bus *bus_if = dev_get_drvdata(dev);
	struct ifxf_pciedev *pcie_bus_dev = bus_if->bus_priv.pcie;
	struct ifxf_pciedev_info *devinfo = pcie_bus_dev->devinfo;

	ifxf_pcie_fwcon_timer(devinfo, false);
}

static int ifxf_pcie_preinit(struct device *dev)
{
	struct ifxf_bus *bus_if = dev_get_drvdata(dev);
	struct ifxf_pciedev *buspub = bus_if->bus_priv.pcie;

	ifxf_dbg(PCIE, "Enter\n");

	ifxf_pcie_intr_enable(buspub->devinfo);
	ifxf_pcie_hostready(buspub->devinfo);

	return 0;
}

static int ifxf_pcie_tx(struct device *dev, struct sk_buff *skb)
{
	return 0;
}


static int ifxf_pcie_tx_ctlpkt(struct device *dev, unsigned char *msg,
				uint len)
{
	return 0;
}


static int ifxf_pcie_rx_ctlpkt(struct device *dev, unsigned char *msg,
				uint len)
{
	return 0;
}


static void ifxf_pcie_wowl_config(struct device *dev, bool enabled)
{
	struct ifxf_bus *bus_if = dev_get_drvdata(dev);
	struct ifxf_pciedev *buspub = bus_if->bus_priv.pcie;
	struct ifxf_pciedev_info *devinfo = buspub->devinfo;

	ifxf_dbg(PCIE, "Configuring WOWL, enabled=%d\n", enabled);
	devinfo->wowl_enabled = enabled;
}


static size_t ifxf_pcie_get_ramsize(struct device *dev)
{
	struct ifxf_bus *bus_if = dev_get_drvdata(dev);
	struct ifxf_pciedev *buspub = bus_if->bus_priv.pcie;
	struct ifxf_pciedev_info *devinfo = buspub->devinfo;

	return devinfo->ci->ramsize - devinfo->ci->srsize;
}


static int ifxf_pcie_get_memdump(struct device *dev, void *data, size_t len)
{
	struct ifxf_bus *bus_if = dev_get_drvdata(dev);
	struct ifxf_pciedev *buspub = bus_if->bus_priv.pcie;
	struct ifxf_pciedev_info *devinfo = buspub->devinfo;

	ifxf_dbg(PCIE, "dump at 0x%08X: len=%zu\n", devinfo->ci->rambase, len);
	ifxf_pcie_copy_dev_tomem(devinfo, devinfo->ci->rambase, data, len);
	return 0;
}

static int ifxf_pcie_get_blob(struct device *dev, const struct firmware **fw,
			       enum ifxf_blob_type type)
{
	struct ifxf_bus *bus_if = dev_get_drvdata(dev);
	struct ifxf_pciedev *buspub = bus_if->bus_priv.pcie;
	struct ifxf_pciedev_info *devinfo = buspub->devinfo;

	switch (type) {
	case IFXF_BLOB_CLM:
		*fw = devinfo->clm_fw;
		devinfo->clm_fw = NULL;
		break;
	default:
		return -ENOENT;
	}

	if (!*fw)
		return -ENOENT;

	return 0;
}

static int ifxf_pcie_reset(struct device *dev)
{
	struct ifxf_bus *bus_if = dev_get_drvdata(dev);
	struct ifxf_pciedev *buspub = bus_if->bus_priv.pcie;
	struct ifxf_pciedev_info *devinfo = buspub->devinfo;
	struct ifxf_fw_request *fwreq;
	int err;

	ifxf_pcie_intr_disable(devinfo);

	ifxf_pcie_bus_console_read(devinfo, true);

	ifxf_detach(dev);

	ifxf_pcie_release_irq(devinfo);
	ifxf_pcie_release_scratchbuffers(devinfo);
	ifxf_pcie_release_ringbuffers(devinfo);
	ifxf_pcie_reset_device(devinfo);

	fwreq = ifxf_pcie_prepare_fw_request(devinfo);
	if (!fwreq) {
		dev_err(dev, "Failed to prepare FW request\n");
		return -ENOMEM;
	}

	err = ifxf_fw_get_firmwares(dev, fwreq, ifxf_pcie_setup);
	if (err) {
		dev_err(dev, "Failed to prepare FW request\n");
		kfree(fwreq);
	}

	return err;
}

static const struct ifxf_bus_ops ifxf_pcie_bus_ops = {
	.preinit = ifxf_pcie_preinit,
	.txdata = ifxf_pcie_tx,
	.stop = ifxf_pcie_down,
	.txctl = ifxf_pcie_tx_ctlpkt,
	.rxctl = ifxf_pcie_rx_ctlpkt,
	.wowl_config = ifxf_pcie_wowl_config,
	.get_ramsize = ifxf_pcie_get_ramsize,
	.get_memdump = ifxf_pcie_get_memdump,
	.get_blob = ifxf_pcie_get_blob,
	.reset = ifxf_pcie_reset,
	.debugfs_create = ifxf_pcie_debugfs_create,
};


static void
ifxf_pcie_adjust_ramsize(struct ifxf_pciedev_info *devinfo, u8 *data,
			  u32 data_len)
{
	__le32 *field;
	u32 newsize;

	if (data_len < IFXF_RAMSIZE_OFFSET + 8)
		return;

	field = (__le32 *)&data[IFXF_RAMSIZE_OFFSET];
	if (le32_to_cpup(field) != IFXF_RAMSIZE_MAGIC)
		return;
	field++;
	newsize = le32_to_cpup(field);

	ifxf_dbg(PCIE, "Found ramsize info in FW, adjusting to 0x%x\n",
		  newsize);
	devinfo->ci->ramsize = newsize;
}


static void
ifxf_pcie_write_rand(struct ifxf_pciedev_info *devinfo, u32 nvram_csm)
{
	struct ifxf_rand_metadata rand_data;
	u8 rand_buf[IFXF_ENTROPY_HOST_LEN];
	u32 count = IFXF_ENTROPY_HOST_LEN;
	u32 address;

	address = devinfo->ci->rambase +
		  (devinfo->ci->ramsize - IFXF_NVRAM_OFFSET_TCM) -
		  ((nvram_csm & 0xffff) * IFXF_NVRAM_COMPRS_FACTOR) -
		  sizeof(rand_data);
	memset(rand_buf, 0, IFXF_ENTROPY_HOST_LEN);
	rand_data.signature = cpu_to_le32(IFXF_NVRAM_RNG_SIGNATURE);
	rand_data.count = cpu_to_le32(count);
	ifxf_pcie_copy_mem_todev(devinfo, address, &rand_data,
				  sizeof(rand_data));
	address -= count;
	get_random_bytes(rand_buf, count);
	ifxf_pcie_copy_mem_todev(devinfo, address, rand_buf, count);
}

static int
ifxf_pcie_init_share_ram_info(struct ifxf_pciedev_info *devinfo,
			       u32 sharedram_addr)
{
	struct ifxf_bus *bus = dev_get_drvdata(&devinfo->pdev->dev);
	struct ifxf_pcie_shared_info *shared;
	u32 addr;
	u32 host_cap;

	shared = &devinfo->shared;
	shared->tcm_base_address = sharedram_addr;

	shared->flags = ifxf_pcie_read_tcm32(devinfo, sharedram_addr);
	shared->version = (u8)(shared->flags & IFXF_PCIE_SHARED_VERSION_MASK);
	ifxf_dbg(PCIE, "PCIe protocol version %d\n", shared->version);
	if ((shared->version > IFXF_PCIE_MAX_SHARED_VERSION) ||
	    (shared->version < IFXF_PCIE_MIN_SHARED_VERSION)) {
		ifxf_err(bus, "Unsupported PCIE version %d\n",
			  shared->version);
		return -EINVAL;
	}

	/* check firmware support dma indicies */
	if (shared->flags & IFXF_PCIE_SHARED_DMA_INDEX) {
		if (shared->flags & IFXF_PCIE_SHARED_DMA_2B_IDX)
			devinfo->dma_idx_sz = sizeof(u16);
		else
			devinfo->dma_idx_sz = sizeof(u32);
	}

	addr = sharedram_addr + IFXF_SHARED_MAX_RXBUFPOST_OFFSET;
	shared->max_rxbufpost = ifxf_pcie_read_tcm16(devinfo, addr);
	if (shared->max_rxbufpost == 0)
		shared->max_rxbufpost = IFXF_DEF_MAX_RXBUFPOST;

	addr = sharedram_addr + IFXF_SHARED_RX_DATAOFFSET_OFFSET;
	shared->rx_dataoffset = ifxf_pcie_read_tcm32(devinfo, addr);

	addr = sharedram_addr + IFXF_SHARED_HTOD_MB_DATA_ADDR_OFFSET;
	shared->htod_mb_data_addr = ifxf_pcie_read_tcm32(devinfo, addr);

	addr = sharedram_addr + IFXF_SHARED_DTOH_MB_DATA_ADDR_OFFSET;
	shared->dtoh_mb_data_addr = ifxf_pcie_read_tcm32(devinfo, addr);

	addr = sharedram_addr + IFXF_SHARED_RING_INFO_ADDR_OFFSET;
	shared->ring_info_addr = ifxf_pcie_read_tcm32(devinfo, addr);

	if (shared->version >= IFXF_PCIE_SHARED_VERSION_6) {
		host_cap = shared->version;

		/* Disable OOB Device Wake based DeepSleep State Machine */
		host_cap |= IFXF_HOSTCAP_DS_NO_OOB_DW;

		devinfo->hostready =
			((shared->flags & IFXF_PCIE_SHARED_HOSTRDY_DB1)
			 == IFXF_PCIE_SHARED_HOSTRDY_DB1);
		if (devinfo->hostready) {
			ifxf_dbg(PCIE, "HostReady supported by dongle.\n");
			host_cap |= IFXF_HOSTCAP_H2D_ENABLE_HOSTRDY;
		}
		devinfo->use_mailbox =
			((shared->flags & IFXF_PCIE_SHARED_USE_MAILBOX)
			 == IFXF_PCIE_SHARED_USE_MAILBOX);
		devinfo->use_d0_inform = false;
		addr = sharedram_addr + IFXF_SHARED_HOST_CAP_OFFSET;

		ifxf_pcie_write_tcm32(devinfo, addr, host_cap);
	} else {
		devinfo->use_d0_inform = true;
	}

	ifxf_dbg(PCIE, "max rx buf post %d, rx dataoffset %d\n",
		  shared->max_rxbufpost, shared->rx_dataoffset);

	ifxf_pcie_bus_console_init(devinfo);
	ifxf_pcie_bus_console_read(devinfo, false);

	return 0;
}


static int ifxf_pcie_download_fw_nvram(struct ifxf_pciedev_info *devinfo,
					const struct firmware *fw, void *nvram,
					u32 nvram_len)
{
	struct ifxf_bus *bus = dev_get_drvdata(&devinfo->pdev->dev);
	struct trx_header_le *trx = (struct trx_header_le *)fw->data;
	u32 fw_size;
	u32 sharedram_addr;
	u32 sharedram_addr_written;
	u32 loop_counter;
	int err;
	u32 address;
	u32 resetintr;
	u32 nvram_lenw;
	u32 nvram_csm;

	ifxf_dbg(PCIE, "Halt ARM.\n");
	err = ifxf_pcie_enter_download_state(devinfo);
	if (err)
		return err;

	ifxf_dbg(PCIE, "Download FW %s\n", devinfo->fw_name);
	address = devinfo->ci->rambase;
	fw_size = fw->size;
	if (trx->magic == cpu_to_le32(TRX_MAGIC)) {
		address -= sizeof(struct trx_header_le);
		fw_size = le32_to_cpu(trx->len);
	}
	ifxf_pcie_copy_mem_todev(devinfo, address, (void *)fw->data, fw_size);

	resetintr = get_unaligned_le32(fw->data);
	release_firmware(fw);

	if (devinfo->ci->blhs) {
		ifxf_pcie_bus_console_read(devinfo, false);
		err = devinfo->ci->blhs->post_fwdl(devinfo->ci);
		if (err) {
			ifxf_err(bus, "FW download failed, err=%d\n", err);
			return err;
		}

		err = devinfo->ci->blhs->chk_validation(devinfo->ci);
		if (err) {
			ifxf_err(bus, "FW valication failed, err=%d\n", err);
			return err;
		}
	} else {
		/* reset last 4 bytes of RAM address. to be used for shared
		 * area. This identifies when FW is running
		 */
		ifxf_pcie_write_ram32(devinfo, devinfo->ci->ramsize - 4, 0);
	}

	if (nvram) {
		ifxf_dbg(PCIE, "Download NVRAM %s\n", devinfo->nvram_name);
		address = devinfo->ci->rambase + devinfo->ci->ramsize -
			  nvram_len;

		if (devinfo->ci->blhs)
			address -= 4;
		ifxf_pcie_copy_mem_todev(devinfo, address, nvram, nvram_len);

		/* Convert nvram_len to words to determine the length token */
		nvram_lenw = nvram_len / 4;
		/* subtract word used to store the token itself on non-blhs devices */
		if (!devinfo->ci->blhs)
			nvram_lenw -= 1;
		nvram_csm = (~nvram_lenw << 16) | (nvram_lenw & 0x0000FFFF);
		ifxf_fw_nvram_free(nvram);
	} else {
		nvram_csm = 0;
		ifxf_dbg(PCIE, "No matching NVRAM file found %s\n",
			  devinfo->nvram_name);
	}

	if (devinfo->ci->chip == CY_CC_55572_CHIP_ID) {
		/* Write the length token to the last word of RAM address */
		ifxf_pcie_write_ram32(devinfo, devinfo->ci->ramsize - 4,
				       cpu_to_le32(nvram_csm));

		/* Write random numbers to TCM for randomizing heap address */
		ifxf_pcie_write_rand(devinfo, nvram_csm);
	}

	sharedram_addr_written = ifxf_pcie_read_ram32(devinfo,
						       devinfo->ci->ramsize -
						       4);
	ifxf_dbg(PCIE, "Bring ARM in running state\n");
	err = ifxf_pcie_exit_download_state(devinfo, resetintr);
	if (err)
		return err;

	if (!ifxf_pcie_bus_readshared(devinfo, nvram_csm))
		ifxf_pcie_bus_console_read(devinfo, false);

	ifxf_dbg(PCIE, "Wait for FW init\n");
	sharedram_addr = sharedram_addr_written;
	loop_counter = IFXF_PCIE_FW_UP_TIMEOUT / 50;
	while ((sharedram_addr == sharedram_addr_written) && (loop_counter)) {
		msleep(50);
		sharedram_addr = ifxf_pcie_read_ram32(devinfo,
						       devinfo->ci->ramsize -
						       4);
		loop_counter--;
	}
	if (sharedram_addr == sharedram_addr_written) {
		ifxf_err(bus, "FW failed to initialize\n");
		return -ENODEV;
	}
	if (sharedram_addr < devinfo->ci->rambase ||
	    sharedram_addr >= devinfo->ci->rambase + devinfo->ci->ramsize) {
		ifxf_err(bus, "Invalid shared RAM address 0x%08x\n",
			  sharedram_addr);
		return -ENODEV;
	}
	ifxf_dbg(PCIE, "Shared RAM addr: 0x%08x\n", sharedram_addr);

	return (ifxf_pcie_init_share_ram_info(devinfo, sharedram_addr));
}


static int ifxf_pcie_get_resource(struct ifxf_pciedev_info *devinfo)
{
	struct pci_dev *pdev = devinfo->pdev;
	struct ifxf_bus *bus = dev_get_drvdata(&pdev->dev);
	int err;
	phys_addr_t  bar0_addr, bar1_addr;
	ulong bar1_size;

	err = pci_enable_device(pdev);
	if (err) {
		ifxf_err(bus, "pci_enable_device failed err=%d\n", err);
		return err;
	}

	pci_set_master(pdev);

	/* Bar-0 mapped address */
	bar0_addr = pci_resource_start(pdev, 0);
	/* Bar-1 mapped address */
	bar1_addr = pci_resource_start(pdev, 2);
	/* read Bar-1 mapped memory range */
	bar1_size = pci_resource_len(pdev, 2);
	if ((bar1_size == 0) || (bar1_addr == 0)) {
		ifxf_err(bus, "BAR1 Not enabled, device size=%ld, addr=%#016llx\n",
			  bar1_size, (unsigned long long)bar1_addr);
		return -EINVAL;
	}

	devinfo->regs = ioremap(bar0_addr, IFXF_PCIE_REG_MAP_SIZE);
	devinfo->tcm = ioremap(bar1_addr, bar1_size);
	devinfo->bar1_size = bar1_size;

	if (!devinfo->regs || !devinfo->tcm) {
		ifxf_err(bus, "ioremap() failed (%p,%p)\n", devinfo->regs,
			  devinfo->tcm);
		return -EINVAL;
	}
	ifxf_dbg(PCIE, "Phys addr : reg space = %p base addr %#016llx\n",
		  devinfo->regs, (unsigned long long)bar0_addr);
	ifxf_dbg(PCIE, "Phys addr : mem space = %p base addr %#016llx size 0x%x\n",
		  devinfo->tcm, (unsigned long long)bar1_addr,
		  (unsigned int)bar1_size);

	return 0;
}


static void ifxf_pcie_release_resource(struct ifxf_pciedev_info *devinfo)
{
	if (devinfo->tcm)
		iounmap(devinfo->tcm);
	if (devinfo->regs)
		iounmap(devinfo->regs);

	pci_disable_device(devinfo->pdev);
}

static u32 ifxf_pcie_buscore_blhs_read(void *ctx, u32 reg_offset)
{
	struct ifxf_pciedev_info *devinfo = (struct ifxf_pciedev_info *)ctx;

	ifxf_pcie_select_core(devinfo, BCMA_CORE_PCIE2);
	return ifxf_pcie_read_reg32(devinfo, reg_offset);
}

static void ifxf_pcie_buscore_blhs_write(void *ctx, u32 reg_offset, u32 value)
{
	struct ifxf_pciedev_info *devinfo = (struct ifxf_pciedev_info *)ctx;

	ifxf_pcie_select_core(devinfo, BCMA_CORE_PCIE2);
	ifxf_pcie_write_reg32(devinfo, reg_offset, value);
}

static u32 ifxf_pcie_buscore_prep_addr(const struct pci_dev *pdev, u32 addr)
{
	u32 ret_addr;

	ret_addr = addr & (IFXF_PCIE_BAR0_REG_SIZE - 1);
	addr &= ~(IFXF_PCIE_BAR0_REG_SIZE - 1);
	pci_write_config_dword(pdev, IFXF_PCIE_BAR0_WINDOW, addr);

	return ret_addr;
}


static u32 ifxf_pcie_buscore_read32(void *ctx, u32 addr)
{
	struct ifxf_pciedev_info *devinfo = (struct ifxf_pciedev_info *)ctx;

	addr = ifxf_pcie_buscore_prep_addr(devinfo->pdev, addr);
	return ifxf_pcie_read_reg32(devinfo, addr);
}


static void ifxf_pcie_buscore_write32(void *ctx, u32 addr, u32 value)
{
	struct ifxf_pciedev_info *devinfo = (struct ifxf_pciedev_info *)ctx;

	addr = ifxf_pcie_buscore_prep_addr(devinfo->pdev, addr);
	ifxf_pcie_write_reg32(devinfo, addr, value);
}


static int ifxf_pcie_buscoreprep(void *ctx)
{
	return ifxf_pcie_get_resource(ctx);
}


static int ifxf_pcie_buscore_reset(void *ctx, struct ifxf_chip *chip)
{
	struct ifxf_pciedev_info *devinfo = (struct ifxf_pciedev_info *)ctx;
	struct ifxf_core *core;
	u32 val, reg;

	devinfo->ci = chip;
	ifxf_pcie_reset_device(devinfo);

	/* reginfo is not ready yet */
	core = ifxf_chip_get_core(chip, BCMA_CORE_PCIE2);
	if (core->rev >= 64)
		reg = IFXF_PCIE_64_PCIE2REG_MAILBOXINT;
	else
		reg = IFXF_PCIE_PCIE2REG_MAILBOXINT;

	val = ifxf_pcie_read_reg32(devinfo, reg);
	if (val != 0xffffffff)
		ifxf_pcie_write_reg32(devinfo, reg, val);

	return 0;
}


static void ifxf_pcie_buscore_activate(void *ctx, struct ifxf_chip *chip,
					u32 rstvec)
{
	struct ifxf_pciedev_info *devinfo = (struct ifxf_pciedev_info *)ctx;

	ifxf_pcie_write_tcm32(devinfo, 0, rstvec);
}


static int
ifxf_pcie_buscore_sec_attach(void *ctx, struct ifxf_blhs **blhs, struct ifxf_ccsec **ccsec,
			      u32 flag, uint timeout, uint interval)
{
	struct ifxf_pciedev_info *devinfo = (struct ifxf_pciedev_info *)ctx;
	struct ifxf_bus *bus = dev_get_drvdata(&devinfo->pdev->dev);
	struct ifxf_blhs *blhsh;
	u32 regdata;
	u32 pcie_enum;
	u32 addr;

	if (devinfo->pdev->vendor != CY_PCIE_VENDOR_ID_CYPRESS)
		return 0;

	pci_read_config_dword(devinfo->pdev, IFXF_PCIE_CFGREG_REVID, &regdata);
	if (regdata & IFXF_PCIE_CFGREG_REVID_SECURE_MODE) {
		blhsh = kzalloc(sizeof(*blhsh), GFP_KERNEL);
		if (!blhsh)
			return -ENOMEM;

		blhsh->d2h = IFXF_PCIE_PCIE2REG_DAR_D2H_MSG_0;
		blhsh->h2d = IFXF_PCIE_PCIE2REG_DAR_H2D_MSG_0;
		blhsh->read = ifxf_pcie_buscore_blhs_read;
		blhsh->write = ifxf_pcie_buscore_blhs_write;

		/* Host indication for bootloarder to start the init */
		if (devinfo->pdev->device == CY_PCIE_55572_DEVICE_ID)
			pcie_enum = IFXF_CYW55572_PCIE_BAR0_PCIE_ENUM_OFFSET;
		else
			pcie_enum = IFXF_PCIE_BAR0_PCIE_ENUM_OFFSET;

		pci_read_config_dword(devinfo->pdev, PCI_BASE_ADDRESS_0,
				      &regdata);
		addr = regdata + pcie_enum + blhsh->h2d;
		ifxf_pcie_buscore_write32(ctx, addr, 0);

		addr = regdata + pcie_enum + blhsh->d2h;
		SPINWAIT_MS((ifxf_pcie_buscore_read32(ctx, addr) & flag) == 0,
			    timeout, interval);
		regdata = ifxf_pcie_buscore_read32(ctx, addr);
		if (!(regdata & flag)) {
			ifxf_err(bus, "Timeout waiting for bootloader ready\n");
			kfree(blhsh);
			return -EPERM;
		}
		*blhs = blhsh;
	}

	return 0;
}

static const struct ifxf_buscore_ops ifxf_pcie_buscore_ops = {
	.prepare = ifxf_pcie_buscoreprep,
	.reset = ifxf_pcie_buscore_reset,
	.activate = ifxf_pcie_buscore_activate,
	.read32 = ifxf_pcie_buscore_read32,
	.write32 = ifxf_pcie_buscore_write32,
	.sec_attach = ifxf_pcie_buscore_sec_attach,
};

#define IFXF_OTP_SYS_VENDOR	0x15
#define IFXF_OTP_IFX_CIS	0x80

#define IFXF_OTP_VENDOR_HDR	0x00000008

static int
ifxf_pcie_parse_otp_sys_vendor(struct ifxf_pciedev_info *devinfo,
				u8 *data, size_t size)
{
	int idx = 4;
	const char *chip_params;
	const char *board_params;
	const char *p;

	/* 4-byte header and two empty strings */
	if (size < 6)
		return -EINVAL;

	if (get_unaligned_le32(data) != IFXF_OTP_VENDOR_HDR)
		return -EINVAL;

	chip_params = &data[idx];

	/* Skip first string, including terminator */
	idx += strnlen(chip_params, size - idx) + 1;
	if (idx >= size)
		return -EINVAL;

	board_params = &data[idx];

	/* Skip to terminator of second string */
	idx += strnlen(board_params, size - idx);
	if (idx >= size)
		return -EINVAL;

	/* At this point both strings are guaranteed NUL-terminated */
	ifxf_dbg(PCIE, "OTP: chip_params='%s' board_params='%s'\n",
		  chip_params, board_params);

	p = skip_spaces(board_params);
	while (*p) {
		char tag = *p++;
		const char *end;
		size_t len;

		if (*p++ != '=') /* implicit NUL check */
			return -EINVAL;

		/* *p might be NUL here, if so end == p and len == 0 */
		end = strchrnul(p, ' ');
		len = end - p;

		/* leave 1 byte for NUL in destination string */
		if (len > (IFXF_OTP_MAX_PARAM_LEN - 1))
			return -EINVAL;

		/* Copy len characters plus a NUL terminator */
		switch (tag) {
		case 'M':
			strscpy(devinfo->otp.module, p, len + 1);
			break;
		case 'V':
			strscpy(devinfo->otp.vendor, p, len + 1);
			break;
		case 'm':
			strscpy(devinfo->otp.version, p, len + 1);
			break;
		}

		/* Skip to next arg, if any */
		p = skip_spaces(end);
	}

	ifxf_dbg(PCIE, "OTP: module=%s vendor=%s version=%s\n",
		  devinfo->otp.module, devinfo->otp.vendor,
		  devinfo->otp.version);

	if (!devinfo->otp.module[0] ||
	    !devinfo->otp.vendor[0] ||
	    !devinfo->otp.version[0])
		return -EINVAL;

	devinfo->otp.valid = true;
	return 0;
}

static int
ifxf_pcie_parse_otp(struct ifxf_pciedev_info *devinfo, u8 *otp, size_t size)
{
	int p = 0;
	int ret = -EINVAL;

	ifxf_dbg(PCIE, "parse_otp size=%zd\n", size);

	while (p < (size - 1)) {
		u8 type = otp[p];
		u8 length = otp[p + 1];

		if (type == 0)
			break;

		if ((p + 2 + length) > size)
			break;

		switch (type) {
		case IFXF_OTP_SYS_VENDOR:
			ifxf_dbg(PCIE, "OTP @ 0x%x (%d): SYS_VENDOR\n",
				  p, length);
			ret = ifxf_pcie_parse_otp_sys_vendor(devinfo,
							      &otp[p + 2],
							      length);
			break;
		case IFXF_OTP_IFX_CIS:
			ifxf_dbg(PCIE, "OTP @ 0x%x (%d): IFX_CIS\n",
				  p, length);
			break;
		default:
			ifxf_dbg(PCIE, "OTP @ 0x%x (%d): Unknown type 0x%x\n",
				  p, length, type);
			break;
		}

		p += 2 + length;
	}

	return ret;
}

static int ifxf_pcie_read_otp(struct ifxf_pciedev_info *devinfo)
{
	const struct pci_dev *pdev = devinfo->pdev;
	struct ifxf_bus *bus = dev_get_drvdata(&pdev->dev);
	u32 coreid, base, words, idx, sromctl;
	u16 *otp;
	struct ifxf_core *core;
	int ret;

	switch (devinfo->ci->chip) {
	default:
		/* OTP not supported on this chip */
		return 0;
	}

	core = ifxf_chip_get_core(devinfo->ci, coreid);
	if (!core) {
		ifxf_err(bus, "No OTP core\n");
		return -ENODEV;
	}

	if (coreid == BCMA_CORE_CHIPCOMMON) {
		/* Chips with OTP accessed via ChipCommon need additional
		 * handling to access the OTP
		 */
		ifxf_pcie_select_core(devinfo, coreid);
		sromctl = READCC32(devinfo, sromcontrol);

		if (!(sromctl & BCMA_CC_SROM_CONTROL_OTP_PRESENT)) {
			/* Chip lacks OTP, try without it... */
			ifxf_err(bus,
				  "OTP unavailable, using default firmware\n");
			return 0;
		}

		/* Map OTP to shadow area */
		WRITECC32(devinfo, sromcontrol,
			  sromctl | BCMA_CC_SROM_CONTROL_OTPSEL);
	}

	otp = kcalloc(words, sizeof(u16), GFP_KERNEL);
	if (!otp)
		return -ENOMEM;

	/* Map bus window to SROM/OTP shadow area in core */
	base = ifxf_pcie_buscore_prep_addr(devinfo->pdev, base + core->base);

	ifxf_dbg(PCIE, "OTP data:\n");
	for (idx = 0; idx < words; idx++) {
		otp[idx] = ifxf_pcie_read_reg16(devinfo, base + 2 * idx);
		ifxf_dbg(PCIE, "[%8x] 0x%04x\n", base + 2 * idx, otp[idx]);
	}

	if (coreid == BCMA_CORE_CHIPCOMMON) {
		ifxf_pcie_select_core(devinfo, coreid);
		WRITECC32(devinfo, sromcontrol, sromctl);
	}

	ret = ifxf_pcie_parse_otp(devinfo, (u8 *)otp, 2 * words);
	kfree(otp);

	return ret;
}

#define IFXF_PCIE_FW_CODE	0
#define IFXF_PCIE_FW_NVRAM	1
#define IFXF_PCIE_FW_CLM	2

static void ifxf_pcie_setup(struct device *dev, int ret,
			     struct ifxf_fw_request *fwreq)
{
	const struct firmware *fw;
	void *nvram;
	struct ifxf_bus *bus;
	struct ifxf_pciedev *pcie_bus_dev;
	struct ifxf_pciedev_info *devinfo;
	struct ifxf_commonring **flowrings;
	u32 i, nvram_len;

	bus = dev_get_drvdata(dev);
	pcie_bus_dev = bus->bus_priv.pcie;
	devinfo = pcie_bus_dev->devinfo;

	/* check firmware loading result */
	if (ret)
		goto fail;

	ifxf_pcie_attach(devinfo);

	fw = fwreq->items[IFXF_PCIE_FW_CODE].binary;
	nvram = fwreq->items[IFXF_PCIE_FW_NVRAM].nv_data.data;
	nvram_len = fwreq->items[IFXF_PCIE_FW_NVRAM].nv_data.len;
	devinfo->clm_fw = fwreq->items[IFXF_PCIE_FW_CLM].binary;
	kfree(fwreq);

	ret = ifxf_chip_get_raminfo(devinfo->ci);
	if (ret) {
		ifxf_err(bus, "Failed to get RAM info\n");
		release_firmware(fw);
		ifxf_fw_nvram_free(nvram);
		goto fail;
	}

	/* Some of the firmwares have the size of the memory of the device
	 * defined inside the firmware. This is because part of the memory in
	 * the device is shared and the devision is determined by FW. Parse
	 * the firmware and adjust the chip memory size now.
	 */
	ifxf_pcie_adjust_ramsize(devinfo, (u8 *)fw->data, fw->size);

	ret = ifxf_pcie_download_fw_nvram(devinfo, fw, nvram, nvram_len);
	if (ret) {
		if (devinfo->ci->blhs && !ifxf_pcie_bus_readshared(devinfo, 0))
			ifxf_pcie_bus_console_read(devinfo, true);
		goto fail;
	}

	devinfo->state = IFXFMAC_PCIE_STATE_UP;

	ret = ifxf_pcie_init_ringbuffers(devinfo);
	if (ret)
		goto fail;

	ret = ifxf_pcie_init_scratchbuffers(devinfo);
	if (ret)
		goto fail;

	ifxf_pcie_select_core(devinfo, BCMA_CORE_PCIE2);
	ret = ifxf_pcie_request_irq(devinfo);
	if (ret)
		goto fail;

	/* hook the commonrings in the bus structure. */
	for (i = 0; i < IFXF_NROF_COMMON_MSGRINGS; i++)
		bus->msgbuf->commonrings[i] =
				&devinfo->shared.commonrings[i]->commonring;

	flowrings = kcalloc(devinfo->shared.max_flowrings, sizeof(*flowrings),
			    GFP_KERNEL);
	if (!flowrings)
		goto fail;

	for (i = 0; i < devinfo->shared.max_flowrings; i++)
		flowrings[i] = &devinfo->shared.flowrings[i].commonring;
	bus->msgbuf->flowrings = flowrings;

	bus->msgbuf->rx_dataoffset = devinfo->shared.rx_dataoffset;
	bus->msgbuf->max_rxbufpost = devinfo->shared.max_rxbufpost;
	bus->msgbuf->max_flowrings = devinfo->shared.max_flowrings;

	init_waitqueue_head(&devinfo->mbdata_resp_wait);

	ret = ifxf_attach(&devinfo->pdev->dev, true);
	if (ret)
		goto fail;

	ifxf_pcie_bus_console_read(devinfo, false);

	ifxf_pcie_fwcon_timer(devinfo, true);

	return;

fail:
	ifxf_err(bus, "Dongle setup failed\n");
	ifxf_pcie_bus_console_read(devinfo, true);
	ifxf_fw_crashed(dev);
	device_release_driver(dev);
}

static struct ifxf_fw_request *
ifxf_pcie_prepare_fw_request(struct ifxf_pciedev_info *devinfo)
{
	struct ifxf_fw_request *fwreq;
	struct ifxf_fw_name fwnames[] = {
		{ ".bin", devinfo->fw_name },
		{ ".txt", devinfo->nvram_name },
		{ ".clm_blob", devinfo->clm_name },
	};
	u32 chip;

	if (devinfo->ci->blhs)
		fwnames[IFXF_PCIE_FW_CODE].extension = ".trxse";

	chip = devinfo->ci->chip;
	fwreq = ifxf_fw_alloc_request(chip, devinfo->ci->chiprev,
				       ifxf_pcie_fwnames,
				       ARRAY_SIZE(ifxf_pcie_fwnames),
				       fwnames, ARRAY_SIZE(fwnames));
	if (!fwreq)
		return NULL;

	if (devinfo->ci->blhs)
		fwreq->items[IFXF_PCIE_FW_CODE].type = IFXF_FW_TYPE_TRXSE;
	else
		fwreq->items[IFXF_PCIE_FW_CODE].type = IFXF_FW_TYPE_BINARY;
	fwreq->items[IFXF_PCIE_FW_NVRAM].type = IFXF_FW_TYPE_NVRAM;
	fwreq->items[IFXF_PCIE_FW_NVRAM].flags = IFXF_FW_REQF_OPTIONAL;
	fwreq->items[IFXF_PCIE_FW_CLM].type = IFXF_FW_TYPE_BINARY;
	fwreq->items[IFXF_PCIE_FW_CLM].flags = IFXF_FW_REQF_OPTIONAL;
	/* NVRAM reserves PCI domain 0 for Broadcom's SDK faked bus */
	fwreq->domain_nr = pci_domain_nr(devinfo->pdev->bus) + 1;
	fwreq->bus_nr = devinfo->pdev->bus->number;

	/* Apple platforms with fancy firmware/NVRAM selection */
	if (devinfo->settings->board_type &&
	    devinfo->settings->antenna_sku &&
	    devinfo->otp.valid) {
		const struct ifxf_otp_params *otp = &devinfo->otp;
		struct device *dev = &devinfo->pdev->dev;
		const char **bt = fwreq->board_types;

		ifxf_dbg(PCIE, "Apple board: %s\n",
			  devinfo->settings->board_type);

		/* Example: apple,shikoku-RASP-m-6.11-X3 */
		bt[0] = devm_kasprintf(dev, GFP_KERNEL, "%s-%s-%s-%s-%s",
				       devinfo->settings->board_type,
				       otp->module, otp->vendor, otp->version,
				       devinfo->settings->antenna_sku);
		bt[1] = devm_kasprintf(dev, GFP_KERNEL, "%s-%s-%s-%s",
				       devinfo->settings->board_type,
				       otp->module, otp->vendor, otp->version);
		bt[2] = devm_kasprintf(dev, GFP_KERNEL, "%s-%s-%s",
				       devinfo->settings->board_type,
				       otp->module, otp->vendor);
		bt[3] = devm_kasprintf(dev, GFP_KERNEL, "%s-%s",
				       devinfo->settings->board_type,
				       otp->module);
		bt[4] = devm_kasprintf(dev, GFP_KERNEL, "%s-%s",
				       devinfo->settings->board_type,
				       devinfo->settings->antenna_sku);
		bt[5] = devinfo->settings->board_type;

		if (!bt[0] || !bt[1] || !bt[2] || !bt[3] || !bt[4]) {
			kfree(fwreq);
			return NULL;
		}
	} else {
		ifxf_dbg(PCIE, "Board: %s\n", devinfo->settings->board_type);
		fwreq->board_types[0] = devinfo->settings->board_type;
	}

	return fwreq;
}

#ifdef DEBUG
static void
ifxf_pcie_fwcon_timer(struct ifxf_pciedev_info *devinfo, bool active)
{
	if (!active) {
		if (devinfo->console_active) {
			del_timer_sync(&devinfo->timer);
			devinfo->console_active = false;
		}
		return;
	}

	/* don't start the timer */
	if (devinfo->state != IFXFMAC_PCIE_STATE_UP ||
	    !devinfo->console_interval || !IFXF_FWCON_ON())
		return;

	if (!devinfo->console_active) {
		devinfo->timer.expires = jiffies + devinfo->console_interval;
		add_timer(&devinfo->timer);
		devinfo->console_active = true;
	} else {
		/* Reschedule the timer */
		mod_timer(&devinfo->timer, jiffies + devinfo->console_interval);
	}
}

static void
ifxf_pcie_fwcon(struct timer_list *t)
{
	struct ifxf_pciedev_info *devinfo = from_timer(devinfo, t, timer);

	if (!devinfo->console_active)
		return;

	ifxf_pcie_bus_console_read(devinfo, false);

	/* Reschedule the timer if console interval is not zero */
	mod_timer(&devinfo->timer, jiffies + devinfo->console_interval);
}

static int ifxf_pcie_console_interval_get(void *data, u64 *val)
{
	struct ifxf_pciedev_info *devinfo = data;

	*val = devinfo->console_interval;

	return 0;
}

static int ifxf_pcie_console_interval_set(void *data, u64 val)
{
	struct ifxf_pciedev_info *devinfo = data;

	if (val > MAX_CONSOLE_INTERVAL)
		return -EINVAL;

	devinfo->console_interval = val;

	if (!val && devinfo->console_active)
		ifxf_pcie_fwcon_timer(devinfo, false);
	else if (val)
		ifxf_pcie_fwcon_timer(devinfo, true);

	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(ifxf_pcie_console_interval_fops,
			ifxf_pcie_console_interval_get,
			ifxf_pcie_console_interval_set,
			"%llu\n");

static void ifxf_pcie_debugfs_create(struct device *dev)
{
	struct ifxf_bus *bus_if = dev_get_drvdata(dev);
	struct ifxf_pub *drvr = bus_if->drvr;
	struct ifxf_pciedev *pcie_bus_dev = bus_if->bus_priv.pcie;
	struct ifxf_pciedev_info *devinfo = pcie_bus_dev->devinfo;
	struct dentry *dentry = ifxf_debugfs_get_devdir(drvr);

	if (IS_ERR_OR_NULL(dentry))
		return;

	devinfo->console_interval = IFXF_CONSOLE;

	debugfs_create_file("console_interval", 0644, dentry, devinfo,
			    &ifxf_pcie_console_interval_fops);
}

#else
void ifxf_pcie_fwcon_timer(struct ifxf_pciedev_info *devinfo, bool active)
{
}

static void ifxf_pcie_debugfs_create(struct device *dev)
{
}
#endif

static int
ifxf_pcie_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	int ret;
	struct ifxf_fw_request *fwreq;
	struct ifxf_pciedev_info *devinfo;
	struct ifxf_pciedev *pcie_bus_dev;
	struct ifxf_core *core;
	struct ifxf_bus *bus;

	ifxf_dbg(PCIE, "Enter %x:%x\n", pdev->vendor, pdev->device);

	ret = -ENOMEM;
	devinfo = kzalloc(sizeof(*devinfo), GFP_KERNEL);
	if (devinfo == NULL)
		return ret;

	devinfo->pdev = pdev;
	pcie_bus_dev = NULL;
	devinfo->ci = ifxf_chip_attach(devinfo, pdev->device,
					&ifxf_pcie_buscore_ops);
	if (IS_ERR(devinfo->ci)) {
		ret = PTR_ERR(devinfo->ci);
		devinfo->ci = NULL;
		goto fail;
	}

	core = ifxf_chip_get_core(devinfo->ci, BCMA_CORE_PCIE2);
	if (core->rev >= 64)
		devinfo->reginfo = &ifxf_reginfo_64;
	else
		devinfo->reginfo = &ifxf_reginfo_default;

	pcie_bus_dev = kzalloc(sizeof(*pcie_bus_dev), GFP_KERNEL);
	if (pcie_bus_dev == NULL) {
		ret = -ENOMEM;
		goto fail;
	}

	devinfo->settings = ifxf_get_module_param(&devinfo->pdev->dev,
						   IFXF_BUSTYPE_PCIE,
						   devinfo->ci->chip,
						   devinfo->ci->chiprev);
	if (!devinfo->settings) {
		ret = -ENOMEM;
		goto fail;
	}

	bus = kzalloc(sizeof(*bus), GFP_KERNEL);
	if (!bus) {
		ret = -ENOMEM;
		goto fail;
	}
	bus->msgbuf = kzalloc(sizeof(*bus->msgbuf), GFP_KERNEL);
	if (!bus->msgbuf) {
		ret = -ENOMEM;
		kfree(bus);
		goto fail;
	}

	/* hook it all together. */
	pcie_bus_dev->devinfo = devinfo;
	pcie_bus_dev->bus = bus;
	bus->dev = &pdev->dev;
	bus->bus_priv.pcie = pcie_bus_dev;
	bus->ops = &ifxf_pcie_bus_ops;
	bus->proto_type = IFXF_PROTO_MSGBUF;
	bus->chip = devinfo->coreid;
	bus->wowl_supported = pci_pme_capable(pdev, PCI_D3hot);
	dev_set_drvdata(&pdev->dev, bus);

	ret = ifxf_alloc(&devinfo->pdev->dev, devinfo->settings);
	if (ret)
		goto fail_bus;

	ret = ifxf_pcie_read_otp(devinfo);
	if (ret) {
		ifxf_err(bus, "failed to parse OTP\n");
		goto fail_ifxf;
	}

#ifdef DEBUG
	/* Set up the fwcon timer */
	timer_setup(&devinfo->timer, ifxf_pcie_fwcon, 0);
#endif

	fwreq = ifxf_pcie_prepare_fw_request(devinfo);
	if (!fwreq) {
		ret = -ENOMEM;
		goto fail_ifxf;
	}

	ret = ifxf_fw_get_firmwares(bus->dev, fwreq, ifxf_pcie_setup);
	if (ret < 0) {
		kfree(fwreq);
		goto fail_ifxf;
	}
	return 0;

fail_ifxf:
	ifxf_free(&devinfo->pdev->dev);
fail_bus:
	kfree(bus->msgbuf);
	kfree(bus);
fail:
	ifxf_err(NULL, "failed %x:%x\n", pdev->vendor, pdev->device);
	ifxf_pcie_release_resource(devinfo);
	if (devinfo->ci)
		ifxf_chip_detach(devinfo->ci);
	if (devinfo->settings)
		ifxf_release_module_param(devinfo->settings);
	kfree(pcie_bus_dev);
	kfree(devinfo);
	return ret;
}


static void
ifxf_pcie_remove(struct pci_dev *pdev)
{
	struct ifxf_pciedev_info *devinfo;
	struct ifxf_bus *bus;

	ifxf_dbg(PCIE, "Enter\n");

	bus = dev_get_drvdata(&pdev->dev);
	if (bus == NULL)
		return;

	devinfo = bus->bus_priv.pcie->devinfo;
	ifxf_pcie_bus_console_read(devinfo, false);

	ifxf_pcie_fwcon_timer(devinfo, false);

	devinfo->state = IFXFMAC_PCIE_STATE_DOWN;
	if (devinfo->ci)
		ifxf_pcie_intr_disable(devinfo);

	ifxf_detach(&pdev->dev);
	ifxf_free(&pdev->dev);

	kfree(bus->bus_priv.pcie);
	kfree(bus->msgbuf->flowrings);
	kfree(bus->msgbuf);
	kfree(bus);

	ifxf_pcie_release_irq(devinfo);
	ifxf_pcie_release_scratchbuffers(devinfo);
	ifxf_pcie_release_ringbuffers(devinfo);
	ifxf_pcie_reset_device(devinfo);
	ifxf_pcie_release_resource(devinfo);
	release_firmware(devinfo->clm_fw);

	if (devinfo->ci)
		ifxf_chip_detach(devinfo->ci);
	if (devinfo->settings)
		ifxf_release_module_param(devinfo->settings);

	kfree(devinfo);
	dev_set_drvdata(&pdev->dev, NULL);
}


#ifdef CONFIG_PM


static int ifxf_pcie_pm_enter_D3(struct device *dev)
{
	struct ifxf_pciedev_info *devinfo;
	struct ifxf_bus *bus;
	struct ifxf_cfg80211_info *config;
	int retry = IFXF_PM_WAIT_MAXRETRY;

	ifxf_dbg(PCIE, "Enter\n");

	bus = dev_get_drvdata(dev);
	devinfo = bus->bus_priv.pcie->devinfo;
	config = bus->drvr->config;

	while (retry &&
	       config->pm_state == IFXF_CFG80211_PM_STATE_SUSPENDING) {
		usleep_range(10000, 20000);
		retry--;
	}
	if (!retry && config->pm_state == IFXF_CFG80211_PM_STATE_SUSPENDING)
		ifxf_err(bus, "timed out wait for cfg80211 suspended\n");

	ifxf_pcie_fwcon_timer(devinfo, false);

	ifxf_bus_change_state(bus, IFXF_BUS_DOWN);

	devinfo->mbdata_completed = false;
	ifxf_pcie_send_mb_data(devinfo, IFXF_H2D_HOST_D3_INFORM);

	wait_event_timeout(devinfo->mbdata_resp_wait, devinfo->mbdata_completed,
			   IFXF_PCIE_MBDATA_TIMEOUT);
	if (!devinfo->mbdata_completed) {
		ifxf_err(bus, "Timeout on response for entering D3 substate\n");
		ifxf_bus_change_state(bus, IFXF_BUS_UP);
		return -EIO;
	}

	devinfo->state = IFXFMAC_PCIE_STATE_DOWN;

	return 0;
}


static int ifxf_pcie_pm_leave_D3(struct device *dev)
{
	struct ifxf_pciedev_info *devinfo;
	struct ifxf_bus *bus;
	struct pci_dev *pdev;
	int err;

	ifxf_dbg(PCIE, "Enter\n");

	bus = dev_get_drvdata(dev);
	devinfo = bus->bus_priv.pcie->devinfo;
	ifxf_dbg(PCIE, "Enter, dev=%p, bus=%p\n", dev, bus);

	/* Check if device is still up and running, if so we are ready */
	if (ifxf_pcie_read_reg32(devinfo, devinfo->reginfo->intmask) != 0) {
		ifxf_dbg(PCIE, "Try to wakeup device....\n");
		if (devinfo->use_d0_inform) {
			if (ifxf_pcie_send_mb_data(devinfo,
						    IFXF_H2D_HOST_D0_INFORM))
				goto cleanup;
		} else {
			ifxf_pcie_hostready(devinfo);
		}

		ifxf_dbg(PCIE, "Hot resume, continue....\n");
		devinfo->state = IFXFMAC_PCIE_STATE_UP;
		ifxf_pcie_select_core(devinfo, BCMA_CORE_PCIE2);
		ifxf_bus_change_state(bus, IFXF_BUS_UP);
		ifxf_pcie_intr_enable(devinfo);
		if (devinfo->use_d0_inform) {
			ifxf_dbg(TRACE, "sending ifxf_pcie_hostready since use_d0_inform=%d\n",
				  devinfo->use_d0_inform);
			ifxf_pcie_hostready(devinfo);
		}

		ifxf_pcie_fwcon_timer(devinfo, true);
		return 0;
	}

cleanup:
	ifxf_chip_detach(devinfo->ci);
	devinfo->ci = NULL;
	pdev = devinfo->pdev;
	ifxf_pcie_remove(pdev);

	err = ifxf_pcie_probe(pdev, NULL);
	if (err)
		__ifxf_err(NULL, __func__, "probe after resume failed, err=%d\n", err);

	return err;
}


static const struct dev_pm_ops ifxf_pciedrvr_pm = {
	.suspend = ifxf_pcie_pm_enter_D3,
	.resume = ifxf_pcie_pm_leave_D3,
	.freeze = ifxf_pcie_pm_enter_D3,
	.restore = ifxf_pcie_pm_leave_D3,
};


#endif /* CONFIG_PM */


#define IFXF_PCIE_DEVICE_LEGACY(dev_id)	{ BRCM_PCIE_VENDOR_ID_BROADCOM, dev_id,\
	PCI_ANY_ID, PCI_ANY_ID, PCI_CLASS_NETWORK_OTHER << 8, 0xffff00, 0 }
#define IFXF_PCIE_DEVICE_LEGACY_SUB(dev_id, subvend, subdev)	{ \
	BRCM_PCIE_VENDOR_ID_BROADCOM, dev_id,\
	subvend, subdev, PCI_CLASS_NETWORK_OTHER << 8, 0xffff00, 0 }

#define IFXF_PCIE_DEVICE(dev_id)	{ CY_PCIE_VENDOR_ID_CYPRESS, dev_id,\
	PCI_ANY_ID, PCI_ANY_ID, PCI_CLASS_NETWORK_OTHER << 8, 0xffff00, 0 }

static const struct pci_device_id ifxf_pcie_devid_table[] = {
	IFXF_PCIE_DEVICE_LEGACY_SUB(0x4355, BRCM_PCIE_VENDOR_ID_BROADCOM, 0x4355),
	IFXF_PCIE_DEVICE_LEGACY(CY_PCIE_4354_RAW_DEVICE_ID),
	IFXF_PCIE_DEVICE_LEGACY(CY_PCIE_4356_DEVICE_ID),
	IFXF_PCIE_DEVICE_LEGACY(CY_PCIE_43570_DEVICE_ID),
	IFXF_PCIE_DEVICE_LEGACY(CY_PCIE_43570_RAW_DEVICE_ID),
	IFXF_PCIE_DEVICE_LEGACY(CY_PCIE_4359_DEVICE_ID),
	IFXF_PCIE_DEVICE_LEGACY(CY_PCIE_89459_DEVICE_ID),
	IFXF_PCIE_DEVICE_LEGACY(CY_PCIE_89459_RAW_DEVICE_ID),
	IFXF_PCIE_DEVICE_LEGACY(CY_PCIE_54591_DEVICE_ID),
	IFXF_PCIE_DEVICE_LEGACY(CY_PCIE_54590_DEVICE_ID),
	IFXF_PCIE_DEVICE_LEGACY(CY_PCIE_54594_DEVICE_ID),
	IFXF_PCIE_DEVICE_LEGACY(CY_PCIE_4373_RAW_DEVICE_ID),
	IFXF_PCIE_DEVICE_LEGACY(CY_PCIE_4373_DUAL_DEVICE_ID),
	IFXF_PCIE_DEVICE_LEGACY(CY_PCIE_4373_2G_DEVICE_ID),
	IFXF_PCIE_DEVICE_LEGACY(CY_PCIE_4373_5G_DEVICE_ID),
	IFXF_PCIE_DEVICE(CY_PCIE_55572_DEVICE_ID),
	{ /* end: all zeroes */ }
};

MODULE_DEVICE_TABLE(pci, ifxf_pcie_devid_table);

static struct pci_driver ifxf_pciedrvr = {
	.node = {},
	.name = KBUILD_MODNAME,
	.id_table = ifxf_pcie_devid_table,
	.probe = ifxf_pcie_probe,
	.remove = ifxf_pcie_remove,
#ifdef CONFIG_PM
	.driver.pm = &ifxf_pciedrvr_pm,
#endif
	.driver.coredump = ifxf_dev_coredump,
};

int ifxf_pcie_register(void)
{
	ifxf_dbg(PCIE, "Enter\n");
	return pci_register_driver(&ifxf_pciedrvr);
}

void ifxf_pcie_exit(void)
{
	ifxf_dbg(PCIE, "Enter\n");
	pci_unregister_driver(&ifxf_pciedrvr);
}
