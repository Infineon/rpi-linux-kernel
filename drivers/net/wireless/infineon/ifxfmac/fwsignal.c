// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2010 Broadcom Corporation
 */
#include <linux/types.h>
#include <linux/module.h>
#include <linux/if_ether.h>
#include <linux/spinlock.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/err.h>
#include <linux/jiffies.h>
#include <net/cfg80211.h>

#include <ifxu_utils.h>
#include <ifxu_wifi.h>
#include "core.h"
#include "debug.h"
#include "bus.h"
#include "fwil.h"
#include "fwil_types.h"
#include "fweh.h"
#include "fwsignal.h"
#include "p2p.h"
#include "cfg80211.h"
#include "proto.h"
#include "bcdc.h"
#include "common.h"

/**
 * DOC: Firmware Signalling
 *
 * Firmware can send signals to host and vice versa, which are passed in the
 * data packets using TLV based header. This signalling layer is on top of the
 * BDC bus protocol layer.
 */

/*
 * single definition for firmware-driver flow control tlv's.
 *
 * each tlv is specified by IFXF_FWS_TLV_DEF(name, ID, length).
 * A length value 0 indicates variable length tlv.
 */
#define IFXF_FWS_TLV_DEFLIST \
	IFXF_FWS_TLV_DEF(MAC_OPEN, 1, 1) \
	IFXF_FWS_TLV_DEF(MAC_CLOSE, 2, 1) \
	IFXF_FWS_TLV_DEF(MAC_REQUEST_CREDIT, 3, 2) \
	IFXF_FWS_TLV_DEF(TXSTATUS, 4, 4) \
	IFXF_FWS_TLV_DEF(PKTTAG, 5, 4) \
	IFXF_FWS_TLV_DEF(MACDESC_ADD,	6, 8) \
	IFXF_FWS_TLV_DEF(MACDESC_DEL, 7, 8) \
	IFXF_FWS_TLV_DEF(RSSI, 8, 1) \
	IFXF_FWS_TLV_DEF(INTERFACE_OPEN, 9, 1) \
	IFXF_FWS_TLV_DEF(INTERFACE_CLOSE, 10, 1) \
	IFXF_FWS_TLV_DEF(FIFO_CREDITBACK, 11, 6) \
	IFXF_FWS_TLV_DEF(PENDING_TRAFFIC_BMP, 12, 2) \
	IFXF_FWS_TLV_DEF(MAC_REQUEST_PACKET, 13, 3) \
	IFXF_FWS_TLV_DEF(HOST_REORDER_RXPKTS, 14, 10) \
	IFXF_FWS_TLV_DEF(TRANS_ID, 18, 6) \
	IFXF_FWS_TLV_DEF(COMP_TXSTATUS, 19, 1) \
	IFXF_FWS_TLV_DEF(FILLER, 255, 0)

/*
 * enum ifxf_fws_tlv_type - definition of tlv identifiers.
 */
#define IFXF_FWS_TLV_DEF(name, id, len) \
	IFXF_FWS_TYPE_ ## name =  id,
enum ifxf_fws_tlv_type {
	IFXF_FWS_TLV_DEFLIST
	IFXF_FWS_TYPE_INVALID
};
#undef IFXF_FWS_TLV_DEF

/*
 * enum ifxf_fws_tlv_len - definition of tlv lengths.
 */
#define IFXF_FWS_TLV_DEF(name, id, len) \
	IFXF_FWS_TYPE_ ## name ## _LEN = (len),
enum ifxf_fws_tlv_len {
	IFXF_FWS_TLV_DEFLIST
};
#undef IFXF_FWS_TLV_DEF

/* AMPDU rx reordering definitions */
#define IFXF_RXREORDER_FLOWID_OFFSET		0
#define IFXF_RXREORDER_MAXIDX_OFFSET		2
#define IFXF_RXREORDER_FLAGS_OFFSET		4
#define IFXF_RXREORDER_CURIDX_OFFSET		6
#define IFXF_RXREORDER_EXPIDX_OFFSET		8

#define IFXF_RXREORDER_DEL_FLOW		0x01
#define IFXF_RXREORDER_FLUSH_ALL		0x02
#define IFXF_RXREORDER_CURIDX_VALID		0x04
#define IFXF_RXREORDER_EXPIDX_VALID		0x08
#define IFXF_RXREORDER_NEW_HOLE		0x10

#ifdef DEBUG
/*
 * ifxf_fws_tlv_names - array of tlv names.
 */
#define IFXF_FWS_TLV_DEF(name, id, len) \
	{ id, #name },
static struct {
	enum ifxf_fws_tlv_type id;
	const char *name;
} ifxf_fws_tlv_names[] = {
	IFXF_FWS_TLV_DEFLIST
};
#undef IFXF_FWS_TLV_DEF


static const char *ifxf_fws_get_tlv_name(enum ifxf_fws_tlv_type id)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(ifxf_fws_tlv_names); i++)
		if (ifxf_fws_tlv_names[i].id == id)
			return ifxf_fws_tlv_names[i].name;

	return "INVALID";
}
#else
static const char *ifxf_fws_get_tlv_name(enum ifxf_fws_tlv_type id)
{
	return "NODEBUG";
}
#endif /* DEBUG */

/*
 * The PKTTAG tlv has additional bytes when firmware-signalling
 * mode has REUSESEQ flag set.
 */
#define IFXF_FWS_TYPE_SEQ_LEN				2

/*
 * flags used to enable tlv signalling from firmware.
 */
#define IFXF_FWS_FLAGS_RSSI_SIGNALS			0x0001
#define IFXF_FWS_FLAGS_XONXOFF_SIGNALS			0x0002
#define IFXF_FWS_FLAGS_CREDIT_STATUS_SIGNALS		0x0004
#define IFXF_FWS_FLAGS_HOST_PROPTXSTATUS_ACTIVE	0x0008
#define IFXF_FWS_FLAGS_PSQ_GENERATIONFSM_ENABLE	0x0010
#define IFXF_FWS_FLAGS_PSQ_ZERO_BUFFER_ENABLE		0x0020
#define IFXF_FWS_FLAGS_HOST_RXREORDER_ACTIVE		0x0040

#define IFXF_FWS_MAC_DESC_TABLE_SIZE			32
#define IFXF_FWS_MAC_DESC_ID_INVALID			0xff

#define IFXF_FWS_HOSTIF_FLOWSTATE_OFF			0
#define IFXF_FWS_HOSTIF_FLOWSTATE_ON			1
#define IFXF_FWS_FLOWCONTROL_HIWATER			128
#define IFXF_FWS_FLOWCONTROL_LOWATER			64

#define IFXF_FWS_PSQ_PREC_COUNT		((IFXF_FWS_FIFO_COUNT + 1) * 2)
#define IFXF_FWS_PSQ_LEN				256

#define IFXF_FWS_HTOD_FLAG_PKTFROMHOST			0x01
#define IFXF_FWS_HTOD_FLAG_PKT_REQUESTED		0x02

#define IFXF_FWS_RET_OK_NOSCHEDULE			0
#define IFXF_FWS_RET_OK_SCHEDULE			1

#define IFXF_FWS_MODE_REUSESEQ_SHIFT			3	/* seq reuse */
#define IFXF_FWS_MODE_SET_REUSESEQ(x, val)	((x) = \
		((x) & ~(1 << IFXF_FWS_MODE_REUSESEQ_SHIFT)) | \
		(((val) & 1) << IFXF_FWS_MODE_REUSESEQ_SHIFT))
#define IFXF_FWS_MODE_GET_REUSESEQ(x)	\
		(((x) >> IFXF_FWS_MODE_REUSESEQ_SHIFT) & 1)

/**
 * enum ifxf_fws_skb_state - indicates processing state of skb.
 *
 * @IFXF_FWS_SKBSTATE_NEW: sk_buff is newly arrived in the driver.
 * @IFXF_FWS_SKBSTATE_DELAYED: sk_buff had to wait on queue.
 * @IFXF_FWS_SKBSTATE_SUPPRESSED: sk_buff has been suppressed by firmware.
 * @IFXF_FWS_SKBSTATE_TIM: allocated for TIM update info.
 */
enum ifxf_fws_skb_state {
	IFXF_FWS_SKBSTATE_NEW,
	IFXF_FWS_SKBSTATE_DELAYED,
	IFXF_FWS_SKBSTATE_SUPPRESSED,
	IFXF_FWS_SKBSTATE_TIM
};

/**
 * struct ifxf_skbuff_cb - control buffer associated with skbuff.
 *
 * @bus_flags: 2 bytes reserved for bus specific parameters
 * @if_flags: holds interface index and packet related flags.
 * @htod: host to device packet identifier (used in PKTTAG tlv).
 * @htod_seq: this 16-bit is original seq number for every suppress packet.
 * @state: transmit state of the packet.
 * @mac: descriptor related to destination for this packet.
 *
 * This information is stored in control buffer struct sk_buff::cb, which
 * provides 48 bytes of storage so this structure should not exceed that.
 */
struct ifxf_skbuff_cb {
	u16 bus_flags;
	u16 if_flags;
	u32 htod;
	u16 htod_seq;
	enum ifxf_fws_skb_state state;
	struct ifxf_fws_mac_descriptor *mac;
};

/*
 * macro casting skbuff control buffer to struct ifxf_skbuff_cb.
 */
#define ifxf_skbcb(skb)	((struct ifxf_skbuff_cb *)((skb)->cb))

/*
 * sk_buff control if flags
 *
 *	b[11]  - packet sent upon firmware request.
 *	b[10]  - packet only contains signalling data.
 *	b[9]   - packet is a tx packet.
 *	b[8]   - packet used requested credit
 *	b[7]   - interface in AP mode.
 *	b[3:0] - interface index.
 */
#define IFXF_SKB_IF_FLAGS_REQUESTED_MASK	0x0800
#define IFXF_SKB_IF_FLAGS_REQUESTED_SHIFT	11
#define IFXF_SKB_IF_FLAGS_SIGNAL_ONLY_MASK	0x0400
#define IFXF_SKB_IF_FLAGS_SIGNAL_ONLY_SHIFT	10
#define IFXF_SKB_IF_FLAGS_TRANSMIT_MASK        0x0200
#define IFXF_SKB_IF_FLAGS_TRANSMIT_SHIFT	9
#define IFXF_SKB_IF_FLAGS_REQ_CREDIT_MASK	0x0100
#define IFXF_SKB_IF_FLAGS_REQ_CREDIT_SHIFT	8
#define IFXF_SKB_IF_FLAGS_IF_AP_MASK		0x0080
#define IFXF_SKB_IF_FLAGS_IF_AP_SHIFT		7
#define IFXF_SKB_IF_FLAGS_INDEX_MASK		0x000f
#define IFXF_SKB_IF_FLAGS_INDEX_SHIFT		0

#define ifxf_skb_if_flags_set_field(skb, field, value) \
	ifxu_maskset16(&(ifxf_skbcb(skb)->if_flags), \
			IFXF_SKB_IF_FLAGS_ ## field ## _MASK, \
			IFXF_SKB_IF_FLAGS_ ## field ## _SHIFT, (value))
#define ifxf_skb_if_flags_get_field(skb, field) \
	ifxu_maskget16(ifxf_skbcb(skb)->if_flags, \
			IFXF_SKB_IF_FLAGS_ ## field ## _MASK, \
			IFXF_SKB_IF_FLAGS_ ## field ## _SHIFT)

/*
 * sk_buff control packet identifier
 *
 * 32-bit packet identifier used in PKTTAG tlv from host to dongle.
 *
 * - Generated at the host (e.g. dhd)
 * - Seen as a generic sequence number by firmware except for the flags field.
 *
 * Generation	: b[31]	=> generation number for this packet [host->fw]
 *			   OR, current generation number [fw->host]
 * Flags	: b[30:27] => command, status flags
 * FIFO-AC	: b[26:24] => AC-FIFO id
 * h-slot	: b[23:8] => hanger-slot
 * freerun	: b[7:0] => A free running counter
 */
#define IFXF_SKB_HTOD_TAG_GENERATION_MASK		0x80000000
#define IFXF_SKB_HTOD_TAG_GENERATION_SHIFT		31
#define IFXF_SKB_HTOD_TAG_FLAGS_MASK			0x78000000
#define IFXF_SKB_HTOD_TAG_FLAGS_SHIFT			27
#define IFXF_SKB_HTOD_TAG_FIFO_MASK			0x07000000
#define IFXF_SKB_HTOD_TAG_FIFO_SHIFT			24
#define IFXF_SKB_HTOD_TAG_HSLOT_MASK			0x00ffff00
#define IFXF_SKB_HTOD_TAG_HSLOT_SHIFT			8
#define IFXF_SKB_HTOD_TAG_FREERUN_MASK			0x000000ff
#define IFXF_SKB_HTOD_TAG_FREERUN_SHIFT		0

#define ifxf_skb_htod_tag_set_field(skb, field, value) \
	ifxu_maskset32(&(ifxf_skbcb(skb)->htod), \
			IFXF_SKB_HTOD_TAG_ ## field ## _MASK, \
			IFXF_SKB_HTOD_TAG_ ## field ## _SHIFT, (value))
#define ifxf_skb_htod_tag_get_field(skb, field) \
	ifxu_maskget32(ifxf_skbcb(skb)->htod, \
			IFXF_SKB_HTOD_TAG_ ## field ## _MASK, \
			IFXF_SKB_HTOD_TAG_ ## field ## _SHIFT)

#define IFXF_SKB_HTOD_SEQ_FROMFW_MASK			0x2000
#define IFXF_SKB_HTOD_SEQ_FROMFW_SHIFT			13
#define IFXF_SKB_HTOD_SEQ_FROMDRV_MASK			0x1000
#define IFXF_SKB_HTOD_SEQ_FROMDRV_SHIFT		12
#define IFXF_SKB_HTOD_SEQ_NR_MASK			0x0fff
#define IFXF_SKB_HTOD_SEQ_NR_SHIFT			0

#define ifxf_skb_htod_seq_set_field(skb, field, value) \
	ifxu_maskset16(&(ifxf_skbcb(skb)->htod_seq), \
			IFXF_SKB_HTOD_SEQ_ ## field ## _MASK, \
			IFXF_SKB_HTOD_SEQ_ ## field ## _SHIFT, (value))
#define ifxf_skb_htod_seq_get_field(skb, field) \
	ifxu_maskget16(ifxf_skbcb(skb)->htod_seq, \
			IFXF_SKB_HTOD_SEQ_ ## field ## _MASK, \
			IFXF_SKB_HTOD_SEQ_ ## field ## _SHIFT)

#define IFXF_FWS_TXSTAT_GENERATION_MASK	0x80000000
#define IFXF_FWS_TXSTAT_GENERATION_SHIFT	31
#define IFXF_FWS_TXSTAT_FLAGS_MASK		0x78000000
#define IFXF_FWS_TXSTAT_FLAGS_SHIFT		27
#define IFXF_FWS_TXSTAT_FIFO_MASK		0x07000000
#define IFXF_FWS_TXSTAT_FIFO_SHIFT		24
#define IFXF_FWS_TXSTAT_HSLOT_MASK		0x00FFFF00
#define IFXF_FWS_TXSTAT_HSLOT_SHIFT		8
#define IFXF_FWS_TXSTAT_FREERUN_MASK		0x000000FF
#define IFXF_FWS_TXSTAT_FREERUN_SHIFT		0

#define ifxf_txstatus_get_field(txs, field) \
	ifxu_maskget32(txs, IFXF_FWS_TXSTAT_ ## field ## _MASK, \
			IFXF_FWS_TXSTAT_ ## field ## _SHIFT)

/* How long to defer borrowing in jiffies */
#define IFXF_FWS_BORROW_DEFER_PERIOD		(HZ / 10)


/**
 * enum ifxf_fws_txstatus - txstatus flag values.
 *
 * @IFXF_FWS_TXSTATUS_DISCARD:
 *	host is free to discard the packet.
 * @IFXF_FWS_TXSTATUS_CORE_SUPPRESS:
 *	802.11 core suppressed the packet.
 * @IFXF_FWS_TXSTATUS_FW_PS_SUPPRESS:
 *	firmware suppress the packet as device is already in PS mode.
 * @IFXF_FWS_TXSTATUS_FW_TOSSED:
 *	firmware tossed the packet.
 * @IFXF_FWS_TXSTATUS_FW_DISCARD_NOACK:
 *	firmware tossed the packet after retries.
 * @IFXF_FWS_TXSTATUS_FW_SUPPRESS_ACKED:
 *	firmware wrongly reported suppressed previously, now fixing to acked.
 * @IFXF_FWS_TXSTATUS_HOST_TOSSED:
 *	host tossed the packet.
 */
enum ifxf_fws_txstatus {
	IFXF_FWS_TXSTATUS_DISCARD,
	IFXF_FWS_TXSTATUS_CORE_SUPPRESS,
	IFXF_FWS_TXSTATUS_FW_PS_SUPPRESS,
	IFXF_FWS_TXSTATUS_FW_TOSSED,
	IFXF_FWS_TXSTATUS_FW_DISCARD_NOACK,
	IFXF_FWS_TXSTATUS_FW_SUPPRESS_ACKED,
	IFXF_FWS_TXSTATUS_HOST_TOSSED
};

enum ifxf_fws_fcmode {
	IFXF_FWS_FCMODE_NONE,
	IFXF_FWS_FCMODE_IMPLIED_CREDIT,
	IFXF_FWS_FCMODE_EXPLICIT_CREDIT
};

enum ifxf_fws_mac_desc_state {
	IFXF_FWS_STATE_OPEN = 1,
	IFXF_FWS_STATE_CLOSE
};

/**
 * struct ifxf_fws_mac_descriptor - firmware signalling data per node/interface
 *
 * @name: name of the descriptor.
 * @occupied: slot is in use.
 * @mac_handle: handle for mac entry determined by firmware.
 * @interface_id: interface index.
 * @state: current state.
 * @suppressed: mac entry is suppressed.
 * @generation: generation bit.
 * @ac_bitmap: ac queue bitmap.
 * @requested_credit: credits requested by firmware.
 * @requested_packet: packet requested by firmware.
 * @ea: ethernet address.
 * @seq: per-node free-running sequence.
 * @psq: power-save queue.
 * @transit_count: packet in transit to firmware.
 * @suppr_transit_count: suppressed packet in transit to firmware.
 * @send_tim_signal: if set tim signal will be sent.
 * @traffic_pending_bmp: traffic pending bitmap.
 * @traffic_lastreported_bmp: traffic last reported bitmap.
 */
struct ifxf_fws_mac_descriptor {
	char name[16];
	u8 occupied;
	u8 mac_handle;
	u8 interface_id;
	u8 state;
	bool suppressed;
	u8 generation;
	u8 ac_bitmap;
	u8 requested_credit;
	u8 requested_packet;
	u8 ea[ETH_ALEN];
	u8 seq[IFXF_FWS_FIFO_COUNT];
	struct pktq psq;
	int transit_count;
	int suppr_transit_count;
	bool send_tim_signal;
	u8 traffic_pending_bmp;
	u8 traffic_lastreported_bmp;
};

#define IFXF_FWS_HANGER_MAXITEMS	3072
#define IFXF_BORROW_RATIO			3

/**
 * enum ifxf_fws_hanger_item_state - state of hanger item.
 *
 * @IFXF_FWS_HANGER_ITEM_STATE_FREE: item is free for use.
 * @IFXF_FWS_HANGER_ITEM_STATE_INUSE: item is in use.
 * @IFXF_FWS_HANGER_ITEM_STATE_INUSE_SUPPRESSED: item was suppressed.
 */
enum ifxf_fws_hanger_item_state {
	IFXF_FWS_HANGER_ITEM_STATE_FREE = 1,
	IFXF_FWS_HANGER_ITEM_STATE_INUSE,
	IFXF_FWS_HANGER_ITEM_STATE_INUSE_SUPPRESSED
};


/**
 * struct ifxf_fws_hanger_item - single entry for tx pending packet.
 *
 * @state: entry is either free or occupied.
 * @pkt: packet itself.
 */
struct ifxf_fws_hanger_item {
	enum ifxf_fws_hanger_item_state state;
	struct sk_buff *pkt;
};

/**
 * struct ifxf_fws_hanger - holds packets awaiting firmware txstatus.
 *
 * @pushed: packets pushed to await txstatus.
 * @popped: packets popped upon handling txstatus.
 * @failed_to_push: packets that could not be pushed.
 * @failed_to_pop: packets that could not be popped.
 * @failed_slotfind: packets for which failed to find an entry.
 * @slot_pos: last returned item index for a free entry.
 * @items: array of hanger items.
 */
struct ifxf_fws_hanger {
	u32 pushed;
	u32 popped;
	u32 failed_to_push;
	u32 failed_to_pop;
	u32 failed_slotfind;
	u32 slot_pos;
	struct ifxf_fws_hanger_item items[IFXF_FWS_HANGER_MAXITEMS];
};

struct ifxf_fws_macdesc_table {
	struct ifxf_fws_mac_descriptor nodes[IFXF_FWS_MAC_DESC_TABLE_SIZE];
	struct ifxf_fws_mac_descriptor iface[IFXF_MAX_IFS];
	struct ifxf_fws_mac_descriptor other;
};

struct ifxf_fws_stats {
	u32 tlv_parse_failed;
	u32 tlv_invalid_type;
	u32 header_only_pkt;
	u32 header_pulls;
	u32 pkt2bus;
	u32 send_pkts[5];
	u32 requested_sent[5];
	u32 generic_error;
	u32 mac_update_failed;
	u32 mac_ps_update_failed;
	u32 if_update_failed;
	u32 packet_request_failed;
	u32 credit_request_failed;
	u32 rollback_success;
	u32 rollback_failed;
	u32 delayq_full_error;
	u32 supprq_full_error;
	u32 txs_indicate;
	u32 txs_discard;
	u32 txs_supp_core;
	u32 txs_supp_ps;
	u32 txs_tossed;
	u32 txs_host_tossed;
	u32 bus_flow_block;
	u32 fws_flow_block;
};

struct ifxf_fws_info {
	struct ifxf_pub *drvr;
	spinlock_t spinlock;
	ulong flags;
	struct ifxf_fws_stats stats;
	struct ifxf_fws_hanger hanger;
	enum ifxf_fws_fcmode fcmode;
	bool fw_signals;
	bool bcmc_credit_check;
	struct ifxf_fws_macdesc_table desc;
	struct workqueue_struct *fws_wq;
	struct work_struct fws_dequeue_work;
	u32 fifo_enqpkt[IFXF_FWS_FIFO_COUNT];
	int fifo_credit[IFXF_FWS_FIFO_COUNT];
	int init_fifo_credit[IFXF_FWS_FIFO_COUNT];
	int credits_borrowed[IFXF_FWS_FIFO_AC_VO + 1]
		[IFXF_FWS_FIFO_AC_VO + 1];
	int deq_node_pos[IFXF_FWS_FIFO_COUNT];
	u32 fifo_credit_map;
	u32 fifo_delay_map;
	unsigned long borrow_defer_timestamp;
	bool bus_flow_blocked;
	bool creditmap_received;
	u8 mode;
	bool avoid_queueing;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0))
	int fifo_init_credit[IFXF_FWS_FIFO_COUNT];
#endif
};

#define IFXF_FWS_TLV_DEF(name, id, len) \
	case IFXF_FWS_TYPE_ ## name: \
		return len;

/**
 * ifxf_fws_get_tlv_len() - returns defined length for given tlv id.
 *
 * @fws: firmware-signalling information.
 * @id: identifier of the TLV.
 *
 * Return: the specified length for the given TLV; Otherwise -EINVAL.
 */
static int ifxf_fws_get_tlv_len(struct ifxf_fws_info *fws,
				 enum ifxf_fws_tlv_type id)
{
	switch (id) {
	IFXF_FWS_TLV_DEFLIST
	default:
		fws->stats.tlv_invalid_type++;
		break;
	}
	return -EINVAL;
}
#undef IFXF_FWS_TLV_DEF

static void ifxf_fws_lock(struct ifxf_fws_info *fws)
		__acquires(&fws->spinlock)
{
	spin_lock_irqsave(&fws->spinlock, fws->flags);
}

static void ifxf_fws_unlock(struct ifxf_fws_info *fws)
		__releases(&fws->spinlock)
{
	spin_unlock_irqrestore(&fws->spinlock, fws->flags);
}

static bool ifxf_fws_ifidx_match(struct sk_buff *skb, void *arg)
{
	u32 ifidx = ifxf_skb_if_flags_get_field(skb, INDEX);
	return ifidx == *(int *)arg;
}

static void ifxf_fws_hanger_init(struct ifxf_fws_hanger *hanger)
{
	int i;

	memset(hanger, 0, sizeof(*hanger));
	for (i = 0; i < ARRAY_SIZE(hanger->items); i++)
		hanger->items[i].state = IFXF_FWS_HANGER_ITEM_STATE_FREE;
}

static u32 ifxf_fws_hanger_get_free_slot(struct ifxf_fws_hanger *h)
{
	u32 i;

	i = (h->slot_pos + 1) % IFXF_FWS_HANGER_MAXITEMS;

	while (i != h->slot_pos) {
		if (h->items[i].state == IFXF_FWS_HANGER_ITEM_STATE_FREE) {
			h->slot_pos = i;
			goto done;
		}
		i++;
		if (i == IFXF_FWS_HANGER_MAXITEMS)
			i = 0;
	}
	ifxf_err("all slots occupied\n");
	h->failed_slotfind++;
	i = IFXF_FWS_HANGER_MAXITEMS;
done:
	return i;
}

static int ifxf_fws_hanger_pushpkt(struct ifxf_fws_hanger *h,
				    struct sk_buff *pkt, u32 slot_id)
{
	if (slot_id >= IFXF_FWS_HANGER_MAXITEMS)
		return -ENOENT;

	if (h->items[slot_id].state != IFXF_FWS_HANGER_ITEM_STATE_FREE) {
		ifxf_err("slot is not free\n");
		h->failed_to_push++;
		return -EINVAL;
	}

	h->items[slot_id].state = IFXF_FWS_HANGER_ITEM_STATE_INUSE;
	h->items[slot_id].pkt = pkt;
	h->pushed++;
	return 0;
}

static inline int ifxf_fws_hanger_poppkt(struct ifxf_fws_hanger *h,
					  u32 slot_id, struct sk_buff **pktout,
					  bool remove_item)
{
	if (slot_id >= IFXF_FWS_HANGER_MAXITEMS)
		return -ENOENT;

	if (h->items[slot_id].state == IFXF_FWS_HANGER_ITEM_STATE_FREE) {
		ifxf_err("entry not in use\n");
		h->failed_to_pop++;
		return -EINVAL;
	}

	*pktout = h->items[slot_id].pkt;
	if (remove_item) {
		h->items[slot_id].state = IFXF_FWS_HANGER_ITEM_STATE_FREE;
		h->items[slot_id].pkt = NULL;
		h->popped++;
	}
	return 0;
}

static void ifxf_fws_psq_flush(struct ifxf_fws_info *fws, struct pktq *q,
				int ifidx)
{
	bool (*matchfn)(struct sk_buff *, void *) = NULL;
	struct sk_buff *skb;
	int prec;
	u32 hslot;

	if (ifidx != -1)
		matchfn = ifxf_fws_ifidx_match;
	for (prec = 0; prec < q->num_prec; prec++) {
		skb = ifxu_pktq_pdeq_match(q, prec, matchfn, &ifidx);
		while (skb) {
			hslot = ifxf_skb_htod_tag_get_field(skb, HSLOT);
			ifxf_fws_hanger_poppkt(&fws->hanger, hslot, &skb,
						true);
			ifxu_pkt_buf_free_skb(skb);
			skb = ifxu_pktq_pdeq_match(q, prec, matchfn, &ifidx);
		}
	}
}

static int ifxf_fws_hanger_mark_suppressed(struct ifxf_fws_hanger *h,
					    u32 slot_id)
{
	if (slot_id >= IFXF_FWS_HANGER_MAXITEMS)
		return -ENOENT;

	if (h->items[slot_id].state == IFXF_FWS_HANGER_ITEM_STATE_FREE) {
		ifxf_err("entry not in use\n");
		return -EINVAL;
	}

	h->items[slot_id].state = IFXF_FWS_HANGER_ITEM_STATE_INUSE_SUPPRESSED;
	return 0;
}

static void ifxf_fws_hanger_cleanup(struct ifxf_fws_info *fws,
				     bool (*fn)(struct sk_buff *, void *),
				     int ifidx)
{
	struct ifxf_fws_hanger *h = &fws->hanger;
	struct sk_buff *skb;
	int i;
	enum ifxf_fws_hanger_item_state s;

	for (i = 0; i < ARRAY_SIZE(h->items); i++) {
		s = h->items[i].state;
		if (s == IFXF_FWS_HANGER_ITEM_STATE_INUSE ||
		    s == IFXF_FWS_HANGER_ITEM_STATE_INUSE_SUPPRESSED) {
			skb = h->items[i].pkt;
			if (fn == NULL || fn(skb, &ifidx)) {
				/* suppress packets freed from psq */
				if (s == IFXF_FWS_HANGER_ITEM_STATE_INUSE)
					ifxu_pkt_buf_free_skb(skb);
				h->items[i].state =
					IFXF_FWS_HANGER_ITEM_STATE_FREE;
			}
		}
	}
}

static void ifxf_fws_macdesc_set_name(struct ifxf_fws_info *fws,
				       struct ifxf_fws_mac_descriptor *desc)
{
	if (desc == &fws->desc.other)
		strscpy(desc->name, "MAC-OTHER", sizeof(desc->name));
	else if (desc->mac_handle)
		scnprintf(desc->name, sizeof(desc->name), "MAC-%d:%d",
			  desc->mac_handle, desc->interface_id);
	else
		scnprintf(desc->name, sizeof(desc->name), "MACIF:%d",
			  desc->interface_id);
}

static void ifxf_fws_macdesc_init(struct ifxf_fws_mac_descriptor *desc,
				   u8 *addr, u8 ifidx)
{
	ifxf_dbg(TRACE,
		  "enter: desc %p ea=%pM, ifidx=%u\n", desc, addr, ifidx);
	desc->occupied = 1;
	desc->state = IFXF_FWS_STATE_OPEN;
	desc->requested_credit = 0;
	desc->requested_packet = 0;
	/* depending on use may need ifp->bsscfgidx instead */
	desc->interface_id = ifidx;
	desc->ac_bitmap = 0xff; /* update this when handling APSD */
	if (addr)
		memcpy(&desc->ea[0], addr, ETH_ALEN);
}

static
void ifxf_fws_macdesc_deinit(struct ifxf_fws_mac_descriptor *desc)
{
	ifxf_dbg(TRACE,
		  "enter: ea=%pM, ifidx=%u\n", desc->ea, desc->interface_id);
	desc->occupied = 0;
	desc->state = IFXF_FWS_STATE_CLOSE;
	desc->requested_credit = 0;
	desc->requested_packet = 0;
}

static struct ifxf_fws_mac_descriptor *
ifxf_fws_macdesc_lookup(struct ifxf_fws_info *fws, u8 *ea)
{
	struct ifxf_fws_mac_descriptor *entry;
	int i;

	if (ea == NULL)
		return ERR_PTR(-EINVAL);

	entry = &fws->desc.nodes[0];
	for (i = 0; i < ARRAY_SIZE(fws->desc.nodes); i++) {
		if (entry->occupied && !memcmp(entry->ea, ea, ETH_ALEN))
			return entry;
		entry++;
	}

	return ERR_PTR(-ENOENT);
}

static struct ifxf_fws_mac_descriptor*
ifxf_fws_macdesc_find(struct ifxf_fws_info *fws, struct ifxf_if *ifp, u8 *da)
{
	struct ifxf_fws_mac_descriptor *entry;
	bool multicast;

	multicast = is_multicast_ether_addr(da);

	/* Multicast destination, STA and P2P clients get the interface entry.
	 * STA/GC gets the Mac Entry for TDLS destinations, TDLS destinations
	 * have their own entry.
	 */
	if (multicast && ifp->fws_desc) {
		entry = ifp->fws_desc;
		goto done;
	}

	entry = ifxf_fws_macdesc_lookup(fws, da);
	if (IS_ERR(entry))
		entry = ifp->fws_desc;

done:
	return entry;
}

static bool ifxf_fws_macdesc_closed(struct ifxf_fws_info *fws,
				     struct ifxf_fws_mac_descriptor *entry,
				     int fifo)
{
	struct ifxf_fws_mac_descriptor *if_entry;
	bool closed;

	/* for unique destination entries the related interface
	 * may be closed.
	 */
	if (entry->mac_handle) {
		if_entry = &fws->desc.iface[entry->interface_id];
		if (if_entry->state == IFXF_FWS_STATE_CLOSE)
			return true;
	}
	/* an entry is closed when the state is closed and
	 * the firmware did not request anything.
	 */
	closed = entry->state == IFXF_FWS_STATE_CLOSE &&
		 !entry->requested_credit && !entry->requested_packet;

	/* Or firmware does not allow traffic for given fifo */
	return closed || !(entry->ac_bitmap & BIT(fifo));
}

static void ifxf_fws_macdesc_cleanup(struct ifxf_fws_info *fws,
				      struct ifxf_fws_mac_descriptor *entry,
				      int ifidx)
{
	if (entry->occupied && (ifidx == -1 || ifidx == entry->interface_id)) {
		ifxf_fws_psq_flush(fws, &entry->psq, ifidx);
		entry->occupied = !!(entry->psq.len);
	}
}

static void ifxf_fws_bus_txq_cleanup(struct ifxf_fws_info *fws,
				      bool (*fn)(struct sk_buff *, void *),
				      int ifidx)
{
	struct ifxf_fws_hanger_item *hi;
	struct pktq *txq;
	struct sk_buff *skb;
	int prec;
	u32 hslot;

	txq = ifxf_bus_gettxq(fws->drvr->bus_if);
	if (IS_ERR(txq)) {
		ifxf_dbg(TRACE, "no txq to clean up\n");
		return;
	}

	for (prec = 0; prec < txq->num_prec; prec++) {
		skb = ifxu_pktq_pdeq_match(txq, prec, fn, &ifidx);
		while (skb) {
			hslot = ifxf_skb_htod_tag_get_field(skb, HSLOT);
			hi = &fws->hanger.items[hslot];
			WARN_ON(skb != hi->pkt);
			hi->state = IFXF_FWS_HANGER_ITEM_STATE_FREE;
			ifxu_pkt_buf_free_skb(skb);
			skb = ifxu_pktq_pdeq_match(txq, prec, fn, &ifidx);
		}
	}
}

static void ifxf_fws_cleanup(struct ifxf_fws_info *fws, int ifidx)
{
	int i;
	struct ifxf_fws_mac_descriptor *table;
	bool (*matchfn)(struct sk_buff *, void *) = NULL;

	if (fws == NULL)
		return;

	if (ifidx != -1)
		matchfn = ifxf_fws_ifidx_match;

	/* cleanup individual nodes */
	table = &fws->desc.nodes[0];
	for (i = 0; i < ARRAY_SIZE(fws->desc.nodes); i++)
		ifxf_fws_macdesc_cleanup(fws, &table[i], ifidx);

	ifxf_fws_macdesc_cleanup(fws, &fws->desc.other, ifidx);
	ifxf_fws_bus_txq_cleanup(fws, matchfn, ifidx);
	ifxf_fws_hanger_cleanup(fws, matchfn, ifidx);
}

static u8 ifxf_fws_hdrpush(struct ifxf_fws_info *fws, struct sk_buff *skb)
{
	struct ifxf_fws_mac_descriptor *entry = ifxf_skbcb(skb)->mac;
	u8 *wlh;
	u16 data_offset = 0;
	u8 fillers;
	__le32 pkttag = cpu_to_le32(ifxf_skbcb(skb)->htod);
	__le16 pktseq = cpu_to_le16(ifxf_skbcb(skb)->htod_seq);

	ifxf_dbg(TRACE, "enter: %s, idx=%d hslot=%d htod %X seq %X\n",
		  entry->name, ifxf_skb_if_flags_get_field(skb, INDEX),
		  (le32_to_cpu(pkttag) >> 8) & 0xffff,
		  ifxf_skbcb(skb)->htod, ifxf_skbcb(skb)->htod_seq);
	if (entry->send_tim_signal)
		data_offset += 2 + IFXF_FWS_TYPE_PENDING_TRAFFIC_BMP_LEN;
	if (IFXF_FWS_MODE_GET_REUSESEQ(fws->mode))
		data_offset += IFXF_FWS_TYPE_SEQ_LEN;
	/* +2 is for Type[1] and Len[1] in TLV, plus TIM signal */
	data_offset += 2 + IFXF_FWS_TYPE_PKTTAG_LEN;
	fillers = round_up(data_offset, 4) - data_offset;
	data_offset += fillers;

	skb_push(skb, data_offset);
	wlh = skb->data;

	wlh[0] = IFXF_FWS_TYPE_PKTTAG;
	wlh[1] = IFXF_FWS_TYPE_PKTTAG_LEN;
	memcpy(&wlh[2], &pkttag, sizeof(pkttag));
	if (IFXF_FWS_MODE_GET_REUSESEQ(fws->mode)) {
		wlh[1] += IFXF_FWS_TYPE_SEQ_LEN;
		memcpy(&wlh[2 + IFXF_FWS_TYPE_PKTTAG_LEN], &pktseq,
		       sizeof(pktseq));
	}
	wlh += wlh[1] + 2;

	if (entry->send_tim_signal) {
		entry->send_tim_signal = false;
		wlh[0] = IFXF_FWS_TYPE_PENDING_TRAFFIC_BMP;
		wlh[1] = IFXF_FWS_TYPE_PENDING_TRAFFIC_BMP_LEN;
		wlh[2] = entry->mac_handle;
		wlh[3] = entry->traffic_pending_bmp;
		ifxf_dbg(TRACE, "adding TIM info: handle %d bmp 0x%X\n",
			  entry->mac_handle, entry->traffic_pending_bmp);
		wlh += IFXF_FWS_TYPE_PENDING_TRAFFIC_BMP_LEN + 2;
		entry->traffic_lastreported_bmp = entry->traffic_pending_bmp;
	}
	if (fillers)
		memset(wlh, IFXF_FWS_TYPE_FILLER, fillers);

	return (u8)(data_offset >> 2);
}

static bool ifxf_fws_tim_update(struct ifxf_fws_info *fws,
				 struct ifxf_fws_mac_descriptor *entry,
				 int fifo, bool send_immediately)
{
	struct sk_buff *skb;
	struct ifxf_skbuff_cb *skcb;
	s32 err;
	u32 len;
	u8 data_offset;
	int ifidx;

	/* check delayedQ and suppressQ in one call using bitmap */
	if (ifxu_pktq_mlen(&entry->psq, 3 << (fifo * 2)) == 0)
		entry->traffic_pending_bmp &= ~NBITVAL(fifo);
	else
		entry->traffic_pending_bmp |= NBITVAL(fifo);

	entry->send_tim_signal = false;
	if (entry->traffic_lastreported_bmp != entry->traffic_pending_bmp)
		entry->send_tim_signal = true;
	if (send_immediately && entry->send_tim_signal &&
	    entry->state == IFXF_FWS_STATE_CLOSE) {
		/* create a dummy packet and sent that. The traffic          */
		/* bitmap info will automatically be attached to that packet */
		len = IFXF_FWS_TYPE_PKTTAG_LEN + 2 +
		      IFXF_FWS_TYPE_SEQ_LEN +
		      IFXF_FWS_TYPE_PENDING_TRAFFIC_BMP_LEN + 2 +
		      4 + fws->drvr->hdrlen;
		skb = ifxu_pkt_buf_get_skb(len);
		if (skb == NULL)
			return false;
		skb_pull(skb, len);
		skcb = ifxf_skbcb(skb);
		skcb->mac = entry;
		skcb->state = IFXF_FWS_SKBSTATE_TIM;
		skcb->htod = 0;
		skcb->htod_seq = 0;
		data_offset = ifxf_fws_hdrpush(fws, skb);
		ifidx = ifxf_skb_if_flags_get_field(skb, INDEX);
		ifxf_fws_unlock(fws);
		err = ifxf_proto_txdata(fws->drvr, ifidx, data_offset, skb);
		ifxf_fws_lock(fws);
		if (err)
			ifxu_pkt_buf_free_skb(skb);
		return true;
	}
	return false;
}

static void
ifxf_fws_flow_control_check(struct ifxf_fws_info *fws, struct pktq *pq,
			     u8 if_id)
{
	struct ifxf_if *ifp = ifxf_get_ifp(fws->drvr, if_id);

	if (WARN_ON(!ifp))
		return;

	if ((ifp->netif_stop & IFXF_NETIF_STOP_REASON_FWS_FC) &&
	    pq->len <= IFXF_FWS_FLOWCONTROL_LOWATER)
		ifxf_txflowblock_if(ifp,
				     IFXF_NETIF_STOP_REASON_FWS_FC, false);
	if (!(ifp->netif_stop & IFXF_NETIF_STOP_REASON_FWS_FC) &&
	    pq->len >= IFXF_FWS_FLOWCONTROL_HIWATER) {
		fws->stats.fws_flow_block++;
		ifxf_txflowblock_if(ifp, IFXF_NETIF_STOP_REASON_FWS_FC, true);
	}
	return;
}

static int ifxf_fws_rssi_indicate(struct ifxf_fws_info *fws, s8 rssi)
{
	ifxf_dbg(CTL, "rssi %d\n", rssi);
	return 0;
}

static
int ifxf_fws_macdesc_indicate(struct ifxf_fws_info *fws, u8 type, u8 *data)
{
	struct ifxf_fws_mac_descriptor *entry, *existing;
	u8 mac_handle;
	u8 ifidx;
	u8 *addr;

	mac_handle = *data++;
	ifidx = *data++;
	addr = data;

	entry = &fws->desc.nodes[mac_handle & 0x1F];
	if (type == IFXF_FWS_TYPE_MACDESC_DEL) {
		if (entry->occupied) {
			ifxf_dbg(TRACE, "deleting %s mac %pM\n",
				  entry->name, addr);
			ifxf_fws_lock(fws);
			ifxf_fws_macdesc_cleanup(fws, entry, -1);
			ifxf_fws_macdesc_deinit(entry);
			ifxf_fws_unlock(fws);
		} else
			fws->stats.mac_update_failed++;
		return 0;
	}

	existing = ifxf_fws_macdesc_lookup(fws, addr);
	if (IS_ERR(existing)) {
		if (!entry->occupied) {
			ifxf_fws_lock(fws);
			entry->mac_handle = mac_handle;
			ifxf_fws_macdesc_init(entry, addr, ifidx);
			ifxf_fws_macdesc_set_name(fws, entry);
			ifxu_pktq_init(&entry->psq, IFXF_FWS_PSQ_PREC_COUNT,
					IFXF_FWS_PSQ_LEN);
			ifxf_fws_unlock(fws);
			ifxf_dbg(TRACE, "add %s mac %pM\n", entry->name, addr);
		} else {
			fws->stats.mac_update_failed++;
		}
	} else {
		if (entry != existing) {
			ifxf_dbg(TRACE, "copy mac %s\n", existing->name);
			ifxf_fws_lock(fws);
			memcpy(entry, existing,
			       offsetof(struct ifxf_fws_mac_descriptor, psq));
			entry->mac_handle = mac_handle;
			ifxf_fws_macdesc_deinit(existing);
			ifxf_fws_macdesc_set_name(fws, entry);
			ifxf_fws_unlock(fws);
			ifxf_dbg(TRACE, "relocate %s mac %pM\n", entry->name,
				  addr);
		} else {
			ifxf_dbg(TRACE, "use existing\n");
			WARN_ON(entry->mac_handle != mac_handle);
			/* TODO: what should we do here: continue, reinit, .. */
		}
	}
	return 0;
}

static int ifxf_fws_macdesc_state_indicate(struct ifxf_fws_info *fws,
					    u8 type, u8 *data)
{
	struct ifxf_fws_mac_descriptor *entry;
	u8 mac_handle;
	int ret;

	mac_handle = data[0];
	entry = &fws->desc.nodes[mac_handle & 0x1F];
	if (!entry->occupied) {
		fws->stats.mac_ps_update_failed++;
		return -ESRCH;
	}
	ifxf_fws_lock(fws);
	/* a state update should wipe old credits */
	entry->requested_credit = 0;
	entry->requested_packet = 0;
	if (type == IFXF_FWS_TYPE_MAC_OPEN) {
		entry->state = IFXF_FWS_STATE_OPEN;
		ret = IFXF_FWS_RET_OK_SCHEDULE;
	} else {
		entry->state = IFXF_FWS_STATE_CLOSE;
		ifxf_fws_tim_update(fws, entry, IFXF_FWS_FIFO_AC_BK, false);
		ifxf_fws_tim_update(fws, entry, IFXF_FWS_FIFO_AC_BE, false);
		ifxf_fws_tim_update(fws, entry, IFXF_FWS_FIFO_AC_VI, false);
		ifxf_fws_tim_update(fws, entry, IFXF_FWS_FIFO_AC_VO, true);
		ret = IFXF_FWS_RET_OK_NOSCHEDULE;
	}
	ifxf_fws_unlock(fws);
	return ret;
}

static int ifxf_fws_interface_state_indicate(struct ifxf_fws_info *fws,
					      u8 type, u8 *data)
{
	struct ifxf_fws_mac_descriptor *entry;
	u8 ifidx;
	int ret;

	ifidx = data[0];

	if (ifidx >= IFXF_MAX_IFS) {
		ret = -ERANGE;
		goto fail;
	}

	entry = &fws->desc.iface[ifidx];
	if (!entry->occupied) {
		ret = -ESRCH;
		goto fail;
	}

	ifxf_dbg(TRACE, "%s (%d): %s\n", ifxf_fws_get_tlv_name(type), type,
		  entry->name);
	ifxf_fws_lock(fws);
	switch (type) {
	case IFXF_FWS_TYPE_INTERFACE_OPEN:
		entry->state = IFXF_FWS_STATE_OPEN;
		ret = IFXF_FWS_RET_OK_SCHEDULE;
		break;
	case IFXF_FWS_TYPE_INTERFACE_CLOSE:
		entry->state = IFXF_FWS_STATE_CLOSE;
		ret = IFXF_FWS_RET_OK_NOSCHEDULE;
		break;
	default:
		ret = -EINVAL;
		ifxf_fws_unlock(fws);
		goto fail;
	}
	ifxf_fws_unlock(fws);
	return ret;

fail:
	fws->stats.if_update_failed++;
	return ret;
}

static int ifxf_fws_request_indicate(struct ifxf_fws_info *fws, u8 type,
				      u8 *data)
{
	struct ifxf_fws_mac_descriptor *entry;

	entry = &fws->desc.nodes[data[1] & 0x1F];
	if (!entry->occupied) {
		if (type == IFXF_FWS_TYPE_MAC_REQUEST_CREDIT)
			fws->stats.credit_request_failed++;
		else
			fws->stats.packet_request_failed++;
		return -ESRCH;
	}

	ifxf_dbg(TRACE, "%s (%d): %s cnt %d bmp %d\n",
		  ifxf_fws_get_tlv_name(type), type, entry->name,
		  data[0], data[2]);
	ifxf_fws_lock(fws);
	if (type == IFXF_FWS_TYPE_MAC_REQUEST_CREDIT)
		entry->requested_credit = data[0];
	else
		entry->requested_packet = data[0];

	entry->ac_bitmap = data[2];
	ifxf_fws_unlock(fws);
	return IFXF_FWS_RET_OK_SCHEDULE;
}

static void
ifxf_fws_macdesc_use_req_credit(struct ifxf_fws_mac_descriptor *entry,
				 struct sk_buff *skb)
{
	if (entry->requested_credit > 0) {
		entry->requested_credit--;
		ifxf_skb_if_flags_set_field(skb, REQUESTED, 1);
		ifxf_skb_if_flags_set_field(skb, REQ_CREDIT, 1);
		if (entry->state != IFXF_FWS_STATE_CLOSE)
			ifxf_err("requested credit set while mac not closed!\n");
	} else if (entry->requested_packet > 0) {
		entry->requested_packet--;
		ifxf_skb_if_flags_set_field(skb, REQUESTED, 1);
		ifxf_skb_if_flags_set_field(skb, REQ_CREDIT, 0);
		if (entry->state != IFXF_FWS_STATE_CLOSE)
			ifxf_err("requested packet set while mac not closed!\n");
	} else {
		ifxf_skb_if_flags_set_field(skb, REQUESTED, 0);
		ifxf_skb_if_flags_set_field(skb, REQ_CREDIT, 0);
	}
}

static void ifxf_fws_macdesc_return_req_credit(struct sk_buff *skb)
{
	struct ifxf_fws_mac_descriptor *entry = ifxf_skbcb(skb)->mac;

	if ((ifxf_skb_if_flags_get_field(skb, REQ_CREDIT)) &&
	    (entry->state == IFXF_FWS_STATE_CLOSE))
		entry->requested_credit++;
}

static void ifxf_fws_return_credits(struct ifxf_fws_info *fws,
				     u8 fifo, u8 credits)
{
	int lender_ac;
	int *borrowed;
	int *fifo_credit;

	if (!credits)
		return;

	fws->fifo_credit_map |= 1 << fifo;

	if (fifo > IFXF_FWS_FIFO_AC_BK &&
	    fifo <= IFXF_FWS_FIFO_AC_VO) {
		for (lender_ac = IFXF_FWS_FIFO_AC_VO; lender_ac >= 0;
		     lender_ac--) {
			borrowed = &fws->credits_borrowed[fifo][lender_ac];
			if (*borrowed) {
				fws->fifo_credit_map |= (1 << lender_ac);
				fifo_credit = &fws->fifo_credit[lender_ac];
				if (*borrowed >= credits) {
					*borrowed -= credits;
					*fifo_credit += credits;
					return;
				} else {
					credits -= *borrowed;
					*fifo_credit += *borrowed;
					*borrowed = 0;
				}
			}
		}
	}

	if (credits) {
		fws->fifo_credit[fifo] += credits;
	}

	if (fws->fifo_credit[fifo] > fws->init_fifo_credit[fifo])
		fws->fifo_credit[fifo] = fws->init_fifo_credit[fifo];

}

static void ifxf_fws_schedule_deq(struct ifxf_fws_info *fws)
{
	/* only schedule dequeue when there are credits for delayed traffic */
	if ((fws->fifo_credit_map & fws->fifo_delay_map) ||
	    (!ifxf_fws_fc_active(fws) && fws->fifo_delay_map))
		queue_work(fws->fws_wq, &fws->fws_dequeue_work);
}

static int ifxf_fws_enq(struct ifxf_fws_info *fws,
			 enum ifxf_fws_skb_state state, int fifo,
			 struct sk_buff *p)
{
	struct ifxf_pub *drvr = fws->drvr;
	int prec = 2 * fifo;
	u32 *qfull_stat = &fws->stats.delayq_full_error;
	struct ifxf_fws_mac_descriptor *entry;
	struct pktq *pq;
	struct sk_buff_head *queue;
	struct sk_buff *p_head;
	struct sk_buff *p_tail;
	u32 fr_new;
	u32 fr_compare;

	entry = ifxf_skbcb(p)->mac;
	if (entry == NULL) {
		bphy_err(drvr, "no mac descriptor found for skb %p\n", p);
		return -ENOENT;
	}

	ifxf_dbg(DATA, "enter: fifo %d skb %p\n", fifo, p);
	if (state == IFXF_FWS_SKBSTATE_SUPPRESSED) {
		prec += 1;
		qfull_stat = &fws->stats.supprq_full_error;

		/* Fix out of order delivery of frames. Dont assume frame    */
		/* can be inserted at the end, but look for correct position */
		pq = &entry->psq;
		if (pktq_full(pq) || pktq_pfull(pq, prec)) {
			*qfull_stat += 1;
			return -ENFILE;
		}
		queue = &pq->q[prec].skblist;

		p_head = skb_peek(queue);
		p_tail = skb_peek_tail(queue);
		fr_new = ifxf_skb_htod_tag_get_field(p, FREERUN);

		while (p_head != p_tail) {
			fr_compare = ifxf_skb_htod_tag_get_field(p_tail,
								  FREERUN);
			/* be sure to handle wrap of 256 */
			if (((fr_new > fr_compare) &&
			     ((fr_new - fr_compare) < 128)) ||
			    ((fr_new < fr_compare) &&
			     ((fr_compare - fr_new) > 128)))
				break;
			p_tail = skb_queue_prev(queue, p_tail);
		}
		/* Position found. Determine what to do */
		if (p_tail == NULL) {
			/* empty list */
			__skb_queue_tail(queue, p);
		} else {
			fr_compare = ifxf_skb_htod_tag_get_field(p_tail,
								  FREERUN);
			if (((fr_new > fr_compare) &&
			     ((fr_new - fr_compare) < 128)) ||
			    ((fr_new < fr_compare) &&
			     ((fr_compare - fr_new) > 128))) {
				/* After tail */
				__skb_queue_after(queue, p_tail, p);
			} else {
				/* Before tail */
				__skb_insert(p, p_tail->prev, p_tail, queue);
			}
		}

		/* Complete the counters and statistics */
		pq->len++;
		if (pq->hi_prec < prec)
			pq->hi_prec = (u8) prec;
	} else if (ifxu_pktq_penq(&entry->psq, prec, p) == NULL) {
		*qfull_stat += 1;
		return -ENFILE;
	}

	/* increment total enqueued packet count */
	fws->fifo_delay_map |= 1 << fifo;
	fws->fifo_enqpkt[fifo]++;

	/* update the sk_buff state */
	ifxf_skbcb(p)->state = state;

	/*
	 * A packet has been pushed so update traffic
	 * availability bitmap, if applicable
	 */
	ifxf_fws_tim_update(fws, entry, fifo, true);
	ifxf_fws_flow_control_check(fws, &entry->psq,
				     ifxf_skb_if_flags_get_field(p, INDEX));
	return 0;
}

static struct sk_buff *ifxf_fws_deq(struct ifxf_fws_info *fws, int fifo)
{
	struct ifxf_fws_mac_descriptor *table;
	struct ifxf_fws_mac_descriptor *entry;
	struct sk_buff *p;
	int num_nodes;
	int node_pos;
	int prec_out;
	int pmsk;
	int i;

	table = (struct ifxf_fws_mac_descriptor *)&fws->desc;
	num_nodes = sizeof(fws->desc) / sizeof(struct ifxf_fws_mac_descriptor);
	node_pos = fws->deq_node_pos[fifo];

	for (i = 0; i < num_nodes; i++) {
		entry = &table[(node_pos + i) % num_nodes];
		if (!entry->occupied ||
		    ifxf_fws_macdesc_closed(fws, entry, fifo))
			continue;

		if (entry->suppressed)
			pmsk = 2;
		else
			pmsk = 3;
		p = ifxu_pktq_mdeq(&entry->psq, pmsk << (fifo * 2), &prec_out);
		if (p == NULL) {
			if (entry->suppressed) {
				if (entry->suppr_transit_count)
					continue;
				entry->suppressed = false;
				p = ifxu_pktq_mdeq(&entry->psq,
						    1 << (fifo * 2), &prec_out);
			}
		}
		if  (p == NULL)
			continue;

		ifxf_fws_macdesc_use_req_credit(entry, p);

		/* move dequeue position to ensure fair round-robin */
		fws->deq_node_pos[fifo] = (node_pos + i + 1) % num_nodes;
		ifxf_fws_flow_control_check(fws, &entry->psq,
					     ifxf_skb_if_flags_get_field(p,
									  INDEX)
					     );
		/*
		 * A packet has been picked up, update traffic
		 * availability bitmap, if applicable
		 */
		ifxf_fws_tim_update(fws, entry, fifo, false);

		/*
		 * decrement total enqueued fifo packets and
		 * clear delay bitmap if done.
		 */
		fws->fifo_enqpkt[fifo]--;
		if (fws->fifo_enqpkt[fifo] == 0)
			fws->fifo_delay_map &= ~(1 << fifo);
		goto done;
	}
	p = NULL;
done:
	ifxf_dbg(DATA, "exit: fifo %d skb %p\n", fifo, p);
	return p;
}

static int ifxf_fws_txstatus_suppressed(struct ifxf_fws_info *fws, int fifo,
					 struct sk_buff *skb,
					 u32 genbit, u16 seq)
{
	struct ifxf_fws_mac_descriptor *entry = ifxf_skbcb(skb)->mac;
	u32 hslot;
	int ret;

	hslot = ifxf_skb_htod_tag_get_field(skb, HSLOT);

	/* this packet was suppressed */
	if (!entry->suppressed) {
		entry->suppressed = true;
		entry->suppr_transit_count = entry->transit_count;
		ifxf_dbg(DATA, "suppress %s: transit %d\n",
			  entry->name, entry->transit_count);
	}

	entry->generation = genbit;

	ifxf_skb_htod_tag_set_field(skb, GENERATION, genbit);
	ifxf_skbcb(skb)->htod_seq = seq;
	if (ifxf_skb_htod_seq_get_field(skb, FROMFW)) {
		ifxf_skb_htod_seq_set_field(skb, FROMDRV, 1);
		ifxf_skb_htod_seq_set_field(skb, FROMFW, 0);
	} else {
		ifxf_skb_htod_seq_set_field(skb, FROMDRV, 0);
	}
	ret = ifxf_fws_enq(fws, IFXF_FWS_SKBSTATE_SUPPRESSED, fifo, skb);

	if (ret != 0) {
		/* suppress q is full drop this packet */
		ifxf_fws_hanger_poppkt(&fws->hanger, hslot, &skb, true);
	} else {
		/* Mark suppressed to avoid a double free during wlfc cleanup */
		ifxf_fws_hanger_mark_suppressed(&fws->hanger, hslot);
	}

	return ret;
}

static int
ifxf_fws_txs_process(struct ifxf_fws_info *fws, u8 flags, u32 hslot,
		      u32 genbit, u16 seq, u8 compcnt)
{
	struct ifxf_pub *drvr = fws->drvr;
	u32 fifo;
	u8 cnt = 0;
	int ret;
	bool remove_from_hanger = true;
	struct sk_buff *skb;
	struct ifxf_skbuff_cb *skcb;
	struct ifxf_fws_mac_descriptor *entry = NULL;
	struct ifxf_if *ifp;

	ifxf_dbg(DATA, "flags %d\n", flags);

	if (flags == IFXF_FWS_TXSTATUS_DISCARD)
		fws->stats.txs_discard += compcnt;
	else if (flags == IFXF_FWS_TXSTATUS_CORE_SUPPRESS) {
		fws->stats.txs_supp_core += compcnt;
		remove_from_hanger = false;
	} else if (flags == IFXF_FWS_TXSTATUS_FW_PS_SUPPRESS) {
		fws->stats.txs_supp_ps += compcnt;
		remove_from_hanger = false;
	} else if (flags == IFXF_FWS_TXSTATUS_FW_TOSSED)
		fws->stats.txs_tossed += compcnt;
	else if (flags == IFXF_FWS_TXSTATUS_FW_DISCARD_NOACK)
		fws->stats.txs_discard += compcnt;
	else if (flags == IFXF_FWS_TXSTATUS_FW_SUPPRESS_ACKED)
		fws->stats.txs_discard += compcnt;
	else if (flags == IFXF_FWS_TXSTATUS_HOST_TOSSED)
		fws->stats.txs_host_tossed += compcnt;
	else
		bphy_err(drvr, "unexpected txstatus\n");

	while (cnt < compcnt) {
		ret = ifxf_fws_hanger_poppkt(&fws->hanger, hslot, &skb,
					      remove_from_hanger);
		if (ret != 0) {
			bphy_err(drvr, "no packet in hanger slot: hslot=%d\n",
				 hslot);
			goto cont;
		}

		skcb = ifxf_skbcb(skb);
		entry = skcb->mac;
		if (WARN_ON(!entry)) {
			ifxu_pkt_buf_free_skb(skb);
			goto cont;
		}
		entry->transit_count--;
		if (entry->suppressed && entry->suppr_transit_count)
			entry->suppr_transit_count--;

		ifxf_dbg(DATA, "%s flags %d htod %X seq %X\n", entry->name,
			  flags, skcb->htod, seq);

		/* pick up the implicit credit from this packet */
		fifo = ifxf_skb_htod_tag_get_field(skb, FIFO);
		if (fws->fcmode == IFXF_FWS_FCMODE_IMPLIED_CREDIT ||
		    (ifxf_skb_if_flags_get_field(skb, REQ_CREDIT)) ||
		    flags == IFXF_FWS_TXSTATUS_HOST_TOSSED) {
			ifxf_fws_return_credits(fws, fifo, 1);
			ifxf_fws_schedule_deq(fws);
		}
		ifxf_fws_macdesc_return_req_credit(skb);

		ret = ifxf_proto_hdrpull(fws->drvr, false, skb, &ifp);
		if (ret) {
			ifxu_pkt_buf_free_skb(skb);
			goto cont;
		}
		if (!remove_from_hanger)
			ret = ifxf_fws_txstatus_suppressed(fws, fifo, skb,
							    genbit, seq);
		if (remove_from_hanger || ret)
			ifxf_txfinalize(ifp, skb, true);

cont:
		hslot = (hslot + 1) & (IFXF_FWS_TXSTAT_HSLOT_MASK >>
				       IFXF_FWS_TXSTAT_HSLOT_SHIFT);
		if (IFXF_FWS_MODE_GET_REUSESEQ(fws->mode))
			seq = (seq + 1) & IFXF_SKB_HTOD_SEQ_NR_MASK;

		cnt++;
	}

	return 0;
}

static int ifxf_fws_fifocreditback_indicate(struct ifxf_fws_info *fws,
					     u8 *data)
{
	int i;

	if (fws->fcmode != IFXF_FWS_FCMODE_EXPLICIT_CREDIT) {
		ifxf_dbg(INFO, "ignored\n");
		return IFXF_FWS_RET_OK_NOSCHEDULE;
	}

	ifxf_dbg(DATA, "enter: data %pM\n", data);
	ifxf_fws_lock(fws);
	for (i = 0; i < IFXF_FWS_FIFO_COUNT; i++)
		ifxf_fws_return_credits(fws, i, data[i]);

	ifxf_dbg(DATA, "map: credit %x delay %x\n", fws->fifo_credit_map,
		  fws->fifo_delay_map);
	ifxf_fws_unlock(fws);
	return IFXF_FWS_RET_OK_SCHEDULE;
}

static int ifxf_fws_txstatus_indicate(struct ifxf_fws_info *fws, u8 type,
				       u8 *data)
{
	__le32 status_le;
	__le16 seq_le;
	u32 status;
	u32 hslot;
	u32 genbit;
	u8 flags;
	u16 seq;
	u8 compcnt;
	u8 compcnt_offset = IFXF_FWS_TYPE_TXSTATUS_LEN;

	memcpy(&status_le, data, sizeof(status_le));
	status = le32_to_cpu(status_le);
	flags = ifxf_txstatus_get_field(status, FLAGS);
	hslot = ifxf_txstatus_get_field(status, HSLOT);
	genbit = ifxf_txstatus_get_field(status, GENERATION);
	if (IFXF_FWS_MODE_GET_REUSESEQ(fws->mode)) {
		memcpy(&seq_le, &data[IFXF_FWS_TYPE_TXSTATUS_LEN],
		       sizeof(seq_le));
		seq = le16_to_cpu(seq_le);
		compcnt_offset += IFXF_FWS_TYPE_SEQ_LEN;
	} else {
		seq = 0;
	}

	if (type == IFXF_FWS_TYPE_COMP_TXSTATUS)
		compcnt = data[compcnt_offset];
	else
		compcnt = 1;
	fws->stats.txs_indicate += compcnt;

	ifxf_fws_lock(fws);
	ifxf_fws_txs_process(fws, flags, hslot, genbit, seq, compcnt);
	ifxf_fws_unlock(fws);
	return IFXF_FWS_RET_OK_NOSCHEDULE;
}

static int ifxf_fws_dbg_seqnum_check(struct ifxf_fws_info *fws, u8 *data)
{
	__le32 timestamp;

	memcpy(&timestamp, &data[2], sizeof(timestamp));
	ifxf_dbg(CTL, "received: seq %d, timestamp %d\n", data[1],
		  le32_to_cpu(timestamp));
	return 0;
}

static int ifxf_fws_notify_credit_map(struct ifxf_if *ifp,
				       const struct ifxf_event_msg *e,
				       void *data)
{
	struct ifxf_pub *drvr = ifp->drvr;
	struct ifxf_fws_info *fws = drvr_to_fws(drvr);
	int i;
	u8 *credits = data;

	if (e->datalen < IFXF_FWS_FIFO_COUNT) {
		bphy_err(drvr, "event payload too small (%d)\n", e->datalen);
		return -EINVAL;
	}

	fws->creditmap_received = true;

	ifxf_dbg(TRACE, "enter: credits %pM\n", credits);
	ifxf_fws_lock(fws);
	for (i = 0; i < ARRAY_SIZE(fws->fifo_credit); i++) {
		fws->fifo_credit[i] += credits[i] - fws->init_fifo_credit[i];
		fws->init_fifo_credit[i] = credits[i];
		if (fws->fifo_credit[i] > 0)
			fws->fifo_credit_map |= 1 << i;
		else
			fws->fifo_credit_map &= ~(1 << i);

		WARN_ONCE(fws->fifo_credit[i] < 0,
			  "fifo_credit[%d] is negative(%d)\n", i,
			  fws->fifo_credit[i]);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0))
		fws->fifo_init_credit[i] = fws->fifo_credit[i];
#endif
	}
	ifxf_fws_schedule_deq(fws);
	ifxf_fws_unlock(fws);
	return 0;
}

static int ifxf_fws_notify_bcmc_credit_support(struct ifxf_if *ifp,
						const struct ifxf_event_msg *e,
						void *data)
{
	struct ifxf_fws_info *fws = drvr_to_fws(ifp->drvr);

	if (fws) {
		ifxf_fws_lock(fws);
		fws->bcmc_credit_check = true;
		ifxf_fws_unlock(fws);
	}
	return 0;
}

static void ifxf_rxreorder_get_skb_list(struct ifxf_ampdu_rx_reorder *rfi,
					 u8 start, u8 end,
					 struct sk_buff_head *skb_list)
{
	/* initialize return list */
	__skb_queue_head_init(skb_list);

	if (rfi->pend_pkts == 0) {
		ifxf_dbg(INFO, "no packets in reorder queue\n");
		return;
	}

	do {
		if (rfi->pktslots[start]) {
			__skb_queue_tail(skb_list, rfi->pktslots[start]);
			rfi->pktslots[start] = NULL;
		}
		start++;
		if (start > rfi->max_idx)
			start = 0;
	} while (start != end);
	rfi->pend_pkts -= skb_queue_len(skb_list);
}

void ifxf_fws_rxreorder(struct ifxf_if *ifp, struct sk_buff *pkt)
{
	struct ifxf_pub *drvr = ifp->drvr;
	u8 *reorder_data;
	u8 flow_id, max_idx, cur_idx, exp_idx, end_idx;
	struct ifxf_ampdu_rx_reorder *rfi;
	struct sk_buff_head reorder_list;
	struct sk_buff *pnext;
	u8 flags;
	u32 buf_size;

	reorder_data = ((struct ifxf_skb_reorder_data *)pkt->cb)->reorder;
	flow_id = reorder_data[IFXF_RXREORDER_FLOWID_OFFSET];
	flags = reorder_data[IFXF_RXREORDER_FLAGS_OFFSET];

	/* validate flags and flow id */
	if (flags == 0xFF) {
		bphy_err(drvr, "invalid flags...so ignore this packet\n");
		ifxf_netif_rx(ifp, pkt);
		return;
	}

	rfi = ifp->drvr->reorder_flows[flow_id];
	if (flags & IFXF_RXREORDER_DEL_FLOW) {
		ifxf_dbg(INFO, "flow-%d: delete\n",
			  flow_id);

		if (rfi == NULL) {
			ifxf_dbg(INFO, "received flags to cleanup, but no flow (%d) yet\n",
				  flow_id);
			ifxf_netif_rx(ifp, pkt);
			return;
		}

		ifxf_rxreorder_get_skb_list(rfi, rfi->exp_idx, rfi->exp_idx,
					     &reorder_list);
		/* add the last packet */
		__skb_queue_tail(&reorder_list, pkt);
		kfree(rfi);
		ifp->drvr->reorder_flows[flow_id] = NULL;
		goto netif_rx;
	}
	/* from here on we need a flow reorder instance */
	if (rfi == NULL) {
		buf_size = sizeof(*rfi);
		max_idx = reorder_data[IFXF_RXREORDER_MAXIDX_OFFSET];

		buf_size += (max_idx + 1) * sizeof(pkt);

		/* allocate space for flow reorder info */
		ifxf_dbg(INFO, "flow-%d: start, maxidx %d\n",
			  flow_id, max_idx);
		rfi = kzalloc(buf_size, GFP_ATOMIC);
		if (rfi == NULL) {
			bphy_err(drvr, "failed to alloc buffer\n");
			ifxf_netif_rx(ifp, pkt);
			return;
		}

		ifp->drvr->reorder_flows[flow_id] = rfi;
		rfi->pktslots = (struct sk_buff **)(rfi + 1);
		rfi->max_idx = max_idx;
	}
	if (flags & IFXF_RXREORDER_NEW_HOLE)  {
		if (rfi->pend_pkts) {
			ifxf_rxreorder_get_skb_list(rfi, rfi->exp_idx,
						     rfi->exp_idx,
						     &reorder_list);
			WARN_ON(rfi->pend_pkts);
		} else {
			__skb_queue_head_init(&reorder_list);
		}
		rfi->cur_idx = reorder_data[IFXF_RXREORDER_CURIDX_OFFSET];
		rfi->exp_idx = reorder_data[IFXF_RXREORDER_EXPIDX_OFFSET];
		rfi->max_idx = reorder_data[IFXF_RXREORDER_MAXIDX_OFFSET];
		rfi->pktslots[rfi->cur_idx] = pkt;
		rfi->pend_pkts++;
		ifxf_dbg(DATA, "flow-%d: new hole %d (%d), pending %d\n",
			  flow_id, rfi->cur_idx, rfi->exp_idx, rfi->pend_pkts);
	} else if (flags & IFXF_RXREORDER_CURIDX_VALID) {
		cur_idx = reorder_data[IFXF_RXREORDER_CURIDX_OFFSET];
		exp_idx = reorder_data[IFXF_RXREORDER_EXPIDX_OFFSET];

		if ((exp_idx == rfi->exp_idx) && (cur_idx != rfi->exp_idx)) {
			/* still in the current hole */
			/* enqueue the current on the buffer chain */
			if (rfi->pktslots[cur_idx] != NULL) {
				ifxf_dbg(INFO, "HOLE: ERROR buffer pending..free it\n");
				ifxu_pkt_buf_free_skb(rfi->pktslots[cur_idx]);
				rfi->pktslots[cur_idx] = NULL;
			}
			rfi->pktslots[cur_idx] = pkt;
			rfi->pend_pkts++;
			rfi->cur_idx = cur_idx;
			ifxf_dbg(DATA, "flow-%d: store pkt %d (%d), pending %d\n",
				  flow_id, cur_idx, exp_idx, rfi->pend_pkts);

			/* can return now as there is no reorder
			 * list to process.
			 */
			return;
		}
		if (rfi->exp_idx == cur_idx) {
			if (rfi->pktslots[cur_idx] != NULL) {
				ifxf_dbg(INFO, "error buffer pending..free it\n");
				ifxu_pkt_buf_free_skb(rfi->pktslots[cur_idx]);
				rfi->pktslots[cur_idx] = NULL;
			}
			rfi->pktslots[cur_idx] = pkt;
			rfi->pend_pkts++;

			/* got the expected one. flush from current to expected
			 * and update expected
			 */
			ifxf_dbg(DATA, "flow-%d: expected %d (%d), pending %d\n",
				  flow_id, cur_idx, exp_idx, rfi->pend_pkts);

			rfi->cur_idx = cur_idx;
			rfi->exp_idx = exp_idx;

			ifxf_rxreorder_get_skb_list(rfi, cur_idx, exp_idx,
						     &reorder_list);
			ifxf_dbg(DATA, "flow-%d: freeing buffers %d, pending %d\n",
				  flow_id, skb_queue_len(&reorder_list),
				  rfi->pend_pkts);
		} else {
			u8 end_idx;

			ifxf_dbg(DATA, "flow-%d (0x%x): both moved, old %d/%d, new %d/%d\n",
				  flow_id, flags, rfi->cur_idx, rfi->exp_idx,
				  cur_idx, exp_idx);
			if (flags & IFXF_RXREORDER_FLUSH_ALL)
				end_idx = rfi->exp_idx;
			else
				end_idx = exp_idx;

			/* flush pkts first */
			ifxf_rxreorder_get_skb_list(rfi, rfi->exp_idx, end_idx,
						     &reorder_list);

			if (exp_idx == ((cur_idx + 1) % (rfi->max_idx + 1))) {
				__skb_queue_tail(&reorder_list, pkt);
			} else {
				rfi->pktslots[cur_idx] = pkt;
				rfi->pend_pkts++;
			}
			rfi->exp_idx = exp_idx;
			rfi->cur_idx = cur_idx;
		}
	} else {
		/* explicity window move updating the expected index */
		exp_idx = reorder_data[IFXF_RXREORDER_EXPIDX_OFFSET];

		ifxf_dbg(DATA, "flow-%d (0x%x): change expected: %d -> %d\n",
			  flow_id, flags, rfi->exp_idx, exp_idx);
		if (flags & IFXF_RXREORDER_FLUSH_ALL)
			end_idx =  rfi->exp_idx;
		else
			end_idx =  exp_idx;

		ifxf_rxreorder_get_skb_list(rfi, rfi->exp_idx, end_idx,
					     &reorder_list);
		__skb_queue_tail(&reorder_list, pkt);
		/* set the new expected idx */
		rfi->exp_idx = exp_idx;
	}
netif_rx:
	skb_queue_walk_safe(&reorder_list, pkt, pnext) {
		__skb_unlink(pkt, &reorder_list);
		ifxf_netif_rx(ifp, pkt);
	}
}

void ifxf_fws_hdrpull(struct ifxf_if *ifp, s16 siglen, struct sk_buff *skb)
{
	struct ifxf_skb_reorder_data *rd;
	struct ifxf_fws_info *fws = drvr_to_fws(ifp->drvr);
	u8 *signal_data;
	s16 data_len;
	u8 type;
	s16 len;
	u8 *data;
	s32 status;
	s32 err;

	ifxf_dbg(HDRS, "enter: ifidx %d, skblen %u, sig %d\n",
		  ifp->ifidx, skb->len, siglen);

	WARN_ON(siglen > skb->len);

	if (siglen > skb->len)
		siglen = skb->len;

	if (!siglen)
		return;
	/* if flow control disabled, skip to packet data and leave */
	if ((!fws) || (!fws->fw_signals)) {
		skb_pull(skb, siglen);
		return;
	}

	fws->stats.header_pulls++;
	data_len = siglen;
	signal_data = skb->data;

	status = IFXF_FWS_RET_OK_NOSCHEDULE;
	while (data_len > 0) {
		/* extract tlv info */
		type = signal_data[0];

		/* FILLER type is actually not a TLV, but
		 * a single byte that can be skipped.
		 */
		if (type == IFXF_FWS_TYPE_FILLER) {
			signal_data += 1;
			data_len -= 1;
			continue;
		}
		len = signal_data[1];
		data = signal_data + 2;

		ifxf_dbg(HDRS, "tlv type=%s (%d), len=%d (%d)\n",
			  ifxf_fws_get_tlv_name(type), type, len,
			  ifxf_fws_get_tlv_len(fws, type));

		/* abort parsing when length invalid */
		if (data_len < len + 2)
			break;

		if (len < ifxf_fws_get_tlv_len(fws, type))
			break;

		err = IFXF_FWS_RET_OK_NOSCHEDULE;
		switch (type) {
		case IFXF_FWS_TYPE_HOST_REORDER_RXPKTS:
			rd = (struct ifxf_skb_reorder_data *)skb->cb;
			rd->reorder = data;
			break;
		case IFXF_FWS_TYPE_MACDESC_ADD:
		case IFXF_FWS_TYPE_MACDESC_DEL:
			ifxf_fws_macdesc_indicate(fws, type, data);
			break;
		case IFXF_FWS_TYPE_MAC_OPEN:
		case IFXF_FWS_TYPE_MAC_CLOSE:
			err = ifxf_fws_macdesc_state_indicate(fws, type, data);
			break;
		case IFXF_FWS_TYPE_INTERFACE_OPEN:
		case IFXF_FWS_TYPE_INTERFACE_CLOSE:
			err = ifxf_fws_interface_state_indicate(fws, type,
								 data);
			break;
		case IFXF_FWS_TYPE_MAC_REQUEST_CREDIT:
		case IFXF_FWS_TYPE_MAC_REQUEST_PACKET:
			err = ifxf_fws_request_indicate(fws, type, data);
			break;
		case IFXF_FWS_TYPE_TXSTATUS:
		case IFXF_FWS_TYPE_COMP_TXSTATUS:
			ifxf_fws_txstatus_indicate(fws, type, data);
			break;
		case IFXF_FWS_TYPE_FIFO_CREDITBACK:
			err = ifxf_fws_fifocreditback_indicate(fws, data);
			break;
		case IFXF_FWS_TYPE_RSSI:
			ifxf_fws_rssi_indicate(fws, *data);
			break;
		case IFXF_FWS_TYPE_TRANS_ID:
			ifxf_fws_dbg_seqnum_check(fws, data);
			break;
		case IFXF_FWS_TYPE_PKTTAG:
		case IFXF_FWS_TYPE_PENDING_TRAFFIC_BMP:
		default:
			fws->stats.tlv_invalid_type++;
			break;
		}
		if (err == IFXF_FWS_RET_OK_SCHEDULE)
			status = IFXF_FWS_RET_OK_SCHEDULE;
		signal_data += len + 2;
		data_len -= len + 2;
	}

	if (data_len != 0)
		fws->stats.tlv_parse_failed++;

	if (status == IFXF_FWS_RET_OK_SCHEDULE)
		ifxf_fws_schedule_deq(fws);

	/* signalling processing result does
	 * not affect the actual ethernet packet.
	 */
	skb_pull(skb, siglen);

	/* this may be a signal-only packet
	 */
	if (skb->len == 0)
		fws->stats.header_only_pkt++;
}

static u8 ifxf_fws_precommit_skb(struct ifxf_fws_info *fws, int fifo,
				   struct sk_buff *p)
{
	struct ifxf_skbuff_cb *skcb = ifxf_skbcb(p);
	struct ifxf_fws_mac_descriptor *entry = skcb->mac;
	u8 flags;

	if (skcb->state != IFXF_FWS_SKBSTATE_SUPPRESSED)
		ifxf_skb_htod_tag_set_field(p, GENERATION, entry->generation);
	flags = IFXF_FWS_HTOD_FLAG_PKTFROMHOST;
	if (ifxf_skb_if_flags_get_field(p, REQUESTED)) {
		/*
		 * Indicate that this packet is being sent in response to an
		 * explicit request from the firmware side.
		 */
		flags |= IFXF_FWS_HTOD_FLAG_PKT_REQUESTED;
	}
	ifxf_skb_htod_tag_set_field(p, FLAGS, flags);
	return ifxf_fws_hdrpush(fws, p);
}

static void ifxf_fws_rollback_toq(struct ifxf_fws_info *fws,
				   struct sk_buff *skb, int fifo)
{
	struct ifxf_pub *drvr = fws->drvr;
	struct ifxf_fws_mac_descriptor *entry;
	struct sk_buff *pktout;
	int qidx, hslot;
	int rc = 0;

	entry = ifxf_skbcb(skb)->mac;
	if (entry->occupied) {
		qidx = 2 * fifo;
		if (ifxf_skbcb(skb)->state == IFXF_FWS_SKBSTATE_SUPPRESSED)
			qidx++;

		pktout = ifxu_pktq_penq_head(&entry->psq, qidx, skb);
		if (pktout == NULL) {
			bphy_err(drvr, "%s queue %d full\n", entry->name, qidx);
			rc = -ENOSPC;
		}
	} else {
		bphy_err(drvr, "%s entry removed\n", entry->name);
		rc = -ENOENT;
	}

	if (rc) {
		fws->stats.rollback_failed++;
		hslot = ifxf_skb_htod_tag_get_field(skb, HSLOT);
		ifxf_fws_txs_process(fws, IFXF_FWS_TXSTATUS_HOST_TOSSED,
				      hslot, 0, 0, 1);
	} else {
		fws->stats.rollback_success++;
		ifxf_fws_return_credits(fws, fifo, 1);
		ifxf_fws_macdesc_return_req_credit(skb);
	}
}

static int ifxf_fws_borrow_credit(struct ifxf_fws_info *fws,
				   int highest_lender_ac, int borrower_ac,
				   bool borrow_all)
{
	int lender_ac, borrow_limit = 0;

	for (lender_ac = 0; lender_ac <= highest_lender_ac; lender_ac++) {

		if (!borrow_all)
			borrow_limit =
			  fws->init_fifo_credit[lender_ac] / IFXF_BORROW_RATIO;
		else
			borrow_limit = 0;

		if (fws->fifo_credit[lender_ac] > borrow_limit) {
			fws->credits_borrowed[borrower_ac][lender_ac]++;
			fws->fifo_credit[lender_ac]--;
			if (fws->fifo_credit[lender_ac] == 0)
				fws->fifo_credit_map &= ~(1 << lender_ac);
			fws->fifo_credit_map |= (1 << borrower_ac);
			ifxf_dbg(DATA, "borrow credit from: %d\n", lender_ac);
			return 0;
		}
	}
	fws->fifo_credit_map &= ~(1 << borrower_ac);
	return -ENAVAIL;
}

static int ifxf_fws_commit_skb(struct ifxf_fws_info *fws, int fifo,
				struct sk_buff *skb)
{
	struct ifxf_skbuff_cb *skcb = ifxf_skbcb(skb);
	struct ifxf_fws_mac_descriptor *entry;
	int rc;
	u8 ifidx;
	u8 data_offset;

	entry = skcb->mac;
	if (IS_ERR(entry))
		return PTR_ERR(entry);

	data_offset = ifxf_fws_precommit_skb(fws, fifo, skb);
	entry->transit_count++;
	if (entry->suppressed)
		entry->suppr_transit_count++;
	ifidx = ifxf_skb_if_flags_get_field(skb, INDEX);
	ifxf_fws_unlock(fws);
	rc = ifxf_proto_txdata(fws->drvr, ifidx, data_offset, skb);
	ifxf_fws_lock(fws);
	ifxf_dbg(DATA, "%s flags %X htod %X bus_tx %d\n", entry->name,
		  skcb->if_flags, skcb->htod, rc);
	if (rc < 0) {
		entry->transit_count--;
		if (entry->suppressed)
			entry->suppr_transit_count--;
		(void)ifxf_proto_hdrpull(fws->drvr, false, skb, NULL);
		goto rollback;
	}

	fws->stats.pkt2bus++;
	fws->stats.send_pkts[fifo]++;
	if (ifxf_skb_if_flags_get_field(skb, REQUESTED))
		fws->stats.requested_sent[fifo]++;

	return rc;

rollback:
	ifxf_fws_rollback_toq(fws, skb, fifo);
	return rc;
}

static int ifxf_fws_assign_htod(struct ifxf_fws_info *fws, struct sk_buff *p,
				  int fifo)
{
	struct ifxf_skbuff_cb *skcb = ifxf_skbcb(p);
	int rc, hslot;

	skcb->htod = 0;
	skcb->htod_seq = 0;
	hslot = ifxf_fws_hanger_get_free_slot(&fws->hanger);
	ifxf_skb_htod_tag_set_field(p, HSLOT, hslot);
	ifxf_skb_htod_tag_set_field(p, FREERUN, skcb->mac->seq[fifo]);
	ifxf_skb_htod_tag_set_field(p, FIFO, fifo);
	rc = ifxf_fws_hanger_pushpkt(&fws->hanger, p, hslot);
	if (!rc)
		skcb->mac->seq[fifo]++;
	else
		fws->stats.generic_error++;
	return rc;
}

int ifxf_fws_process_skb(struct ifxf_if *ifp, struct sk_buff *skb)
{
	struct ifxf_pub *drvr = ifp->drvr;
	struct ifxf_fws_info *fws = drvr_to_fws(drvr);
	struct ifxf_skbuff_cb *skcb = ifxf_skbcb(skb);
	struct ethhdr *eh = (struct ethhdr *)(skb->data);
	int fifo = IFXF_FWS_FIFO_BCMC;
	bool multicast = is_multicast_ether_addr(eh->h_dest);
	int rc = 0;

	ifxf_dbg(DATA, "tx proto=0x%X\n", ntohs(eh->h_proto));

	/* set control buffer information */
	skcb->if_flags = 0;
	skcb->state = IFXF_FWS_SKBSTATE_NEW;
	ifxf_skb_if_flags_set_field(skb, INDEX, ifp->ifidx);

	/* mapping from 802.1d priority to firmware fifo index */
	if (!multicast)
		fifo = ifxf_map_prio_to_aci(drvr->config, skb->priority);

	ifxf_fws_lock(fws);
	if (fifo != IFXF_FWS_FIFO_AC_BE && fifo < IFXF_FWS_FIFO_BCMC)
		fws->borrow_defer_timestamp = jiffies +
					      IFXF_FWS_BORROW_DEFER_PERIOD;

	skcb->mac = ifxf_fws_macdesc_find(fws, ifp, eh->h_dest);
	ifxf_dbg(DATA, "%s mac %pM multi %d fifo %d\n", skcb->mac->name,
		  eh->h_dest, multicast, fifo);
	if (!ifxf_fws_assign_htod(fws, skb, fifo)) {
		ifxf_fws_enq(fws, IFXF_FWS_SKBSTATE_DELAYED, fifo, skb);
		ifxf_fws_schedule_deq(fws);
	} else {
		bphy_err(drvr, "no hanger slot available\n");
		rc = -ENOMEM;
	}
	ifxf_fws_unlock(fws);

	return rc;
}

void ifxf_fws_reset_interface(struct ifxf_if *ifp)
{
	struct ifxf_fws_mac_descriptor *entry = ifp->fws_desc;

	ifxf_dbg(TRACE, "enter: bsscfgidx=%d\n", ifp->bsscfgidx);
	if (!entry)
		return;

	ifxf_fws_macdesc_init(entry, ifp->mac_addr, ifp->ifidx);
}

void ifxf_fws_add_interface(struct ifxf_if *ifp)
{
	struct ifxf_fws_info *fws = drvr_to_fws(ifp->drvr);
	struct ifxf_fws_mac_descriptor *entry;

	if (!ifp->ndev || !ifxf_fws_queue_skbs(fws))
		return;

	entry = &fws->desc.iface[ifp->ifidx];
	ifp->fws_desc = entry;
	ifxf_fws_macdesc_init(entry, ifp->mac_addr, ifp->ifidx);
	ifxf_fws_macdesc_set_name(fws, entry);
	ifxu_pktq_init(&entry->psq, IFXF_FWS_PSQ_PREC_COUNT,
			IFXF_FWS_PSQ_LEN);
	ifxf_dbg(TRACE, "added %s\n", entry->name);
}

void ifxf_fws_del_interface(struct ifxf_if *ifp)
{
	struct ifxf_fws_mac_descriptor *entry = ifp->fws_desc;
	struct ifxf_fws_info *fws = drvr_to_fws(ifp->drvr);

	if (!entry)
		return;

	ifxf_fws_lock(fws);
	ifp->fws_desc = NULL;
	ifxf_dbg(TRACE, "deleting %s\n", entry->name);
	ifxf_fws_macdesc_cleanup(fws, &fws->desc.iface[ifp->ifidx],
				  ifp->ifidx);
	ifxf_fws_macdesc_deinit(entry);
	ifxf_fws_cleanup(fws, ifp->ifidx);
	ifxf_fws_unlock(fws);
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0))
static bool ifxf_fws_ismultistream(struct ifxf_fws_info *fws)
{
	bool ret = false;
	u8 credit_usage = 0;

	/* Check only for BE, VI and VO traffic */
	u32 delay_map = fws->fifo_delay_map &
		((1 << IFXF_FWS_FIFO_AC_BE) |
		 (1 << IFXF_FWS_FIFO_AC_VI) |
		 (1 << IFXF_FWS_FIFO_AC_VO));

	if (hweight_long(delay_map) > 1) {
		ret = true;
	} else {
		if (fws->fifo_credit[IFXF_FWS_FIFO_AC_BE] <
			fws->fifo_init_credit[IFXF_FWS_FIFO_AC_BE])
			credit_usage++;
		if (fws->fifo_credit[IFXF_FWS_FIFO_AC_VI] <
			fws->fifo_init_credit[IFXF_FWS_FIFO_AC_VI])
			credit_usage++;
		if (fws->fifo_credit[IFXF_FWS_FIFO_AC_VO] <
			fws->fifo_init_credit[IFXF_FWS_FIFO_AC_VO])
			credit_usage++;

		if (credit_usage > 1)
			ret = true;
	}
	return ret;
}
#endif

static void ifxf_fws_dequeue_worker(struct work_struct *worker)
{
	struct ifxf_fws_info *fws;
	struct ifxf_pub *drvr;
	struct sk_buff *skb;
	int fifo;
	u32 hslot;
	u32 ifidx;
	int ret;

	fws = container_of(worker, struct ifxf_fws_info, fws_dequeue_work);
	drvr = fws->drvr;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0))
	if (ifxf_fws_ismultistream(fws))
		drvr->bus_if->allow_skborphan = false;
	else
		drvr->bus_if->allow_skborphan = true;
#endif

	ifxf_fws_lock(fws);
	for (fifo = IFXF_FWS_FIFO_BCMC; fifo >= 0 && !fws->bus_flow_blocked;
	     fifo--) {
		if (!ifxf_fws_fc_active(fws)) {
			while ((skb = ifxf_fws_deq(fws, fifo)) != NULL) {
				hslot = ifxf_skb_htod_tag_get_field(skb,
								     HSLOT);
				ifxf_fws_hanger_poppkt(&fws->hanger, hslot,
							&skb, true);
				ifidx = ifxf_skb_if_flags_get_field(skb,
								     INDEX);
				/* Use proto layer to send data frame */
				ifxf_fws_unlock(fws);
				ret = ifxf_proto_txdata(drvr, ifidx, 0, skb);
				ifxf_fws_lock(fws);
				if (ret < 0)
					ifxf_txfinalize(ifxf_get_ifp(drvr,
								       ifidx),
							 skb, false);
				if (fws->bus_flow_blocked)
					break;
			}
			continue;
		}

		while ((fws->fifo_credit[fifo]) ||
		       ((!fws->bcmc_credit_check) &&
				(fifo == IFXF_FWS_FIFO_BCMC))) {
			skb = ifxf_fws_deq(fws, fifo);
			if (!skb)
				break;
			fws->fifo_credit[fifo]--;
			if (ifxf_fws_commit_skb(fws, fifo, skb))
				break;
			if (fws->bus_flow_blocked)
				break;
		}

		if (fifo >= IFXF_FWS_FIFO_AC_BE &&
		    fifo <= IFXF_FWS_FIFO_AC_VO &&
		    fws->fifo_credit[fifo] == 0 &&
		    !fws->bus_flow_blocked) {
			while (ifxf_fws_borrow_credit(fws,
						       fifo - 1, fifo,
						       true) == 0) {
				skb = ifxf_fws_deq(fws, fifo);
				if (!skb) {
					ifxf_fws_return_credits(fws, fifo, 1);
					break;
				}
				if (ifxf_fws_commit_skb(fws, fifo, skb))
					break;
				if (fws->bus_flow_blocked)
					break;
			}
		}
	}
	ifxf_fws_unlock(fws);
}

#ifdef DEBUG
static int ifxf_debugfs_fws_stats_read(struct seq_file *seq, void *data)
{
	struct ifxf_bus *bus_if = dev_get_drvdata(seq->private);
	struct ifxf_fws_stats *fwstats = &(drvr_to_fws(bus_if->drvr)->stats);

	seq_printf(seq,
		   "header_pulls:      %u\n"
		   "header_only_pkt:   %u\n"
		   "tlv_parse_failed:  %u\n"
		   "tlv_invalid_type:  %u\n"
		   "mac_update_fails:  %u\n"
		   "ps_update_fails:   %u\n"
		   "if_update_fails:   %u\n"
		   "pkt2bus:           %u\n"
		   "generic_error:     %u\n"
		   "rollback_success:  %u\n"
		   "rollback_failed:   %u\n"
		   "delayq_full:       %u\n"
		   "supprq_full:       %u\n"
		   "txs_indicate:      %u\n"
		   "txs_discard:       %u\n"
		   "txs_suppr_core:    %u\n"
		   "txs_suppr_ps:      %u\n"
		   "txs_tossed:        %u\n"
		   "txs_host_tossed:   %u\n"
		   "bus_flow_block:    %u\n"
		   "fws_flow_block:    %u\n"
		   "send_pkts:         BK:%u BE:%u VO:%u VI:%u BCMC:%u\n"
		   "requested_sent:    BK:%u BE:%u VO:%u VI:%u BCMC:%u\n",
		   fwstats->header_pulls,
		   fwstats->header_only_pkt,
		   fwstats->tlv_parse_failed,
		   fwstats->tlv_invalid_type,
		   fwstats->mac_update_failed,
		   fwstats->mac_ps_update_failed,
		   fwstats->if_update_failed,
		   fwstats->pkt2bus,
		   fwstats->generic_error,
		   fwstats->rollback_success,
		   fwstats->rollback_failed,
		   fwstats->delayq_full_error,
		   fwstats->supprq_full_error,
		   fwstats->txs_indicate,
		   fwstats->txs_discard,
		   fwstats->txs_supp_core,
		   fwstats->txs_supp_ps,
		   fwstats->txs_tossed,
		   fwstats->txs_host_tossed,
		   fwstats->bus_flow_block,
		   fwstats->fws_flow_block,
		   fwstats->send_pkts[0], fwstats->send_pkts[1],
		   fwstats->send_pkts[2], fwstats->send_pkts[3],
		   fwstats->send_pkts[4],
		   fwstats->requested_sent[0],
		   fwstats->requested_sent[1],
		   fwstats->requested_sent[2],
		   fwstats->requested_sent[3],
		   fwstats->requested_sent[4]);

	return 0;
}
#else
static int ifxf_debugfs_fws_stats_read(struct seq_file *seq, void *data)
{
	return 0;
}
#endif

struct ifxf_fws_info *ifxf_fws_attach(struct ifxf_pub *drvr)
{
	struct ifxf_fws_info *fws;
	struct ifxf_if *ifp;
	u32 tlv = IFXF_FWS_FLAGS_RSSI_SIGNALS;
	int rc;
	u32 mode;

	fws = kzalloc(sizeof(*fws), GFP_KERNEL);
	if (!fws) {
		rc = -ENOMEM;
		goto fail;
	}

	spin_lock_init(&fws->spinlock);

	/* store drvr reference */
	fws->drvr = drvr;
	fws->fcmode = drvr->settings->fcmode;

	if (!drvr->bus_if->always_use_fws_queue &&
	    (fws->fcmode == IFXF_FWS_FCMODE_NONE)) {
		fws->avoid_queueing = true;
		ifxf_dbg(INFO, "FWS queueing will be avoided\n");
		return fws;
	}

	fws->fws_wq = create_singlethread_workqueue("ifxf_fws_wq");
	if (fws->fws_wq == NULL) {
		bphy_err(drvr, "workqueue creation failed\n");
		rc = -EBADF;
		goto fail;
	}
	INIT_WORK(&fws->fws_dequeue_work, ifxf_fws_dequeue_worker);

	/* enable firmware signalling if fcmode active */
	if (fws->fcmode != IFXF_FWS_FCMODE_NONE)
		tlv |= IFXF_FWS_FLAGS_XONXOFF_SIGNALS |
		       IFXF_FWS_FLAGS_CREDIT_STATUS_SIGNALS |
		       IFXF_FWS_FLAGS_HOST_PROPTXSTATUS_ACTIVE |
		       IFXF_FWS_FLAGS_HOST_RXREORDER_ACTIVE;

	rc = ifxf_fweh_register(drvr, IFXF_E_FIFO_CREDIT_MAP,
				 ifxf_fws_notify_credit_map);
	if (rc < 0) {
		bphy_err(drvr, "register credit map handler failed\n");
		goto fail;
	}
	rc = ifxf_fweh_register(drvr, IFXF_E_BCMC_CREDIT_SUPPORT,
				 ifxf_fws_notify_bcmc_credit_support);
	if (rc < 0) {
		bphy_err(drvr, "register bcmc credit handler failed\n");
		ifxf_fweh_unregister(drvr, IFXF_E_FIFO_CREDIT_MAP);
		goto fail;
	}

	/* Setting the iovar may fail if feature is unsupported
	 * so leave the rc as is so driver initialization can
	 * continue. Set mode back to none indicating not enabled.
	 */
	fws->fw_signals = true;
	ifp = ifxf_get_ifp(drvr, 0);
	if (ifxf_fil_iovar_int_set(ifp, "tlv", tlv)) {
		bphy_err(drvr, "failed to set bdcv2 tlv signaling\n");
		fws->fcmode = IFXF_FWS_FCMODE_NONE;
		fws->fw_signals = false;
	}

	if (ifxf_fil_iovar_int_set(ifp, "ampdu_hostreorder", 1))
		ifxf_dbg(INFO, "enabling AMPDU host-reorder failed\n");

	/* Enable seq number reuse, if supported */
	if (ifxf_fil_iovar_int_get(ifp, "wlfc_mode", &mode) == 0) {
		if (IFXF_FWS_MODE_GET_REUSESEQ(mode)) {
			mode = 0;
			IFXF_FWS_MODE_SET_REUSESEQ(mode, 1);
			if (ifxf_fil_iovar_int_set(ifp,
						    "wlfc_mode", mode) == 0) {
				IFXF_FWS_MODE_SET_REUSESEQ(fws->mode, 1);
			}
		}
	}

	ifxf_fws_hanger_init(&fws->hanger);
	ifxf_fws_macdesc_init(&fws->desc.other, NULL, 0);
	ifxf_fws_macdesc_set_name(fws, &fws->desc.other);
	ifxf_dbg(INFO, "added %s\n", fws->desc.other.name);
	ifxu_pktq_init(&fws->desc.other.psq, IFXF_FWS_PSQ_PREC_COUNT,
			IFXF_FWS_PSQ_LEN);

	ifxf_dbg(INFO, "%s bdcv2 tlv signaling [%x]\n",
		  fws->fw_signals ? "enabled" : "disabled", tlv);
	return fws;

fail:
	ifxf_fws_detach(fws);
	return ERR_PTR(rc);
}

void ifxf_fws_detach(struct ifxf_fws_info *fws)
{
	if (!fws)
		return;

	if (fws->fws_wq)
		destroy_workqueue(fws->fws_wq);

	/* cleanup */
	ifxf_fws_lock(fws);
	ifxf_fws_cleanup(fws, -1);
	ifxf_fws_unlock(fws);

	/* free top structure */
	kfree(fws);
}

void ifxf_fws_debugfs_create(struct ifxf_pub *drvr)
{
	/* create debugfs file for statistics */
	ifxf_debugfs_add_entry(drvr, "fws_stats",
				ifxf_debugfs_fws_stats_read);
}

bool ifxf_fws_queue_skbs(struct ifxf_fws_info *fws)
{
	return !fws->avoid_queueing;
}

bool ifxf_fws_fc_active(struct ifxf_fws_info *fws)
{
	if (!fws->creditmap_received)
		return false;

	return fws->fcmode != IFXF_FWS_FCMODE_NONE;
}

void ifxf_fws_bustxcomplete(struct ifxf_fws_info *fws, struct sk_buff *skb,
			     bool success)
{
	u32 hslot;

	if (ifxf_skbcb(skb)->state == IFXF_FWS_SKBSTATE_TIM) {
		ifxu_pkt_buf_free_skb(skb);
		return;
	}

	if (!success) {
		ifxf_fws_lock(fws);
		hslot = ifxf_skb_htod_tag_get_field(skb, HSLOT);
		ifxf_fws_txs_process(fws, IFXF_FWS_TXSTATUS_HOST_TOSSED, hslot,
				      0, 0, 1);
		ifxf_fws_unlock(fws);
	}
}

void ifxf_fws_bus_blocked(struct ifxf_pub *drvr, bool flow_blocked)
{
	struct ifxf_fws_info *fws = drvr_to_fws(drvr);
	struct ifxf_if *ifp;
	int i;

	if (fws->avoid_queueing) {
		for (i = 0; i < IFXF_MAX_IFS; i++) {
			ifp = drvr->iflist[i];
			if (!ifp || !ifp->ndev)
				continue;
			ifxf_txflowblock_if(ifp, IFXF_NETIF_STOP_REASON_FLOW,
					     flow_blocked);
		}
	} else {
		fws->bus_flow_blocked = flow_blocked;
		if (!flow_blocked)
			ifxf_fws_schedule_deq(fws);
		else
			fws->stats.bus_flow_block++;
	}
}
