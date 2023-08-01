// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2012 Broadcom Corporation
 */
#include <linux/netdevice.h>

#include "ifxu_wifi.h"
#include "ifxu_utils.h"

#include "cfg80211.h"
#include "core.h"
#include "debug.h"
#include "tracepoint.h"
#include "fweh.h"
#include "fwil.h"
#include "proto.h"

/**
 * struct ifxf_fweh_queue_item - event item on event queue.
 *
 * @q: list element for queuing.
 * @code: event code.
 * @ifidx: interface index related to this event.
 * @ifaddr: ethernet address for interface.
 * @emsg: common parameters of the firmware event message.
 * @datalen: length of the data array
 * @data: event specific data part of the firmware event.
 */
struct ifxf_fweh_queue_item {
	struct list_head q;
	enum ifxf_fweh_event_code code;
	u8 ifidx;
	u8 ifaddr[ETH_ALEN];
	struct ifxf_event_msg_be emsg;
	u32 datalen;
	u8 data[];
};

/*
 * struct ifxf_fweh_event_name - code, name mapping entry.
 */
struct ifxf_fweh_event_name {
	enum ifxf_fweh_event_code code;
	const char *name;
};

#ifdef DEBUG
#define IFXF_ENUM_DEF(id, val) \
	{ val, #id },

/* array for mapping code to event name */
static struct ifxf_fweh_event_name fweh_event_names[] = {
	IFXF_FWEH_EVENT_ENUM_DEFLIST
};
#undef IFXF_ENUM_DEF

/**
 * ifxf_fweh_event_name() - returns name for given event code.
 *
 * @code: code to lookup.
 */
const char *ifxf_fweh_event_name(enum ifxf_fweh_event_code code)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(fweh_event_names); i++) {
		if (fweh_event_names[i].code == code)
			return fweh_event_names[i].name;
	}
	return "unknown";
}
#else
const char *ifxf_fweh_event_name(enum ifxf_fweh_event_code code)
{
	return "nodebug";
}
#endif

/**
 * ifxf_fweh_queue_event() - create and queue event.
 *
 * @fweh: firmware event handling info.
 * @event: event queue entry.
 */
static void ifxf_fweh_queue_event(struct ifxf_fweh_info *fweh,
				   struct ifxf_fweh_queue_item *event)
{
	ulong flags;

	spin_lock_irqsave(&fweh->evt_q_lock, flags);
	list_add_tail(&event->q, &fweh->event_q);
	spin_unlock_irqrestore(&fweh->evt_q_lock, flags);
	schedule_work(&fweh->event_work);
}

static int ifxf_fweh_call_event_handler(struct ifxf_pub *drvr,
					 struct ifxf_if *ifp,
					 enum ifxf_fweh_event_code code,
					 struct ifxf_event_msg *emsg,
					 void *data)
{
	struct ifxf_fweh_info *fweh;
	int err = -EINVAL;

	if (ifp) {
		fweh = &ifp->drvr->fweh;

		/* handle the event if valid interface and handler */
		if (fweh->evt_handler[code])
			err = fweh->evt_handler[code](ifp, emsg, data);
		else
			bphy_err(drvr, "unhandled event %d ignored\n", code);
	} else {
		bphy_err(drvr, "no interface object\n");
	}
	return err;
}

/**
 * ifxf_fweh_handle_if_event() - handle IF event.
 *
 * @drvr: driver information object.
 * @emsg: event message object.
 * @data: event object.
 */
static void ifxf_fweh_handle_if_event(struct ifxf_pub *drvr,
				       struct ifxf_event_msg *emsg,
				       void *data)
{
	struct ifxf_if_event *ifevent = data;
	struct ifxf_if *ifp;
	bool is_p2pdev;

	ifxf_dbg(EVENT, "action: %u ifidx: %u bsscfgidx: %u flags: %u role: %u\n",
		  ifevent->action, ifevent->ifidx, ifevent->bsscfgidx,
		  ifevent->flags, ifevent->role);

	/* The P2P Device interface event must not be ignored contrary to what
	 * firmware tells us. Older firmware uses p2p noif, with sta role.
	 * This should be accepted when p2pdev_setup is ongoing. TDLS setup will
	 * use the same ifevent and should be ignored.
	 */
	is_p2pdev = ((ifevent->flags & IFXF_E_IF_FLAG_NOIF) &&
		     (ifevent->role == IFXF_E_IF_ROLE_P2P_CLIENT ||
		      ((ifevent->role == IFXF_E_IF_ROLE_STA) &&
		       (drvr->fweh.p2pdev_setup_ongoing))));
	if (!is_p2pdev && (ifevent->flags & IFXF_E_IF_FLAG_NOIF)) {
		ifxf_dbg(EVENT, "event can be ignored\n");
		return;
	}
	if (ifevent->ifidx >= IFXF_MAX_IFS) {
		bphy_err(drvr, "invalid interface index: %u\n", ifevent->ifidx);
		return;
	}

	ifp = drvr->iflist[ifevent->bsscfgidx];

	if (ifevent->action == IFXF_E_IF_ADD) {
		ifxf_dbg(EVENT, "adding %s (%pM)\n", emsg->ifname,
			  emsg->addr);
		ifp = ifxf_add_if(drvr, ifevent->bsscfgidx, ifevent->ifidx,
				   is_p2pdev, emsg->ifname, emsg->addr);
		if (IS_ERR(ifp))
			return;
		if (!is_p2pdev)
			ifxf_proto_add_if(drvr, ifp);
		if (!drvr->fweh.evt_handler[IFXF_E_IF])
			if (ifxf_net_attach(ifp, false) < 0)
				return;
	}

	if (ifp && ifevent->action == IFXF_E_IF_CHANGE)
		ifxf_proto_reset_if(drvr, ifp);

	ifxf_fweh_call_event_handler(drvr, ifp, emsg->event_code, emsg,
				      data);

	if (ifp && ifevent->action == IFXF_E_IF_DEL) {
		bool armed = ifxf_cfg80211_vif_event_armed(drvr->config);

		/* Default handling in case no-one waits for this event */
		if (!armed)
			ifxf_remove_interface(ifp, false);
	}
}

/**
 * ifxf_fweh_dequeue_event() - get event from the queue.
 *
 * @fweh: firmware event handling info.
 */
static struct ifxf_fweh_queue_item *
ifxf_fweh_dequeue_event(struct ifxf_fweh_info *fweh)
{
	struct ifxf_fweh_queue_item *event = NULL;
	ulong flags;

	spin_lock_irqsave(&fweh->evt_q_lock, flags);
	if (!list_empty(&fweh->event_q)) {
		event = list_first_entry(&fweh->event_q,
					 struct ifxf_fweh_queue_item, q);
		list_del(&event->q);
	}
	spin_unlock_irqrestore(&fweh->evt_q_lock, flags);

	return event;
}

/**
 * ifxf_fweh_event_worker() - firmware event worker.
 *
 * @work: worker object.
 */
static void ifxf_fweh_event_worker(struct work_struct *work)
{
	struct ifxf_pub *drvr;
	struct ifxf_if *ifp;
	struct ifxf_fweh_info *fweh;
	struct ifxf_fweh_queue_item *event;
	int err = 0;
	struct ifxf_event_msg_be *emsg_be;
	struct ifxf_event_msg emsg;

	fweh = container_of(work, struct ifxf_fweh_info, event_work);
	drvr = container_of(fweh, struct ifxf_pub, fweh);

	while ((event = ifxf_fweh_dequeue_event(fweh))) {
		ifxf_dbg(EVENT, "event %s (%u) ifidx %u bsscfg %u addr %pM\n",
			  ifxf_fweh_event_name(event->code), event->code,
			  event->emsg.ifidx, event->emsg.bsscfgidx,
			  event->emsg.addr);
		if (event->emsg.bsscfgidx >= IFXF_MAX_IFS) {
			bphy_err(drvr, "invalid bsscfg index: %u\n", event->emsg.bsscfgidx);
			goto event_free;
		}

		/* convert event message */
		emsg_be = &event->emsg;
		emsg.version = be16_to_cpu(emsg_be->version);
		emsg.flags = be16_to_cpu(emsg_be->flags);
		emsg.event_code = event->code;
		emsg.status = be32_to_cpu(emsg_be->status);
		emsg.reason = be32_to_cpu(emsg_be->reason);
		emsg.auth_type = be32_to_cpu(emsg_be->auth_type);
		emsg.datalen = be32_to_cpu(emsg_be->datalen);
		memcpy(emsg.addr, emsg_be->addr, ETH_ALEN);
		memcpy(emsg.ifname, emsg_be->ifname, sizeof(emsg.ifname));
		emsg.ifidx = emsg_be->ifidx;
		emsg.bsscfgidx = emsg_be->bsscfgidx;

		ifxf_dbg(EVENT, "  version %u flags %u status %u reason %u\n",
			  emsg.version, emsg.flags, emsg.status, emsg.reason);
		ifxf_dbg_hex_dump(IFXF_EVENT_ON(), event->data,
				   min_t(u32, emsg.datalen, 64),
				   "event payload, len=%d\n", emsg.datalen);

		/* special handling of interface event */
		if (event->code == IFXF_E_IF) {
			ifxf_fweh_handle_if_event(drvr, &emsg, event->data);
			goto event_free;
		}

		if (event->code == IFXF_E_TDLS_PEER_EVENT)
			ifp = drvr->iflist[0];
		else
			ifp = drvr->iflist[emsg.bsscfgidx];
		err = ifxf_fweh_call_event_handler(drvr, ifp, event->code,
						    &emsg, event->data);
		if (err) {
			bphy_err(drvr, "event handler failed (%d)\n",
				 event->code);
			err = 0;
		}
event_free:
		kfree(event);
	}
}

/**
 * ifxf_fweh_p2pdev_setup() - P2P device setup ongoing (or not).
 *
 * @ifp: ifp on which setup is taking place or finished.
 * @ongoing: p2p device setup in progress (or not).
 */
void ifxf_fweh_p2pdev_setup(struct ifxf_if *ifp, bool ongoing)
{
	ifp->drvr->fweh.p2pdev_setup_ongoing = ongoing;
}

/**
 * ifxf_fweh_attach() - initialize firmware event handling.
 *
 * @drvr: driver information object.
 */
void ifxf_fweh_attach(struct ifxf_pub *drvr)
{
	struct ifxf_fweh_info *fweh = &drvr->fweh;
	INIT_WORK(&fweh->event_work, ifxf_fweh_event_worker);
	spin_lock_init(&fweh->evt_q_lock);
	INIT_LIST_HEAD(&fweh->event_q);
}

/**
 * ifxf_fweh_detach() - cleanup firmware event handling.
 *
 * @drvr: driver information object.
 */
void ifxf_fweh_detach(struct ifxf_pub *drvr)
{
	struct ifxf_fweh_info *fweh = &drvr->fweh;

	/* cancel the worker if initialized */
	if (fweh->event_work.func) {
		cancel_work_sync(&fweh->event_work);
		WARN_ON(!list_empty(&fweh->event_q));
		memset(fweh->evt_handler, 0, sizeof(fweh->evt_handler));
	}
}

/**
 * ifxf_fweh_register() - register handler for given event code.
 *
 * @drvr: driver information object.
 * @code: event code.
 * @handler: handler for the given event code.
 */
int ifxf_fweh_register(struct ifxf_pub *drvr, enum ifxf_fweh_event_code code,
			ifxf_fweh_handler_t handler)
{
	if (drvr->fweh.evt_handler[code]) {
		bphy_err(drvr, "event code %d already registered\n", code);
		return -ENOSPC;
	}
	drvr->fweh.evt_handler[code] = handler;
	ifxf_dbg(TRACE, "event handler registered for %s\n",
		  ifxf_fweh_event_name(code));
	return 0;
}

/**
 * ifxf_fweh_unregister() - remove handler for given code.
 *
 * @drvr: driver information object.
 * @code: event code.
 */
void ifxf_fweh_unregister(struct ifxf_pub *drvr,
			   enum ifxf_fweh_event_code code)
{
	ifxf_dbg(TRACE, "event handler cleared for %s\n",
		  ifxf_fweh_event_name(code));
	drvr->fweh.evt_handler[code] = NULL;
}

/**
 * ifxf_fweh_activate_events() - enables firmware events registered.
 *
 * @ifp: primary interface object.
 */
int ifxf_fweh_activate_events(struct ifxf_if *ifp)
{
	struct ifxf_pub *drvr = ifp->drvr;
	int i, err;
	struct eventmsgs_ext *eventmask_msg;
	u32 msglen;

	msglen = EVENTMSGS_EXT_STRUCT_SIZE + IFXF_EVENTING_MASK_LEN;
	eventmask_msg = kzalloc(msglen, GFP_KERNEL);
	if (!eventmask_msg)
		return -ENOMEM;

	for (i = 0; i < IFXF_E_LAST; i++) {
		if (ifp->drvr->fweh.evt_handler[i]) {
			ifxf_dbg(EVENT, "enable event %s\n",
				  ifxf_fweh_event_name(i));
			setbit(eventmask_msg->mask, i);
		}
	}

	/* want to handle IF event as well */
	ifxf_dbg(EVENT, "enable event IF\n");
	setbit(eventmask_msg->mask, IFXF_E_IF);

	eventmask_msg->ver = EVENTMSGS_VER;
	eventmask_msg->command = EVENTMSGS_SET_MASK;
	eventmask_msg->len = IFXF_EVENTING_MASK_LEN;

	err = ifxf_fil_iovar_data_set(ifp, "event_msgs_ext", eventmask_msg,
				       msglen);
	if (!err)
		goto end;

	err = ifxf_fil_iovar_data_set(ifp, "event_msgs", eventmask_msg->mask,
				       IFXF_EVENTING_MASK_LEN);
	if (err)
		bphy_err(drvr, "Set event_msgs error (%d)\n", err);

end:
	kfree(eventmask_msg);
	return err;
}

/**
 * ifxf_fweh_process_event() - process skb as firmware event.
 *
 * @drvr: driver information object.
 * @event_packet: event packet to process.
 * @packet_len: length of the packet
 * @gfp: memory allocation flags.
 *
 * If the packet buffer contains a firmware event message it will
 * dispatch the event to a registered handler (using worker).
 */
void ifxf_fweh_process_event(struct ifxf_pub *drvr,
			      struct ifxf_event *event_packet,
			      u32 packet_len, gfp_t gfp)
{
	enum ifxf_fweh_event_code code;
	struct ifxf_fweh_info *fweh = &drvr->fweh;
	struct ifxf_fweh_queue_item *event;
	void *data;
	u32 datalen;

	/* get event info */
	code = get_unaligned_be32(&event_packet->msg.event_type);
	datalen = get_unaligned_be32(&event_packet->msg.datalen);
	data = &event_packet[1];

	if (code >= IFXF_E_LAST)
		return;

	if (code != IFXF_E_IF && !fweh->evt_handler[code])
		return;

	if (datalen > IFXF_DCMD_MAXLEN ||
	    datalen + sizeof(*event_packet) > packet_len)
		return;

	event = kzalloc(sizeof(*event) + datalen, gfp);
	if (!event)
		return;

	event->code = code;
	event->ifidx = event_packet->msg.ifidx;

	/* use memcpy to get aligned event message */
	memcpy(&event->emsg, &event_packet->msg, sizeof(event->emsg));
	memcpy(event->data, data, datalen);
	event->datalen = datalen;
	memcpy(event->ifaddr, event_packet->eth.h_dest, ETH_ALEN);

	ifxf_fweh_queue_event(fweh, event);
}
