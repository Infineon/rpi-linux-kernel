/* Infineon WLAN driver: Target Wake Time (TWT) Header
 *
 * Copyright 2023 Cypress Semiconductor Corporation (an Infineon company)
 * or an affiliate of Cypress Semiconductor Corporation. All rights reserved.
 * This software, including source code, documentation and related materials
 * ("Software") is owned by Cypress Semiconductor Corporation or one of its
 * affiliates ("Cypress") and is protected by and subject to
 * worldwide patent protection (United States and foreign),
 * United States copyright laws and international treaty provisions.
 * Therefore, you may use this Software only as provided in the license agreement
 * accompanying the software package from which you obtained this Software ("EULA").
 * If no EULA applies, Cypress hereby grants you a personal, non-exclusive,
 * non-transferable license to copy, modify, and compile the Software source code
 * solely for use in connection with Cypress's integrated circuit products.
 * Any reproduction, modification, translation, compilation, or representation
 * of this Software except as specified above is prohibited without
 * the expresswritten permission of Cypress.
 * Disclaimer: THIS SOFTWARE IS PROVIDED AS-IS, WITH NO WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, NONINFRINGEMENT,
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 * Cypress reserves the right to make changes to the Software without notice.
 * Cypress does not assume any liability arising out of the application or
 * use of the Software or any product or circuit described in the Software.
 * Cypress does not authorize its products for use in any products where a malfunction
 * or failure of the Cypress product may reasonably be expected to result in
 * significant property damage, injury or death ("High Risk Product").
 * By including Cypress's product in a High Risk Product, the manufacturer
 * of such system or application assumes all risk of such use and in doing so
 * agrees to indemnify Cypress against all liability.
 */

#ifndef IFXF_TWT_H
#define IFXF_TWT_H

#include <linux/sched.h>
#include <linux/jiffies.h>
#include "vendor_ifx.h"
#include "core.h"

/* Min TWT Default Unit */
#define WAKE_DUR_UNIT_DEF 256
/* Min TWT Unit in TUs */
#define WAKE_DUR_UNIT_TU 1024

#define IFXF_TWT_EVENT_TIMEOUT	msecs_to_jiffies(3000)
/**
 * enum ifxf_twt_cmd - TWT iovar subcmds handled by firmware TWT module
 *
 * @IFXF_TWT_CMD_ENAB: Enable the firmware TWT module.
 * @IFXF_TWT_CMD_SETUP: Setup a TWT session with a TWT peer.
 * @IFXF_TWT_CMD_TEARDOWN: Teardown the active TWT session with a TWT peer.
 */
enum ifxf_twt_cmd {
	IFXF_TWT_CMD_ENAB,
	IFXF_TWT_CMD_SETUP,
	IFXF_TWT_CMD_TEARDOWN,
};

/* TWT iovar subcmd version */
#define IFXF_TWT_SETUP_VER	0u
#define IFXF_TWT_TEARDOWN_VER	0u

/**
 * enum ifxf_twt_flow_flag - TWT flow flags to be used in TWT iovar setup subcmd
 *
 * @IFXF_TWT_FLOW_FLAG_BROADCAST: Broadcast TWT Session.
 * @IFXF_TWT_FLOW_FLAG_IMPLICIT: Implcit TWT session type.
 * @IFXF_TWT_FLOW_FLAG_UNANNOUNCED: Unannounced TWT session type.
 * @IFXF_TWT_FLOW_FLAG_TRIGGER: Trigger based TWT Session type.
 * @IFXF_TWT_FLOW_FLAG_WAKE_TBTT_NEGO: Wake TBTT Negotiation type.
 * @IFXF_TWT_FLOW_FLAG_REQUEST: TWT Session setup requestor.
 * @IFXF_TWT_FLOW_FLAG_RESPONDER_PM: Not used.
 * @IFXF_TWT_FLOW_FLAG_UNSOLICITED: Unsolicited TWT Session Setup.
 * @IFXF_TWT_FLOW_FLAG_PROTECT: Specifies whether Tx within SP is protected, Not used.
 */
enum ifxf_twt_flow_flag {
	IFXF_TWT_FLOW_FLAG_BROADCAST      = BIT(0),
	IFXF_TWT_FLOW_FLAG_IMPLICIT       = BIT(1),
	IFXF_TWT_FLOW_FLAG_UNANNOUNCED    = BIT(2),
	IFXF_TWT_FLOW_FLAG_TRIGGER        = BIT(3),
	IFXF_TWT_FLOW_FLAG_WAKE_TBTT_NEGO = BIT(4),
	IFXF_TWT_FLOW_FLAG_REQUEST        = BIT(5),
	IFXF_TWT_FLOW_FLAG_RESPONDER_PM   = BIT(6),
	IFXF_TWT_FLOW_FLAG_UNSOLICITED    = BIT(7),
	IFXF_TWT_FLOW_FLAG_PROTECT        = BIT(8)
};

/**
 * enum ifxf_twt_session_state - TWT session state in the Host driver list
 *
 * @IFXF_TWT_SESS_STATE_UNSPEC: Reserved value 0.
 * @IFXF_TWT_SESS_STATE_SETUP_INPROGRESS: TWT session setup request was sent
 *	to the Firmware.
 * @IFXF_TWT_SESS_STATE_SETUP_INCOMPLETE: TWT session setup is incomplete,
 *	because either the TWT peer did not send a response, or sent a Reject
 *	response driver received a Reject Setup event from the Firmware.
 * @IFXF_TWT_SESS_STATE_SETUP_COMPLETE: TWT session setup is complete and received
 *	setup event from the Firmware.
 * @IFXF_TWT_SESS_STATE_TEARDOWN_INPROGRESS: TWT session teardown request was sent
 *	to the Firmware.
 * @IFXF_TWT_SESS_STATE_TEARDOWN_INCOMPLETE: TWT session teardown event timed out.
 * @IFXF_TWT_SESS_STATE_TEARDOWN_COMPLETE: TWT session teardown is complete and
 *	received Teardown event from the Firmware.
 * @IFXF_TWT_SESS_STATE_MAX: This acts as a the tail of state list.
 *      Make sure it located at the end of the list.
 */
enum ifxf_twt_session_state {
	IFXF_TWT_SESS_STATE_UNSPEC,
	IFXF_TWT_SESS_STATE_SETUP_INPROGRESS,
	IFXF_TWT_SESS_STATE_SETUP_INCOMPLETE,
	IFXF_TWT_SESS_STATE_SETUP_COMPLETE,
	IFXF_TWT_SESS_STATE_TEARDOWN_INPROGRESS,
	IFXF_TWT_SESS_STATE_TEARDOWN_INCOMPLETE,
	IFXF_TWT_SESS_STATE_TEARDOWN_COMPLETE,
	IFXF_TWT_SESS_STATE_MAX
};

/**
 * struct ifxf_twt_params - TWT session parameters
 *
 * @twt_oper: TWT operation, Refer enum ifx_twt_oper.
 * @negotiation_type: Negotiation Type, Refer enum ifx_twt_param_nego_type.
 * @setup_cmd: Setup cmd, Refer enum ifx_twt_oper_setup_cmd_type.
 * @dialog_token: TWT Negotiation Dialog Token.
 * @twt: Target Wake Time.
 * @twt_offset: Target Wake Time Offset.
 * @min_twt: Nominal Minimum Wake Duration.
 * @exponent: Wake Interval Exponent.
 * @mantissa: Wake Interval Mantissa.
 * @requestor: TWT Session requestor or responder.
 * @implicit: implicit or Explicit TWT session.
 * @flow_type: Announced or Un-Announced TWT session.
 * @flow_id: Flow ID.
 * @bcast_twt_id: Broadcast TWT ID.
 * @protection: Protection, Not used.
 * @twt_channel: TWT Channel, Not used.
 * @twt_info_frame_disabled: TWT information frame disabled, Not used.
 * @min_twt_unit: Nominal Minimum Wake Duration Unit.
 * @teardown_all_twt: Teardown All TWT.
 */
struct ifxf_twt_params {
	enum ifx_twt_oper twt_oper;
	enum ifx_twt_param_nego_type negotiation_type;
	enum ifx_twt_oper_setup_cmd_type setup_cmd;
	u8 dialog_token;
	u64 twt;
	u64 twt_offset;
	u8 min_twt;
	u8 exponent;
	u16 mantissa;
	u8 requestor;
	u8 trigger;
	u8 implicit;
	u8 flow_type;
	u8 flow_id;
	u8 bcast_twt_id;
	u8 protection;
	u8 twt_channel;
	u8 twt_info_frame_disabled;
	u8 min_twt_unit;
	u8 teardown_all_twt;
};

/**
 * struct ifxf_twt_session - TWT session structure.
 *
 * @ifidx: interface index.
 * @bsscfgidx: bsscfg index.
 * @peer: TWT peer address.
 * @state: TWT session state, refer enum ifxf_twt_session_state.
 * @twt_params: TWT session parameters.
 * @oper_req_ts: TWT session operation (setup, teardown, etc..) start timestamp.
 * @list: linked list.
 */
struct ifxf_twt_session {
	u8 ifidx;
	s32 bsscfgidx;
	struct ether_addr peer_addr;
	enum ifxf_twt_session_state state;
	struct ifxf_twt_params twt_params;
	unsigned long oper_start_ts;
	struct list_head list;
};

/**
 * enum ifxf_twt_wake_time_type - Type of the struct members wake_time_{h/l} in the
 *	TWT Setup descriptor struct ifxf_twt_sdesc.
 *
 * @IFXF_TWT_WAKE_TIME_TYPE_BSS: wake_time_{h/l} is the BSS TSF tiume.
 * @IFXF_TWT_WAKE_TIME_TYPE_OFFSET: wake_time_{h/l} is an offset of TSF time
 *	when the iovar is processed.
 * @IFXF_TWT_WAKE_TIME_TYPE_AUTO: The target wake time is chosen internally by the Firmware.
 */
enum ifxf_twt_wake_time_type {
	IFXF_TWT_WAKE_TIME_TYPE_BSS,
	IFXF_TWT_WAKE_TIME_TYPE_OFFSET,
	IFXF_TWT_WAKE_TIME_TYPE_AUTO
};

/**
 * struct ifxf_twt_sdesc - TWT Setup Descriptor.
 *
 * @setup_cmd: Setup command and event type. Refer enum ifx_twt_oper_setup_cmd_type.
 * @flow_flags: Flow attributes, Refer enum ifxf_twt_flow_flag.
 * @flow_id: Flow ID, Range 0-7. Set to 0xFF for auto assignment.
 * @wake_type: wake_time_{h/l} type, Refer enum ifxf_twt_wake_time_type.
 * @wake_time_h: Target Wake Time, high 32 bits.
 * @wake_time_l: Target Wake Time, Low 32 bits.
 * @wake_dur: Target Wake Duration in unit of uS.
 * @wake_int: Target Wake Interval.
 * @btwt_persistence: Broadcast TWT Persistence.
 * @wake_int_max: Max Wake interval(uS) for TWT.
 * @duty_cycle_min: Min Duty cycle for TWT(Percentage).
 * @pad: 1 byte pad.
 * @bid: Brodacst TWT ID, Range 0-31. Set to 0xFF for auto assignment.
 * @channel: TWT channel - Not used.
 * @negotiation_type: Negotiation Type, Refer enum ifx_twt_param_nego_type.
 * @frame_recomm: Frame recommendation for broadcast TWTs - Not used.
 */
struct ifxf_twt_sdesc {
	u8 setup_cmd;
	u8 flow_flags;
	u8 flow_id;
	u8 wake_type;
	u32 wake_time_h;
	u32 wake_time_l;
	u32 wake_dur;
	u32 wake_int;
	u32 btwt_persistence;
	u32 wake_int_max;
	u8 duty_cycle_min;
	u8 pad;
	u8 bid;
	u8 channel;
	u8 negotiation_type;
	u8 frame_recomm;
};

/**
 * struct ifxf_twt_setup_event - TWT Setup Completion event data from firmware TWT module
 *
 * @version: Structure version.
 * @length:the byte count of fields from 'dialog' onwards.
 * @dialog: the dialog token user supplied to the TWT setup API.
 * @pad: 3 byte Pad.
 * @status: Event status.
 */
struct ifxf_twt_setup_event {
	u16 version;
	u16 length;
	u8 dialog;
	u8 pad[3];
	s32 status;
        /* enum ifxf_twt_sdesc sdesc; */
};

/**
 * struct ifxf_twt_setup_oper - TWT iovar Setup operation subcmd data to firmware TWT module
 *
 * @version: Structure version.
 * @length: data length (starting after this field).
 * @peer: TWT peer address.
 * @pad: 2 byte Pad.
 * @sdesc: TWT setup descriptor.
 */
struct ifxf_twt_setup_oper {
	u16 version;
	u16 length;
	struct ether_addr peer;
	u8 pad[2];
	struct ifxf_twt_sdesc sdesc;
	u16 dialog;
};

/**
 * struct ifxf_twt_teardesc - TWT Teardown descriptor.
 *
 * @negotiation_type: Negotiation Type: Refer enum ifx_twt_param_nego_type.
 * @flow_id: Flow ID: Range 0-7. Set to 0xFF for auto assignment.
 * @bid: Brodacst TWT ID: Range 0-31. Set to 0xFF for auto assignment.
 * @alltwt: Teardown all TWT sessions: set to 0 or 1.
 */
struct ifxf_twt_teardesc {
	u8 negotiation_type;
	u8 flow_id;
	u8 bid;
	u8 alltwt;
};

/**
 * struct ifxf_twt_teardown_event - TWT Teardown Completion event data from firmware TWT module.
 *
 * @version: structure version.
 * @length: the byte count of fields from 'status' onwards.
 * @status: Event status.
 */
struct ifxf_twt_teardown_event {
	u16 version;
	u16 length;
	s32 status;
	/* enum ifx_twt_teardesc teardesc; */
};

/**
 * struct ifxf_twt_teardown_oper - TWT iovar Teardown operation subcmd data to firmware TWT module.
 *
 * @version: structure version.
 * @length: data length (starting after this field).
 * @peer: TWT peer address.
 * @teardesc: TWT Teardown descriptor.
 */
struct ifxf_twt_teardown_oper {
	u16 version;
	u16 length;
	struct ether_addr peer;
	struct ifxf_twt_teardesc teardesc;
};

/**
 * ifxf_twt_debugfs_create() - create debugfs entries.
 *
 * @drvr: driver instance.
 */
void ifxf_twt_debugfs_create(struct ifxf_pub *drvr);

/**
 * ifxf_twt_cleanup_sessions - Cleanup the TWT sessions from the driver list.
 *
 * @ifp: interface instatnce.
 */
s32 ifxf_twt_cleanup_sessions(struct ifxf_if *ifp);

/**
 * ifxf_twt_event_timeout_handler - Iterate the session list and handle stale
 *	TWT session entries which are failed to move to next state in FSM.
 */
void ifxf_twt_event_timeout_handler(struct timer_list *t);

/**
 * ifxf_notify_twt_event() - Handle the TWT Event notifications from Firmware.
 *
 * @ifp: interface instatnce.
 * @e: event message.
 * @data: payload of message, contains TWT session data.
 */
int ifxf_notify_twt_event(struct ifxf_if *ifp, const struct ifxf_event_msg *e,
			  void *data);

/**
 * ifxf_twt_oper() - Handle the TWT Operation requests from Userspace.
 *
 * @wiphy: wiphy object for cfg80211 interface.
 * @wdev: wireless device.
 * @twt_params: TWT session parameters.
 */
int ifxf_twt_oper(struct wiphy *wiphy, struct wireless_dev *wdev,
		  struct ifxf_twt_params twt_params);

#endif /* IFXF_TWT_H */
