// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2012 Broadcom Corporation
 */
#ifndef WL_CFGP2P_H_
#define WL_CFGP2P_H_

#include <net/cfg80211.h>

struct ifxf_cfg80211_info;

/**
 * enum p2p_bss_type - different type of BSS configurations.
 *
 * @P2PAPI_BSSCFG_PRIMARY: maps to driver's primary bsscfg.
 * @P2PAPI_BSSCFG_DEVICE: maps to driver's P2P device discovery bsscfg.
 * @P2PAPI_BSSCFG_CONNECTION: maps to driver's 1st P2P connection bsscfg.
 * @P2PAPI_BSSCFG_CONNECTION2: maps to driver's 2nd P2P connection bsscfg.
 * @P2PAPI_BSSCFG_MAX: used for range checking.
 */
enum p2p_bss_type {
	P2PAPI_BSSCFG_PRIMARY, /* maps to driver's primary bsscfg */
	P2PAPI_BSSCFG_DEVICE, /* maps to driver's P2P device discovery bsscfg */
	P2PAPI_BSSCFG_CONNECTION, /* driver's 1st P2P connection bsscfg */
	P2PAPI_BSSCFG_CONNECTION2, /* driver's 2nd P2P connection bsscfg */
	P2PAPI_BSSCFG_MAX
};

/**
 * struct p2p_bss - peer-to-peer bss related information.
 *
 * @vif: virtual interface of this P2P bss.
 * @private_data: TBD
 */
struct p2p_bss {
	struct ifxf_cfg80211_vif *vif;
	void *private_data;
};

/**
 * enum ifxf_p2p_status - P2P specific dongle status.
 *
 * @IFXF_P2P_STATUS_IF_ADD: peer-to-peer vif add sent to dongle.
 * @IFXF_P2P_STATUS_IF_DEL: NOT-USED?
 * @IFXF_P2P_STATUS_IF_DELETING: peer-to-peer vif delete sent to dongle.
 * @IFXF_P2P_STATUS_IF_CHANGING: peer-to-peer vif change sent to dongle.
 * @IFXF_P2P_STATUS_IF_CHANGED: peer-to-peer vif change completed on dongle.
 * @IFXF_P2P_STATUS_ACTION_TX_COMPLETED: action frame tx completed.
 * @IFXF_P2P_STATUS_ACTION_TX_NOACK: action frame tx not acked.
 * @IFXF_P2P_STATUS_GO_NEG_PHASE: P2P GO negotiation ongoing.
 * @IFXF_P2P_STATUS_DISCOVER_LISTEN: P2P listen, remaining on channel.
 * @IFXF_P2P_STATUS_SENDING_ACT_FRAME: In the process of sending action frame.
 * @IFXF_P2P_STATUS_WAITING_NEXT_AF_LISTEN: extra listen time for af tx.
 * @IFXF_P2P_STATUS_WAITING_NEXT_ACT_FRAME: waiting for action frame response.
 * @IFXF_P2P_STATUS_FINDING_COMMON_CHANNEL: search channel for AF active.
 */
enum ifxf_p2p_status {
	IFXF_P2P_STATUS_ENABLED,
	IFXF_P2P_STATUS_IF_ADD,
	IFXF_P2P_STATUS_IF_DEL,
	IFXF_P2P_STATUS_IF_DELETING,
	IFXF_P2P_STATUS_IF_CHANGING,
	IFXF_P2P_STATUS_IF_CHANGED,
	IFXF_P2P_STATUS_ACTION_TX_COMPLETED,
	IFXF_P2P_STATUS_ACTION_TX_NOACK,
	IFXF_P2P_STATUS_GO_NEG_PHASE,
	IFXF_P2P_STATUS_DISCOVER_LISTEN,
	IFXF_P2P_STATUS_SENDING_ACT_FRAME,
	IFXF_P2P_STATUS_WAITING_NEXT_AF_LISTEN,
	IFXF_P2P_STATUS_WAITING_NEXT_ACT_FRAME,
	IFXF_P2P_STATUS_FINDING_COMMON_CHANNEL
};

/**
 * struct afx_hdl - action frame off channel storage.
 *
 * @afx_work: worker thread for searching channel
 * @act_frm_scan: thread synchronizing struct.
 * @is_active: channel searching active.
 * @peer_chan: current channel.
 * @is_listen: sets mode for afx worker.
 * @my_listen_chan: this peers listen channel.
 * @peer_listen_chan: remote peers listen channel.
 * @tx_dst_addr: mac address where tx af should be sent to.
 */
struct afx_hdl {
	struct work_struct afx_work;
	struct completion act_frm_scan;
	bool is_active;
	u16 peer_chan;
	bool is_listen;
	u16 my_listen_chan;
	u16 peer_listen_chan;
	u8 tx_dst_addr[ETH_ALEN];
};

/**
 * struct ifxf_p2p_info - p2p specific driver information.
 *
 * @cfg: driver private data for cfg80211 interface.
 * @status: status of P2P (see enum ifxf_p2p_status).
 * @dev_addr: P2P device address.
 * @int_addr: P2P interface address.
 * @bss_idx: informate for P2P bss types.
 * @listen_timer: timer for @WL_P2P_DISC_ST_LISTEN discover state.
 * @listen_channel: channel for @WL_P2P_DISC_ST_LISTEN discover state.
 * @remain_on_channel: contains copy of struct used by cfg80211.
 * @remain_on_channel_cookie: cookie counter for remain on channel cmd
 * @next_af_subtype: expected action frame subtype.
 * @send_af_done: indication that action frame tx is complete.
 * @afx_hdl: action frame search handler info.
 * @af_sent_channel: channel action frame is sent.
 * @af_tx_sent_jiffies: jiffies time when af tx was transmitted.
 * @wait_next_af: thread synchronizing struct.
 * @gon_req_action: about to send go negotiation requets frame.
 * @block_gon_req_tx: drop tx go negotiation requets frame.
 * @p2pdev_dynamically: is p2p device if created by module param or supplicant.
 * @wait_for_offchan_complete: wait for off-channel tx completion event.
 */
struct ifxf_p2p_info {
	struct ifxf_cfg80211_info *cfg;
	unsigned long status;
	u8 dev_addr[ETH_ALEN];
	u8 conn_int_addr[ETH_ALEN];
	u8 conn2_int_addr[ETH_ALEN];
	struct p2p_bss bss_idx[P2PAPI_BSSCFG_MAX];
	struct timer_list listen_timer;
	u8 listen_channel;
	struct ieee80211_channel remain_on_channel;
	u32 remain_on_channel_cookie;
	u8 next_af_subtype;
	struct completion send_af_done;
	struct afx_hdl afx_hdl;
	u32 af_sent_channel;
	unsigned long af_tx_sent_jiffies;
	struct completion wait_next_af;
	bool gon_req_action;
	bool block_gon_req_tx;
	bool p2pdev_dynamically;
	bool wait_for_offchan_complete;
	struct wireless_dev *remin_on_channel_wdev;
};

s32 ifxf_p2p_attach(struct ifxf_cfg80211_info *cfg, bool p2pdev_forced);
void ifxf_p2p_detach(struct ifxf_p2p_info *p2p);
struct wireless_dev *ifxf_p2p_add_vif(struct wiphy *wiphy, const char *name,
				       unsigned char name_assign_type,
				       enum nl80211_iftype type,
				       struct vif_params *params);
int ifxf_p2p_del_vif(struct wiphy *wiphy, struct wireless_dev *wdev);
int ifxf_p2p_ifchange(struct ifxf_cfg80211_info *cfg,
		       enum ifxf_fil_p2p_if_types if_type);
void ifxf_p2p_ifp_removed(struct ifxf_if *ifp, bool rtnl_locked);
int ifxf_p2p_start_device(struct wiphy *wiphy, struct wireless_dev *wdev);
void ifxf_p2p_stop_device(struct wiphy *wiphy, struct wireless_dev *wdev);
int ifxf_p2p_scan_prep(struct wiphy *wiphy,
			struct cfg80211_scan_request *request,
			struct ifxf_cfg80211_vif *vif);
int ifxf_p2p_remain_on_channel(struct wiphy *wiphy, struct wireless_dev *wdev,
				struct ieee80211_channel *channel,
				unsigned int duration, u64 *cookie);
int ifxf_p2p_notify_listen_complete(struct ifxf_if *ifp,
				     const struct ifxf_event_msg *e,
				     void *data);
void ifxf_p2p_cancel_remain_on_channel(struct ifxf_if *ifp);
int ifxf_p2p_notify_action_frame_rx(struct ifxf_if *ifp,
				     const struct ifxf_event_msg *e,
				     void *data);
int ifxf_p2p_notify_action_tx_complete(struct ifxf_if *ifp,
					const struct ifxf_event_msg *e,
					void *data);
bool ifxf_p2p_send_action_frame(struct ifxf_cfg80211_info *cfg,
				 struct net_device *ndev,
				 struct ifxf_fil_af_params_le *af_params,
				 struct ifxf_cfg80211_vif *vif,
				 struct ieee80211_channel *peer_listen_chan);
bool ifxf_p2p_scan_finding_common_channel(struct ifxf_cfg80211_info *cfg,
					   struct ifxf_bss_info_le *bi);
s32 ifxf_p2p_notify_rx_mgmt_p2p_probereq(struct ifxf_if *ifp,
					  const struct ifxf_event_msg *e,
					  void *data);
#endif /* WL_CFGP2P_H_ */
