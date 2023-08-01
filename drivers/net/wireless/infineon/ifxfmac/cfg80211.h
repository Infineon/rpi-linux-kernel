// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2010 Broadcom Corporation
 */

#ifndef IFXFMAC_CFG80211_H
#define IFXFMAC_CFG80211_H

/* for ifxu_d11inf */
#include <ifxu_d11.h>

#include "core.h"
#include "fwil_types.h"
#include "p2p.h"

#define IFXF_SCAN_IE_LEN_MAX		2048

#define WL_NUM_SCAN_MAX			10
#define WL_TLV_INFO_MAX			1024
#define WL_BSS_INFO_MAX			2048
#define WL_ASSOC_INFO_MAX		512	/* assoc related fil max buf */
#define WL_EXTRA_BUF_MAX		2048
#define WL_ROAM_TRIGGER_LEVEL		-75
#define WL_ROAM_DELTA			20

/* WME Access Category Indices (ACIs) */
#define AC_BE			0	/* Best Effort */
#define AC_BK			1	/* Background */
#define AC_VI			2	/* Video */
#define AC_VO			3	/* Voice */
#define EDCF_AC_COUNT		4
#define MAX_8021D_PRIO		8

#define EDCF_ACI_MASK			0x60
#define EDCF_ACI_SHIFT			5
#define EDCF_ACM_MASK                  0x10
#define EDCF_ECWMIN_MASK		0x0f
#define EDCF_ECWMAX_SHIFT		4
#define EDCF_AIFSN_MASK			0x0f
#define EDCF_AIFSN_MAX			15
#define EDCF_ECWMAX_MASK		0xf0

/* Keep IFXF_ESCAN_BUF_SIZE below 64K (65536). Allocing over 64K can be
 * problematic on some systems and should be avoided.
 */
#define IFXF_ESCAN_BUF_SIZE		65000
#define IFXF_ESCAN_TIMER_INTERVAL_MS	10000	/* E-Scan timeout */

#define WL_ESCAN_ACTION_START		1
#define WL_ESCAN_ACTION_CONTINUE	2
#define WL_ESCAN_ACTION_ABORT		3

#define WL_AUTH_SHARED_KEY		1	/* d11 shared authentication */
#define IE_MAX_LEN			512

/* IE TLV processing */
#define TLV_LEN_OFF			1	/* length offset */
#define TLV_HDR_LEN			2	/* header length */
#define TLV_BODY_OFF			2	/* body offset */
#define TLV_OUI_LEN			3	/* oui id length */

/* 802.11 Mgmt Packet flags */
#define IFXF_VNDR_IE_BEACON_FLAG	0x1
#define IFXF_VNDR_IE_PRBRSP_FLAG	0x2
#define IFXF_VNDR_IE_ASSOCRSP_FLAG	0x4
#define IFXF_VNDR_IE_AUTHRSP_FLAG	0x8
#define IFXF_VNDR_IE_PRBREQ_FLAG	0x10
#define IFXF_VNDR_IE_ASSOCREQ_FLAG	0x20
/* vendor IE in IW advertisement protocol ID field */
#define IFXF_VNDR_IE_IWAPID_FLAG	0x40
/* allow custom IE id */
#define IFXF_VNDR_IE_CUSTOM_FLAG	0x100

/* P2P Action Frames flags (spec ordered) */
#define IFXF_VNDR_IE_GONREQ_FLAG     0x001000
#define IFXF_VNDR_IE_GONRSP_FLAG     0x002000
#define IFXF_VNDR_IE_GONCFM_FLAG     0x004000
#define IFXF_VNDR_IE_INVREQ_FLAG     0x008000
#define IFXF_VNDR_IE_INVRSP_FLAG     0x010000
#define IFXF_VNDR_IE_DISREQ_FLAG     0x020000
#define IFXF_VNDR_IE_DISRSP_FLAG     0x040000
#define IFXF_VNDR_IE_PRDREQ_FLAG     0x080000
#define IFXF_VNDR_IE_PRDRSP_FLAG     0x100000

#define IFXF_VNDR_IE_P2PAF_SHIFT	12

#define IFXF_MAX_DEFAULT_KEYS		6

/* beacon loss timeout defaults */
#define IFXF_DEFAULT_BCN_TIMEOUT_ROAM_ON	2
#define IFXF_DEFAULT_BCN_TIMEOUT_ROAM_OFF	4

#define IFXF_VIF_EVENT_TIMEOUT		msecs_to_jiffies(1500)

#define IFXF_PM_WAIT_MAXRETRY			100

/* cfg80211 wowlan definitions */
#define WL_WOWLAN_MAX_PATTERNS			8
#define WL_WOWLAN_MIN_PATTERN_LEN		1
#define WL_WOWLAN_MAX_PATTERN_LEN		255
#define WL_WOWLAN_PKT_FILTER_ID_FIRST	201
#define WL_WOWLAN_PKT_FILTER_ID_LAST	(WL_WOWLAN_PKT_FILTER_ID_FIRST + \
					WL_WOWLAN_MAX_PATTERNS - 1)

#define WL_RSPEC_ENCODE_HE	     0x03000000 /* HE MCS and Nss is stored in RSPEC_RATE_MASK */
#define WL_RSPEC_HE_NSS_UNSPECIFIED	0xF
#define WL_RSPEC_HE_NSS_SHIFT	     4               /* HE Nss value shift */
#define WL_RSPEC_HE_GI_MASK	     0x00000C00      /* HE GI indices */
#define WL_RSPEC_HE_GI_SHIFT	     10
#define HE_GI_TO_RSPEC(gi)	     (((gi) << WL_RSPEC_HE_GI_SHIFT) & WL_RSPEC_HE_GI_MASK)

/**
 * enum ifxf_scan_status - scan engine status
 *
 * @IFXF_SCAN_STATUS_BUSY: scanning in progress on dongle.
 * @IFXF_SCAN_STATUS_ABORT: scan being aborted on dongle.
 * @IFXF_SCAN_STATUS_SUPPRESS: scanning is suppressed in driver.
 */
enum ifxf_scan_status {
	IFXF_SCAN_STATUS_BUSY,
	IFXF_SCAN_STATUS_ABORT,
	IFXF_SCAN_STATUS_SUPPRESS,
};

/* dongle configuration */
struct ifxf_cfg80211_conf {
	u32 frag_threshold;
	u32 rts_threshold;
	u32 retry_short;
	u32 retry_long;
};

/* security information with currently associated ap */
struct ifxf_cfg80211_security {
	u32 wpa_versions;
	u32 auth_type;
	u32 cipher_pairwise;
	u32 cipher_group;
};

enum ifxf_profile_fwsup {
	IFXF_PROFILE_FWSUP_NONE,
	IFXF_PROFILE_FWSUP_PSK,
	IFXF_PROFILE_FWSUP_1X,
	IFXF_PROFILE_FWSUP_SAE,
	IFXF_PROFILE_FWSUP_ROAM
};

/**
 * enum ifxf_profile_fwauth - firmware authenticator profile
 *
 * @IFXF_PROFILE_FWAUTH_NONE: no firmware authenticator
 * @IFXF_PROFILE_FWAUTH_PSK: authenticator for WPA/WPA2-PSK
 * @IFXF_PROFILE_FWAUTH_SAE: authenticator for SAE
 */
enum ifxf_profile_fwauth {
	IFXF_PROFILE_FWAUTH_NONE,
	IFXF_PROFILE_FWAUTH_PSK,
	IFXF_PROFILE_FWAUTH_SAE
};

/**
 * struct ifxf_cfg80211_profile - profile information.
 *
 * @bssid: bssid of joined/joining ibss.
 * @sec: security information.
 * @key: key information
 */
struct ifxf_cfg80211_profile {
	u8 bssid[ETH_ALEN];
	struct ifxf_cfg80211_security sec;
	struct ifxf_wsec_key key[IFXF_MAX_DEFAULT_KEYS];
	enum ifxf_profile_fwsup use_fwsup;
	u16 use_fwauth;
	bool is_ft;
	bool is_okc;
};

/**
 * enum ifxf_vif_status - bit indices for vif status.
 *
 * @IFXF_VIF_STATUS_READY: ready for operation.
 * @IFXF_VIF_STATUS_CONNECTING: connect/join in progress.
 * @IFXF_VIF_STATUS_CONNECTED: connected/joined successfully.
 * @IFXF_VIF_STATUS_DISCONNECTING: disconnect/disable in progress.
 * @IFXF_VIF_STATUS_AP_CREATED: AP operation started.
 * @IFXF_VIF_STATUS_EAP_SUCCUSS: EAPOL handshake successful.
 * @IFXF_VIF_STATUS_ASSOC_SUCCESS: successful SET_SSID received.
 */
enum ifxf_vif_status {
	IFXF_VIF_STATUS_READY,
	IFXF_VIF_STATUS_CONNECTING,
	IFXF_VIF_STATUS_CONNECTED,
	IFXF_VIF_STATUS_DISCONNECTING,
	IFXF_VIF_STATUS_AP_CREATED,
	IFXF_VIF_STATUS_EAP_SUCCESS,
	IFXF_VIF_STATUS_ASSOC_SUCCESS,
};

enum ifxf_cfg80211_pm_state {
	IFXF_CFG80211_PM_STATE_RESUMED,
	IFXF_CFG80211_PM_STATE_RESUMING,
	IFXF_CFG80211_PM_STATE_SUSPENDED,
	IFXF_CFG80211_PM_STATE_SUSPENDING,
};

/**
 * enum ifxf_mgmt_tx_status - mgmt frame tx status
 *
 * @IFXF_MGMT_TX_ACK: mgmt frame acked
 * @IFXF_MGMT_TX_NOACK: mgmt frame not acked
 * @IFXF_MGMT_TX_OFF_CHAN_COMPLETED: off-channel complete
 * @IFXF_MGMT_TX_SEND_FRAME: mgmt frame tx is in progres
 */
enum ifxf_mgmt_tx_status {
	IFXF_MGMT_TX_ACK,
	IFXF_MGMT_TX_NOACK,
	IFXF_MGMT_TX_OFF_CHAN_COMPLETED,
	IFXF_MGMT_TX_SEND_FRAME
};

/**
 * struct vif_saved_ie - holds saved IEs for a virtual interface.
 *
 * @probe_req_ie: IE info for probe request.
 * @probe_res_ie: IE info for probe response.
 * @beacon_ie: IE info for beacon frame.
 * @assoc_res_ie: IE info for association response frame.
 * @probe_req_ie_len: IE info length for probe request.
 * @probe_res_ie_len: IE info length for probe response.
 * @beacon_ie_len: IE info length for beacon frame.
 * @assoc_res_ie_len: IE info length for association response frame.
 */
struct vif_saved_ie {
	u8  probe_req_ie[IE_MAX_LEN];
	u8  probe_res_ie[IE_MAX_LEN];
	u8  beacon_ie[IE_MAX_LEN];
	u8  assoc_req_ie[IE_MAX_LEN];
	u8  assoc_res_ie[IE_MAX_LEN];
	u32 probe_req_ie_len;
	u32 probe_res_ie_len;
	u32 beacon_ie_len;
	u32 assoc_req_ie_len;
	u32 assoc_res_ie_len;
};

/**
 * struct ifxf_cfg80211_vif - virtual interface specific information.
 *
 * @ifp: lower layer interface pointer
 * @wdev: wireless device.
 * @profile: profile information.
 * @sme_state: SME state using enum ifxf_vif_status bits.
 * @list: linked list.
 * @mgmt_rx_reg: registered rx mgmt frame types.
 * @mbss: Multiple BSS type, set if not first AP (not relevant for P2P).
 * @cqm_rssi_low: Lower RSSI limit for CQM monitoring
 * @cqm_rssi_high: Upper RSSI limit for CQM monitoring
 * @cqm_rssi_last: Last RSSI reading for CQM monitoring
 */
struct ifxf_cfg80211_vif {
	struct ifxf_if *ifp;
	struct wireless_dev wdev;
	struct ifxf_cfg80211_profile profile;
	unsigned long sme_state;
	struct vif_saved_ie saved_ie;
	struct list_head list;
	struct completion mgmt_tx;
	unsigned long mgmt_tx_status;
	u32 mgmt_tx_id;
	u16 mgmt_rx_reg;
	bool mbss;
	int is_11d;
	s32 cqm_rssi_low;
	s32 cqm_rssi_high;
	s32 cqm_rssi_last;
};

/* association inform */
struct ifxf_cfg80211_connect_info {
	u8 *req_ie;
	s32 req_ie_len;
	u8 *resp_ie;
	s32 resp_ie_len;
};

/* assoc ie length */
struct ifxf_cfg80211_assoc_ielen_le {
	__le32 req_len;
	__le32 resp_len;
	__le32 flags;
};

struct ifxf_cfg80211_edcf_acparam {
	u8 ACI;
	u8 ECW;
	u16 TXOP;        /* stored in network order (ls octet first) */
};

/* dongle escan state */
enum wl_escan_state {
	WL_ESCAN_STATE_IDLE,
	WL_ESCAN_STATE_SCANNING
};

struct escan_info {
	u32 escan_state;
	u8 *escan_buf;
	struct wiphy *wiphy;
	struct ifxf_if *ifp;
	s32 (*run)(struct ifxf_cfg80211_info *cfg, struct ifxf_if *ifp,
		   struct cfg80211_scan_request *request);
};

struct cqm_rssi_info {
	bool enable;
	s32 rssi_threshold;
};

/**
 * struct ifxf_cfg80211_vif_event - virtual interface event information.
 *
 * @vif_wq: waitqueue awaiting interface event from firmware.
 * @vif_event_lock: protects other members in this structure.
 * @vif_complete: completion for net attach.
 * @action: either add, change, or delete.
 * @vif: virtual interface object related to the event.
 */
struct ifxf_cfg80211_vif_event {
	wait_queue_head_t vif_wq;
	spinlock_t vif_event_lock;
	u8 action;
	struct ifxf_cfg80211_vif *vif;
};

/**
 * struct ifxf_cfg80211_wowl - wowl related information.
 *
 * @active: set on suspend, cleared on resume.
 * @pre_pmmode: firmware PM mode at entering suspend.
 * @nd: net dectect data.
 * @nd_info: helper struct to pass to cfg80211.
 * @nd_data_wait: wait queue to sync net detect data.
 * @nd_data_completed: completion for net detect data.
 * @nd_enabled: net detect enabled.
 */
struct ifxf_cfg80211_wowl {
	bool active;
	u32 pre_pmmode;
	struct cfg80211_wowlan_nd_match *nd;
	struct cfg80211_wowlan_nd_info *nd_info;
	wait_queue_head_t nd_data_wait;
	bool nd_data_completed;
	bool nd_enabled;
};

/**
 * struct ifxf_cfg80211_info - dongle private data of cfg80211 interface
 *
 * @wiphy: wiphy object for cfg80211 interface.
 * @ops: pointer to copy of ops as registered with wiphy object.
 * @conf: dongle configuration.
 * @p2p: peer-to-peer specific information.
 * @btcoex: Bluetooth coexistence information.
 * @scan_request: cfg80211 scan request object.
 * @usr_sync: mainly for dongle up/down synchronization.
 * @bss_list: bss_list holding scanned ap information.
 * @bss_info: bss information for cfg80211 layer.
 * @conn_info: association info.
 * @pmk_list: wpa2 pmk list.
 * @scan_status: scan activity on the dongle.
 * @pub: common driver information.
 * @channel: current channel.
 * @int_escan_map: bucket map for which internal e-scan is done.
 * @ibss_starter: indicates this sta is ibss starter.
 * @pwr_save: indicate whether dongle to support power save mode.
 * @dongle_up: indicate whether dongle up or not.
 * @roam_on: on/off switch for dongle self-roaming.
 * @scan_tried: indicates if first scan attempted.
 * @dcmd_buf: dcmd buffer.
 * @extra_buf: mainly to grab assoc information.
 * @debugfsdir: debugfs folder for this device.
 * @escan_info: escan information.
 * @escan_timeout: Timer for catch scan timeout.
 * @escan_timeout_work: scan timeout worker.
 * @vif_list: linked list of vif instances.
 * @vif_cnt: number of vif instances.
 * @vif_event: vif event signalling.
 * @wowl: wowl related information.
 * @pno: information of pno module.
 */
struct ifxf_cfg80211_info {
	struct wiphy *wiphy;
	struct ifxf_cfg80211_conf *conf;
	struct ifxf_p2p_info p2p;
	struct ifxf_btcoex_info *btcoex;
	struct cfg80211_scan_request *scan_request;
	struct mutex usr_sync;
	struct wl_cfg80211_bss_info *bss_info;
	struct ifxf_cfg80211_connect_info conn_info;
	struct ifxf_pmk_list_le pmk_list;
	unsigned long scan_status;
	struct ifxf_pub *pub;
	u32 channel;
	u32 int_escan_map;
	bool ibss_starter;
	bool pwr_save;
	bool dongle_up;
	bool scan_tried;
	u8 *dcmd_buf;
	u8 *extra_buf;
	struct dentry *debugfsdir;
	struct escan_info escan_info;
	struct timer_list escan_timeout;
	struct work_struct escan_timeout_work;
	struct cqm_rssi_info cqm_info;
	struct list_head vif_list;
	struct ifxf_cfg80211_vif_event vif_event;
	struct completion vif_disabled;
	struct ifxu_d11inf d11inf;
	struct ifxf_assoclist_le assoclist;
	struct ifxf_cfg80211_wowl wowl;
	struct ifxf_pno_info *pno;
	u8 ac_priority[MAX_8021D_PRIO];
	u8 pm_state;
	u8 num_softap;
};

/**
 * struct ifxf_tlv - tag_ID/length/value_buffer tuple.
 *
 * @id: tag identifier.
 * @len: number of bytes in value buffer.
 * @data: value buffer.
 */
struct ifxf_tlv {
	u8 id;
	u8 len;
	u8 data[1];
};

struct ifx_xtlv {
	u16	id;
	u16	len;
	u8	data[1];
};

static inline struct wiphy *cfg_to_wiphy(struct ifxf_cfg80211_info *cfg)
{
	return cfg->wiphy;
}

static inline struct ifxf_cfg80211_info *wiphy_to_cfg(struct wiphy *w)
{
	struct ifxf_pub *drvr = wiphy_priv(w);
	return drvr->config;
}

static inline struct ifxf_cfg80211_info *wdev_to_cfg(struct wireless_dev *wd)
{
	return wiphy_to_cfg(wd->wiphy);
}

static inline struct ifxf_cfg80211_vif *wdev_to_vif(struct wireless_dev *wdev)
{
	return container_of(wdev, struct ifxf_cfg80211_vif, wdev);
}

static inline
struct net_device *cfg_to_ndev(struct ifxf_cfg80211_info *cfg)
{
	return ifxf_get_ifp(cfg->pub, 0)->ndev;
}

static inline struct ifxf_cfg80211_info *ndev_to_cfg(struct net_device *ndev)
{
	return wdev_to_cfg(ndev->ieee80211_ptr);
}

static inline struct ifxf_cfg80211_profile *ndev_to_prof(struct net_device *nd)
{
	struct ifxf_if *ifp = netdev_priv(nd);
	return &ifp->vif->profile;
}

static inline struct ifxf_cfg80211_vif *ndev_to_vif(struct net_device *ndev)
{
	struct ifxf_if *ifp = netdev_priv(ndev);
	return ifp->vif;
}

static inline struct
ifxf_cfg80211_connect_info *cfg_to_conn(struct ifxf_cfg80211_info *cfg)
{
	return &cfg->conn_info;
}

struct ifxf_cfg80211_info *ifxf_cfg80211_attach(struct ifxf_pub *drvr,
						  struct cfg80211_ops *ops,
						  bool p2pdev_forced);
void ifxf_cfg80211_detach(struct ifxf_cfg80211_info *cfg);
s32 ifxf_cfg80211_up(struct net_device *ndev);
s32 ifxf_cfg80211_down(struct net_device *ndev);
struct cfg80211_ops *ifxf_cfg80211_get_ops(struct ifxf_mp_device *settings);
enum nl80211_iftype ifxf_cfg80211_get_iftype(struct ifxf_if *ifp);

struct ifxf_cfg80211_vif *ifxf_alloc_vif(struct ifxf_cfg80211_info *cfg,
					   enum nl80211_iftype type);
void ifxf_free_vif(struct ifxf_cfg80211_vif *vif);

s32 ifxf_vif_set_mgmt_ie(struct ifxf_cfg80211_vif *vif, s32 pktflag,
			  const u8 *vndr_ie_buf, u32 vndr_ie_len);
s32 ifxf_vif_clear_mgmt_ies(struct ifxf_cfg80211_vif *vif);
u16 channel_to_chanspec(struct ifxu_d11inf *d11inf,
			struct ieee80211_channel *ch);
bool ifxf_get_vif_state_any(struct ifxf_cfg80211_info *cfg,
			     unsigned long state);
void ifxf_cfg80211_arm_vif_event(struct ifxf_cfg80211_info *cfg,
				  struct ifxf_cfg80211_vif *vif);
bool ifxf_cfg80211_vif_event_armed(struct ifxf_cfg80211_info *cfg);
int ifxf_cfg80211_wait_vif_event(struct ifxf_cfg80211_info *cfg,
				  u8 action, ulong timeout);
s32 ifxf_notify_escan_complete(struct ifxf_cfg80211_info *cfg,
				struct ifxf_if *ifp, bool aborted,
				bool fw_abort);
void ifxf_set_mpc(struct ifxf_if *ndev, int mpc);
void ifxf_abort_scanning(struct ifxf_cfg80211_info *cfg);
void ifxf_cfg80211_free_netdev(struct net_device *ndev);
bool ifxf_is_apmode_operating(struct wiphy *wiphy);
void ifxf_cfg80211_update_proto_addr_mode(struct wireless_dev *wdev);
#endif /* IFXFMAC_CFG80211_H */
