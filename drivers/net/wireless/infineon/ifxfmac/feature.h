// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2014 Broadcom Corporation
 */
#ifndef _IFXF_FEATURE_H
#define _IFXF_FEATURE_H

/*
 * Features:
 *
 * MBSS: multiple BSSID support (eg. guest network in AP mode).
 * MCHAN: multi-channel for concurrent P2P.
 * PNO: preferred network offload.
 * WOWL: Wake-On-WLAN.
 * P2P: peer-to-peer
 * RSDB: Real Simultaneous Dual Band
 * TDLS: Tunneled Direct Link Setup
 * SCAN_RANDOM_MAC: Random MAC during (net detect) scheduled scan.
 * WOWL_ND: WOWL net detect (PNO)
 * WOWL_GTK: (WOWL) GTK rekeying offload
 * WOWL_ARP_ND: ARP and Neighbor Discovery offload support during WOWL.
 * MFP: 802.11w Management Frame Protection.
 * GSCAN: enhanced scan offload feature.
 * FWSUP: Firmware supplicant.
 * MONITOR: firmware can pass monitor packets to host.
 * MONITOR_FLAG: firmware flags monitor packets.
 * MONITOR_FMT_RADIOTAP: firmware provides monitor packets with radiotap header
 * MONITOR_FMT_HW_RX_HDR: firmware provides monitor packets with hw/ucode header
 * DOT11H: firmware supports 802.11h
 * SAE: simultaneous authentication of equals
 * FWAUTH: Firmware authenticator
 * DUMP_OBSS: Firmware has capable to dump obss info to support ACS
 * SAE_EXT: SAE be handled by userspace supplicant
 * GCMP: firmware has defined GCMP or not.
 * TWT: Firmware has the TWT Module Support.
 * OFFLOADS: Firmware can do the packet processing work offloaded by
 *	Host Driver, i.e, it can process specifc types of RX packets like
 *	ARP, ND, etc and send out a suitable response packet from within
 * 	Firmware.
 * ULP: Firmware supports Ultra Low Power mode of operation.
 */
#define IFXF_FEAT_LIST \
	IFXF_FEAT_DEF(MBSS) \
	IFXF_FEAT_DEF(MCHAN) \
	IFXF_FEAT_DEF(PNO) \
	IFXF_FEAT_DEF(WOWL) \
	IFXF_FEAT_DEF(P2P) \
	IFXF_FEAT_DEF(RSDB) \
	IFXF_FEAT_DEF(TDLS) \
	IFXF_FEAT_DEF(SCAN_RANDOM_MAC) \
	IFXF_FEAT_DEF(WOWL_ND) \
	IFXF_FEAT_DEF(WOWL_GTK) \
	IFXF_FEAT_DEF(WOWL_ARP_ND) \
	IFXF_FEAT_DEF(MFP) \
	IFXF_FEAT_DEF(GSCAN) \
	IFXF_FEAT_DEF(FWSUP) \
	IFXF_FEAT_DEF(MONITOR) \
	IFXF_FEAT_DEF(MONITOR_FLAG) \
	IFXF_FEAT_DEF(MONITOR_FMT_RADIOTAP) \
	IFXF_FEAT_DEF(MONITOR_FMT_HW_RX_HDR) \
	IFXF_FEAT_DEF(DOT11H) \
	IFXF_FEAT_DEF(SAE) \
	IFXF_FEAT_DEF(FWAUTH) \
	IFXF_FEAT_DEF(DUMP_OBSS) \
	IFXF_FEAT_DEF(SAE_EXT) \
	IFXF_FEAT_DEF(FBT) \
	IFXF_FEAT_DEF(OKC) \
	IFXF_FEAT_DEF(GCMP) \
	IFXF_FEAT_DEF(TWT) \
	IFXF_FEAT_DEF(OFFLOADS) \
	IFXF_FEAT_DEF(ULP)

/*
 * Quirks:
 *
 * AUTO_AUTH: workaround needed for automatic authentication type.
 * NEED_MPC: driver needs to disable MPC during scanning operation.
 */
#define IFXF_QUIRK_LIST \
	IFXF_QUIRK_DEF(AUTO_AUTH) \
	IFXF_QUIRK_DEF(NEED_MPC)

#define IFXF_FEAT_DEF(_f) \
	IFXF_FEAT_ ## _f,
/*
 * expand feature list to enumeration.
 */
enum ifxf_feat_id {
	IFXF_FEAT_LIST
	IFXF_FEAT_LAST
};
#undef IFXF_FEAT_DEF

#define IFXF_QUIRK_DEF(_q) \
	IFXF_FEAT_QUIRK_ ## _q,
/*
 * expand quirk list to enumeration.
 */
enum ifxf_feat_quirk {
	IFXF_QUIRK_LIST
	IFXF_FEAT_QUIRK_LAST
};
#undef IFXF_QUIRK_DEF

/**
 * ifxf_feat_attach() - determine features and quirks.
 *
 * @drvr: driver instance.
 */
void ifxf_feat_attach(struct ifxf_pub *drvr);

/**
 * ifxf_feat_debugfs_create() - create debugfs entries.
 *
 * @drvr: driver instance.
 */
void ifxf_feat_debugfs_create(struct ifxf_pub *drvr);

/**
 * ifxf_feat_is_enabled() - query feature.
 *
 * @ifp: interface instance.
 * @id: feature id to check.
 *
 * Return: true is feature is enabled; otherwise false.
 */
bool ifxf_feat_is_enabled(struct ifxf_if *ifp, enum ifxf_feat_id id);

/**
 * ifxf_feat_is_quirk_enabled() - query chip quirk.
 *
 * @ifp: interface instance.
 * @quirk: quirk id to check.
 *
 * Return: true is quirk is enabled; otherwise false.
 */
bool ifxf_feat_is_quirk_enabled(struct ifxf_if *ifp,
				 enum ifxf_feat_quirk quirk);

/**
 * ifxf_feat_is_6ghz_enabled() - Find if 6GHZ Operation is allowed
 *
 * @ifp: interface instance.
 *
 * Return: true if 6GHz operation is allowed; otherwise false.
 */
bool ifxf_feat_is_6ghz_enabled(struct ifxf_if *ifp);

/**
 * ifxf_feat_is_sdio_rxf_in_kthread() - handle SDIO Rx frame in kthread.
 *
 * @drvr: driver instance.
 */
bool ifxf_feat_is_sdio_rxf_in_kthread(struct ifxf_pub *drvr);

/**
 * ifxf_feat_is_offloads_enabled() - Find if offload_prof power profile
 * is given by user
 *
 * @ifp: interface instance.
 *
 * Return: true if offloads_prof is set otherwise false.
 */
bool ifxf_feat_is_offloads_enabled(struct ifxf_if *ifp);

#endif /* _IFXF_FEATURE_H */
