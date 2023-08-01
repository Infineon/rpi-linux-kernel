// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2012 Broadcom Corporation
 */

#ifndef _fwil_h_
#define _fwil_h_

/*******************************************************************************
 * Dongle command codes that are interpreted by firmware
 ******************************************************************************/
#define IFXF_C_GET_VERSION			1
#define IFXF_C_UP				2
#define IFXF_C_DOWN				3
#define IFXF_C_SET_PROMISC			10
#define IFXF_C_GET_RATE			12
#define IFXF_C_GET_INFRA			19
#define IFXF_C_SET_INFRA			20
#define IFXF_C_GET_AUTH			21
#define IFXF_C_SET_AUTH			22
#define IFXF_C_GET_BSSID			23
#define IFXF_C_GET_SSID			25
#define IFXF_C_SET_SSID			26
#define IFXF_C_TERMINATED			28
#define IFXF_C_GET_CHANNEL			29
#define IFXF_C_SET_CHANNEL			30
#define IFXF_C_GET_SRL				31
#define IFXF_C_SET_SRL				32
#define IFXF_C_GET_LRL				33
#define IFXF_C_SET_LRL				34
#define IFXF_C_GET_RADIO			37
#define IFXF_C_SET_RADIO			38
#define IFXF_C_GET_PHYTYPE			39
#define IFXF_C_SET_KEY				45
#define IFXF_C_GET_REGULATORY			46
#define IFXF_C_SET_REGULATORY			47
#define IFXF_C_SET_PASSIVE_SCAN		49
#define IFXF_C_SCAN				50
#define IFXF_C_SCAN_RESULTS			51
#define IFXF_C_DISASSOC			52
#define IFXF_C_REASSOC				53
#define IFXF_C_SET_ROAM_TRIGGER		55
#define IFXF_C_SET_ROAM_DELTA			57
#define IFXF_C_GET_BCNPRD			75
#define IFXF_C_SET_BCNPRD			76
#define IFXF_C_GET_DTIMPRD			77
#define IFXF_C_SET_DTIMPRD			78
#define IFXF_C_SET_COUNTRY			84
#define IFXF_C_GET_PM				85
#define IFXF_C_SET_PM				86
#define IFXF_C_GET_REVINFO			98
#define IFXF_C_GET_MONITOR			107
#define IFXF_C_SET_MONITOR			108
#define IFXF_C_GET_CURR_RATESET		114
#define IFXF_C_GET_AP				117
#define IFXF_C_SET_AP				118
#define IFXF_C_SET_SCB_AUTHORIZE		121
#define IFXF_C_SET_SCB_DEAUTHORIZE		122
#define IFXF_C_GET_RSSI			127
#define IFXF_C_GET_WSEC			133
#define IFXF_C_SET_WSEC			134
#define IFXF_C_GET_PHY_NOISE			135
#define IFXF_C_GET_BSS_INFO			136
#define IFXF_C_GET_GET_PKTCNTS			137
#define IFXF_C_GET_BANDLIST			140
#define IFXF_C_SET_SCB_TIMEOUT			158
#define IFXF_C_GET_ASSOCLIST			159
#define IFXF_C_GET_PHYLIST			180
#define IFXF_C_SET_SCAN_CHANNEL_TIME		185
#define IFXF_C_SET_SCAN_UNASSOC_TIME		187
#define IFXF_C_SCB_DEAUTHENTICATE_FOR_REASON	201
#define IFXF_C_SET_ASSOC_PREFER		205
#define IFXF_C_GET_VALID_CHANNELS		217
#define IFXF_C_GET_FAKEFRAG                    218
#define IFXF_C_SET_FAKEFRAG			219
#define IFXF_C_GET_KEY_PRIMARY			235
#define IFXF_C_SET_KEY_PRIMARY			236
#define IFXF_C_SET_SCAN_PASSIVE_TIME		258
#define IFXF_C_GET_VAR				262
#define IFXF_C_SET_VAR				263
#define IFXF_C_SET_WSEC_PMK			268

#define IFXF_FW_BADARG				2
#define IFXF_FW_UNSUPPORTED			23

s32 ifxf_fil_cmd_data_set(struct ifxf_if *ifp, u32 cmd, void *data, u32 len);
s32 ifxf_fil_cmd_data_get(struct ifxf_if *ifp, u32 cmd, void *data, u32 len);
s32 ifxf_fil_cmd_int_set(struct ifxf_if *ifp, u32 cmd, u32 data);
s32 ifxf_fil_cmd_int_get(struct ifxf_if *ifp, u32 cmd, u32 *data);

s32 ifxf_fil_iovar_data_set(struct ifxf_if *ifp, const char *name, const void *data,
			     u32 len);
s32 ifxf_fil_iovar_data_get(struct ifxf_if *ifp, const char *name, void *data,
			     u32 len);
s32 ifxf_fil_iovar_int_set(struct ifxf_if *ifp, const char *name, u32 data);
s32 ifxf_fil_iovar_int_get(struct ifxf_if *ifp, const char *name, u32 *data);

s32 ifxf_fil_bsscfg_data_set(struct ifxf_if *ifp, const char *name, void *data,
			      u32 len);
s32 ifxf_fil_bsscfg_data_get(struct ifxf_if *ifp, const char *name, void *data,
			      u32 len);
s32 ifxf_fil_bsscfg_int_set(struct ifxf_if *ifp, const char *name, u32 data);
s32 ifxf_fil_bsscfg_int_get(struct ifxf_if *ifp, const char *name, u32 *data);
s32 ifxf_fil_xtlv_data_set(struct ifxf_if *ifp, const char *name, u16 id,
			    void *data, u32 len);
s32 ifxf_fil_xtlv_data_get(struct ifxf_if *ifp, const char *name, u16 id,
			    void *data, u32 len);
s32 ifxf_fil_xtlv_int_set(struct ifxf_if *ifp, const char *name, u16 id, u32 data);
s32 ifxf_fil_xtlv_int_get(struct ifxf_if *ifp, const char *name, u16 id, u32 *data);
s32 ifxf_fil_xtlv_int8_get(struct ifxf_if *ifp, const char *name, u16 id, u8 *data);
s32 ifxf_fil_xtlv_int16_get(struct ifxf_if *ifp, const char *name, u16 id, u16 *data);

#endif /* _fwil_h_ */
