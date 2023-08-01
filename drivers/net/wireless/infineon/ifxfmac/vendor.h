// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2014 Broadcom Corporation
 */

#ifndef _vendor_h_
#define _vendor_h_

#define BROADCOM_OUI	0x001018

enum ifxf_vndr_cmds {
	IFXF_VNDR_CMDS_UNSPEC,
	IFXF_VNDR_CMDS_DCMD,
	IFXF_VNDR_CMDS_FRAMEBURST,
	IFXF_VNDR_CMDS_LAST
};

enum ifxf_vndr_evts {
	IFXF_VNDR_EVTS_PHY_TEMP,
	IFXF_VNDR_EVTS_LAST
};

/**
 * enum ifxf_nlattrs - nl80211 message attributes
 *
 * @IFXF_NLATTR_LEN: message body length
 * @IFXF_NLATTR_DATA: message body
 */
enum ifxf_nlattrs {
	IFXF_NLATTR_UNSPEC,

	IFXF_NLATTR_LEN,
	IFXF_NLATTR_DATA,
	IFXF_NLATTR_VERS,
	IFXF_NLATTR_PHY_TEMP,
	IFXF_NLATTR_PHY_TEMPDELTA,

	__IFXF_NLATTR_AFTER_LAST,
	IFXF_NLATTR_MAX = __IFXF_NLATTR_AFTER_LAST - 1
};

/* structure of event sent up by firmware: is this the right place for it? */
struct ifxf_phy_temp_evt {
	__le32 version;
	__le32 temp;
	__le32 tempdelta;
} __packed;

/**
 * struct ifxf_vndr_dcmd_hdr - message header for cfg80211 vendor command dcmd
 *				support
 *
 * @cmd: common dongle cmd definition
 * @len: length of expecting return buffer
 * @offset: offset of data buffer
 * @set: get or set request(optional)
 * @magic: magic number for verification
 */
struct ifxf_vndr_dcmd_hdr {
	uint cmd;
	int len;
	uint offset;
	uint set;
	uint magic;
};

extern const struct wiphy_vendor_command ifxf_vendor_cmds[];
extern const struct nl80211_vendor_cmd_info ifxf_vendor_events[];
s32 ifxf_wiphy_phy_temp_evt_handler(struct ifxf_if *ifp,
				     const struct ifxf_event_msg *e,
				     void *data);
int get_ifxf_num_vndr_cmds(void);

#endif /* _vendor_h_ */
