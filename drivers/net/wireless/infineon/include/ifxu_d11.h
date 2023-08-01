// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2010 Broadcom Corporation
 */

#ifndef	_IFXU_D11_H_
#define	_IFXU_D11_H_

/* d11 io type */
#define IFXU_D11N_IOTYPE		1
#define IFXU_D11AC_IOTYPE		2

/* A chanspec (channel specification) holds the channel number, band,
 * bandwidth and control sideband
 */

/* chanspec binary format */

#define IFXU_CHSPEC_INVALID		255
/* bit 0~7 channel number
 * for 80+80 channels: bit 0~3 low channel id, bit 4~7 high channel id
 */
#define IFXU_CHSPEC_CH_MASK		0x00ff
#define IFXU_CHSPEC_CH_SHIFT		0
#define IFXU_CHSPEC_CHL_MASK		0x000f
#define IFXU_CHSPEC_CHL_SHIFT		0
#define IFXU_CHSPEC_CHH_MASK		0x00f0
#define IFXU_CHSPEC_CHH_SHIFT		4

/* bit 8~16 for dot 11n IO types
 * bit 8~9 sideband
 * bit 10~11 bandwidth
 * bit 12~13 spectral band
 * bit 14~15 not used
 */
#define IFXU_CHSPEC_D11N_SB_MASK	0x0300
#define IFXU_CHSPEC_D11N_SB_SHIFT	8
#define  IFXU_CHSPEC_D11N_SB_L		0x0100	/* control lower */
#define  IFXU_CHSPEC_D11N_SB_U		0x0200	/* control upper */
#define  IFXU_CHSPEC_D11N_SB_N		0x0300	/* none */
#define IFXU_CHSPEC_D11N_BW_MASK	0x0c00
#define IFXU_CHSPEC_D11N_BW_SHIFT	10
#define  IFXU_CHSPEC_D11N_BW_10	0x0400
#define  IFXU_CHSPEC_D11N_BW_20	0x0800
#define  IFXU_CHSPEC_D11N_BW_40	0x0c00
#define IFXU_CHSPEC_D11N_BND_MASK	0x3000
#define IFXU_CHSPEC_D11N_BND_SHIFT	12
#define  IFXU_CHSPEC_D11N_BND_5G	0x1000
#define  IFXU_CHSPEC_D11N_BND_2G	0x2000

/* bit 8~16 for dot 11ac IO types
 * bit 8~10 sideband
 * bit 11~13 bandwidth
 * bit 14~15 spectral band
 */
#define IFXU_CHSPEC_D11AC_SB_MASK	0x0700
#define IFXU_CHSPEC_D11AC_SB_SHIFT	8
#define  IFXU_CHSPEC_D11AC_SB_LLL	0x0000
#define  IFXU_CHSPEC_D11AC_SB_LLU	0x0100
#define  IFXU_CHSPEC_D11AC_SB_LUL	0x0200
#define  IFXU_CHSPEC_D11AC_SB_LUU	0x0300
#define  IFXU_CHSPEC_D11AC_SB_ULL	0x0400
#define  IFXU_CHSPEC_D11AC_SB_ULU	0x0500
#define  IFXU_CHSPEC_D11AC_SB_UUL	0x0600
#define  IFXU_CHSPEC_D11AC_SB_UUU	0x0700
#define  IFXU_CHSPEC_D11AC_SB_LL	IFXU_CHSPEC_D11AC_SB_LLL
#define  IFXU_CHSPEC_D11AC_SB_LU	IFXU_CHSPEC_D11AC_SB_LLU
#define  IFXU_CHSPEC_D11AC_SB_UL	IFXU_CHSPEC_D11AC_SB_LUL
#define  IFXU_CHSPEC_D11AC_SB_UU	IFXU_CHSPEC_D11AC_SB_LUU
#define  IFXU_CHSPEC_D11AC_SB_L	IFXU_CHSPEC_D11AC_SB_LLL
#define  IFXU_CHSPEC_D11AC_SB_U	IFXU_CHSPEC_D11AC_SB_LLU
#define IFXU_CHSPEC_D11AC_BW_MASK	0x3800
#define IFXU_CHSPEC_D11AC_BW_SHIFT	11
#define  IFXU_CHSPEC_D11AC_BW_5	0x0000
#define  IFXU_CHSPEC_D11AC_BW_10	0x0800
#define  IFXU_CHSPEC_D11AC_BW_20	0x1000
#define  IFXU_CHSPEC_D11AC_BW_40	0x1800
#define  IFXU_CHSPEC_D11AC_BW_80	0x2000
#define  IFXU_CHSPEC_D11AC_BW_160	0x2800
#define  IFXU_CHSPEC_D11AC_BW_8080	0x3000
#define IFXU_CHSPEC_D11AC_BND_MASK	0xc000
#define IFXU_CHSPEC_D11AC_BND_SHIFT	14
#define  IFXU_CHSPEC_D11AC_BND_2G	0x0000
#define  IFXU_CHSPEC_D11AC_BND_3G	0x4000
#define  IFXU_CHSPEC_D11AC_BND_6G	0x8000
#define  IFXU_CHSPEC_D11AC_BND_5G	0xc000
#define IFXU_CHSPEC_IS5G(chspec) \
	(((chspec) & IFXU_CHSPEC_D11AC_BND_MASK) == IFXU_CHSPEC_D11AC_BND_5G)
#define IFXU_CHSPEC_IS6G(chspec) \
	(((chspec) & IFXU_CHSPEC_D11AC_BND_MASK) == IFXU_CHSPEC_D11AC_BND_6G)
#define IFXU_CHAN_BAND_2G		1
#define IFXU_CHAN_BAND_5G		2
#define IFXU_CHAN_BAND_6G		3
#define IFXU_CHAN_BAND_TO_NL80211(band) \
	((band) == IFXU_CHAN_BAND_2G ? NL80211_BAND_2GHZ : \
	((band) == IFXU_CHAN_BAND_5G ? NL80211_BAND_5GHZ : NL80211_BAND_6GHZ))

enum ifxu_chan_bw {
	IFXU_CHAN_BW_20,
	IFXU_CHAN_BW_40,
	IFXU_CHAN_BW_80,
	IFXU_CHAN_BW_80P80,
	IFXU_CHAN_BW_160,
};

enum ifxu_chan_sb {
	IFXU_CHAN_SB_NONE = -1,
	IFXU_CHAN_SB_LLL,
	IFXU_CHAN_SB_LLU,
	IFXU_CHAN_SB_LUL,
	IFXU_CHAN_SB_LUU,
	IFXU_CHAN_SB_ULL,
	IFXU_CHAN_SB_ULU,
	IFXU_CHAN_SB_UUL,
	IFXU_CHAN_SB_UUU,
	IFXU_CHAN_SB_L = IFXU_CHAN_SB_LLL,
	IFXU_CHAN_SB_U = IFXU_CHAN_SB_LLU,
	IFXU_CHAN_SB_LL = IFXU_CHAN_SB_LLL,
	IFXU_CHAN_SB_LU = IFXU_CHAN_SB_LLU,
	IFXU_CHAN_SB_UL = IFXU_CHAN_SB_LUL,
	IFXU_CHAN_SB_UU = IFXU_CHAN_SB_LUU,
};

/**
 * struct ifxu_chan - stores channel formats
 *
 * This structure can be used with functions translating chanspec into generic
 * channel info and the other way.
 *
 * @chspec: firmware specific format
 * @chnum: center channel number
 * @control_ch_num: control channel number
 * @band: frequency band
 * @bw: channel width
 * @sb: control sideband (location of control channel against the center one)
 */
struct ifxu_chan {
	u16 chspec;
	u8 chnum;
	u8 control_ch_num;
	u8 band;
	enum ifxu_chan_bw bw;
	enum ifxu_chan_sb sb;
};

/**
 * struct ifxu_d11inf - provides functions translating channel format
 *
 * @io_type: determines version of channel format used by firmware
 * @encchspec: encodes channel info into a chanspec, requires center channel
 *	number, ignores control one
 * @decchspec: decodes chanspec into generic info
 */
struct ifxu_d11inf {
	u8 io_type;

	void (*encchspec)(struct ifxu_chan *ch);
	void (*decchspec)(struct ifxu_chan *ch);
};

void ifxu_d11_attach(struct ifxu_d11inf *d11inf);

#endif	/* _IFXU_CHANNELS_H_ */
