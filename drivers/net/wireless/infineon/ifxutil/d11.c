// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2013 Broadcom Corporation
 */
/*********************channel spec common functions*********************/

#include <linux/module.h>

#include <ifxu_utils.h>
#include <ifxu_wifi.h>
#include <ifxu_d11.h>

static u16 d11n_sb(enum ifxu_chan_sb sb)
{
	switch (sb) {
	case IFXU_CHAN_SB_NONE:
		return IFXU_CHSPEC_D11N_SB_N;
	case IFXU_CHAN_SB_L:
		return IFXU_CHSPEC_D11N_SB_L;
	case IFXU_CHAN_SB_U:
		return IFXU_CHSPEC_D11N_SB_U;
	default:
		WARN_ON(1);
	}
	return 0;
}

static u16 d11n_bw(enum ifxu_chan_bw bw)
{
	switch (bw) {
	case IFXU_CHAN_BW_20:
		return IFXU_CHSPEC_D11N_BW_20;
	case IFXU_CHAN_BW_40:
		return IFXU_CHSPEC_D11N_BW_40;
	default:
		WARN_ON(1);
	}
	return 0;
}

static void ifxu_d11n_encchspec(struct ifxu_chan *ch)
{
	if (ch->bw == IFXU_CHAN_BW_20)
		ch->sb = IFXU_CHAN_SB_NONE;

	ch->chspec = 0;
	ifxu_maskset16(&ch->chspec, IFXU_CHSPEC_CH_MASK,
			IFXU_CHSPEC_CH_SHIFT, ch->chnum);
	ifxu_maskset16(&ch->chspec, IFXU_CHSPEC_D11N_SB_MASK,
			0, d11n_sb(ch->sb));
	ifxu_maskset16(&ch->chspec, IFXU_CHSPEC_D11N_BW_MASK,
			0, d11n_bw(ch->bw));

	if (ch->chnum <= CH_MAX_2G_CHANNEL)
		ch->chspec |= IFXU_CHSPEC_D11N_BND_2G;
	else
		ch->chspec |= IFXU_CHSPEC_D11N_BND_5G;
}

static u16 d11ac_bw(enum ifxu_chan_bw bw)
{
	switch (bw) {
	case IFXU_CHAN_BW_20:
		return IFXU_CHSPEC_D11AC_BW_20;
	case IFXU_CHAN_BW_40:
		return IFXU_CHSPEC_D11AC_BW_40;
	case IFXU_CHAN_BW_80:
		return IFXU_CHSPEC_D11AC_BW_80;
	case IFXU_CHAN_BW_160:
		return IFXU_CHSPEC_D11AC_BW_160;
	default:
		WARN_ON(1);
	}
	return 0;
}

static void ifxu_d11ac_encchspec(struct ifxu_chan *ch)
{
	if (ch->bw == IFXU_CHAN_BW_20 || ch->sb == IFXU_CHAN_SB_NONE)
		ch->sb = IFXU_CHAN_SB_L;

	ifxu_maskset16(&ch->chspec, IFXU_CHSPEC_CH_MASK,
			IFXU_CHSPEC_CH_SHIFT, ch->chnum);
	ifxu_maskset16(&ch->chspec, IFXU_CHSPEC_D11AC_SB_MASK,
			IFXU_CHSPEC_D11AC_SB_SHIFT, ch->sb);
	ifxu_maskset16(&ch->chspec, IFXU_CHSPEC_D11AC_BW_MASK,
			0, d11ac_bw(ch->bw));

	ch->chspec &= ~IFXU_CHSPEC_D11AC_BND_MASK;
	switch (ch->band) {
	case IFXU_CHAN_BAND_6G:
		ch->chspec |= IFXU_CHSPEC_D11AC_BND_6G;
		break;
	case IFXU_CHAN_BAND_5G:
		ch->chspec |= IFXU_CHSPEC_D11AC_BND_5G;
		break;
	case IFXU_CHAN_BAND_2G:
		ch->chspec |= IFXU_CHSPEC_D11AC_BND_2G;
		break;
	default:
		WARN_ONCE(1, "Invalid band 0x%04x\n", ch->band);
		break;
	}
}

static void ifxu_d11n_decchspec(struct ifxu_chan *ch)
{
	u16 val;

	ch->chnum = (u8)(ch->chspec & IFXU_CHSPEC_CH_MASK);
	ch->control_ch_num = ch->chnum;

	switch (ch->chspec & IFXU_CHSPEC_D11N_BW_MASK) {
	case IFXU_CHSPEC_D11N_BW_20:
		ch->bw = IFXU_CHAN_BW_20;
		ch->sb = IFXU_CHAN_SB_NONE;
		break;
	case IFXU_CHSPEC_D11N_BW_40:
		ch->bw = IFXU_CHAN_BW_40;
		val = ch->chspec & IFXU_CHSPEC_D11N_SB_MASK;
		if (val == IFXU_CHSPEC_D11N_SB_L) {
			ch->sb = IFXU_CHAN_SB_L;
			ch->control_ch_num -= CH_10MHZ_APART;
		} else {
			ch->sb = IFXU_CHAN_SB_U;
			ch->control_ch_num += CH_10MHZ_APART;
		}
		break;
	default:
		WARN_ONCE(1, "Invalid chanspec 0x%04x\n", ch->chspec);
		break;
	}

	switch (ch->chspec & IFXU_CHSPEC_D11N_BND_MASK) {
	case IFXU_CHSPEC_D11N_BND_5G:
		ch->band = IFXU_CHAN_BAND_5G;
		break;
	case IFXU_CHSPEC_D11N_BND_2G:
		ch->band = IFXU_CHAN_BAND_2G;
		break;
	default:
		WARN_ONCE(1, "Invalid chanspec 0x%04x\n", ch->chspec);
		break;
	}
}

static void ifxu_d11ac_decchspec(struct ifxu_chan *ch)
{
	u16 val;

	ch->chnum = (u8)(ch->chspec & IFXU_CHSPEC_CH_MASK);
	ch->control_ch_num = ch->chnum;

	switch (ch->chspec & IFXU_CHSPEC_D11AC_BW_MASK) {
	case IFXU_CHSPEC_D11AC_BW_20:
		ch->bw = IFXU_CHAN_BW_20;
		ch->sb = IFXU_CHAN_SB_NONE;
		break;
	case IFXU_CHSPEC_D11AC_BW_40:
		ch->bw = IFXU_CHAN_BW_40;
		val = ch->chspec & IFXU_CHSPEC_D11AC_SB_MASK;
		if (val == IFXU_CHSPEC_D11AC_SB_L) {
			ch->sb = IFXU_CHAN_SB_L;
			ch->control_ch_num -= CH_10MHZ_APART;
		} else if (val == IFXU_CHSPEC_D11AC_SB_U) {
			ch->sb = IFXU_CHAN_SB_U;
			ch->control_ch_num += CH_10MHZ_APART;
		} else {
			WARN_ONCE(1, "Invalid chanspec 0x%04x\n", ch->chspec);
		}
		break;
	case IFXU_CHSPEC_D11AC_BW_80:
		ch->bw = IFXU_CHAN_BW_80;
		ch->sb = ifxu_maskget16(ch->chspec, IFXU_CHSPEC_D11AC_SB_MASK,
					 IFXU_CHSPEC_D11AC_SB_SHIFT);
		switch (ch->sb) {
		case IFXU_CHAN_SB_LL:
			ch->control_ch_num -= CH_30MHZ_APART;
			break;
		case IFXU_CHAN_SB_LU:
			ch->control_ch_num -= CH_10MHZ_APART;
			break;
		case IFXU_CHAN_SB_UL:
			ch->control_ch_num += CH_10MHZ_APART;
			break;
		case IFXU_CHAN_SB_UU:
			ch->control_ch_num += CH_30MHZ_APART;
			break;
		default:
			WARN_ONCE(1, "Invalid chanspec 0x%04x\n", ch->chspec);
			break;
		}
		break;
	case IFXU_CHSPEC_D11AC_BW_160:
		ch->bw = IFXU_CHAN_BW_160;
		ch->sb = ifxu_maskget16(ch->chspec, IFXU_CHSPEC_D11AC_SB_MASK,
					 IFXU_CHSPEC_D11AC_SB_SHIFT);
		switch (ch->sb) {
		case IFXU_CHAN_SB_LLL:
			ch->control_ch_num -= CH_70MHZ_APART;
			break;
		case IFXU_CHAN_SB_LLU:
			ch->control_ch_num -= CH_50MHZ_APART;
			break;
		case IFXU_CHAN_SB_LUL:
			ch->control_ch_num -= CH_30MHZ_APART;
			break;
		case IFXU_CHAN_SB_LUU:
			ch->control_ch_num -= CH_10MHZ_APART;
			break;
		case IFXU_CHAN_SB_ULL:
			ch->control_ch_num += CH_10MHZ_APART;
			break;
		case IFXU_CHAN_SB_ULU:
			ch->control_ch_num += CH_30MHZ_APART;
			break;
		case IFXU_CHAN_SB_UUL:
			ch->control_ch_num += CH_50MHZ_APART;
			break;
		case IFXU_CHAN_SB_UUU:
			ch->control_ch_num += CH_70MHZ_APART;
			break;
		default:
			WARN_ONCE(1, "Invalid chanspec 0x%04x\n", ch->chspec);
			break;
		}
		break;
	case IFXU_CHSPEC_D11AC_BW_8080:
	default:
		WARN_ONCE(1, "Invalid chanspec 0x%04x\n", ch->chspec);
		break;
	}

	switch (ch->chspec & IFXU_CHSPEC_D11AC_BND_MASK) {
	case IFXU_CHSPEC_D11AC_BND_6G:
		ch->band = IFXU_CHAN_BAND_6G;
		break;
	case IFXU_CHSPEC_D11AC_BND_5G:
		ch->band = IFXU_CHAN_BAND_5G;
		break;
	case IFXU_CHSPEC_D11AC_BND_2G:
		ch->band = IFXU_CHAN_BAND_2G;
		break;
	default:
		WARN_ONCE(1, "Invalid chanspec 0x%04x\n", ch->chspec);
		break;
	}
}

void ifxu_d11_attach(struct ifxu_d11inf *d11inf)
{
	if (d11inf->io_type == IFXU_D11N_IOTYPE) {
		d11inf->encchspec = ifxu_d11n_encchspec;
		d11inf->decchspec = ifxu_d11n_decchspec;
	} else {
		d11inf->encchspec = ifxu_d11ac_encchspec;
		d11inf->decchspec = ifxu_d11ac_decchspec;
	}
}
EXPORT_SYMBOL(ifxu_d11_attach);
