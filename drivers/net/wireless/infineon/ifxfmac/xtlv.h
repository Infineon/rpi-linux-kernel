// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2019 Broadcom
 */
#ifndef __IFXF_XTLV_H
#define __IFXF_XTLV_H

#include <linux/types.h>
#include <linux/bits.h>

/* ifx type(id), length, value with w/16 bit id/len. The structure below
 * is nominal, and is used to support variable length id and type. See
 * xtlv options below.
 */
struct ifxf_xtlv {
	u16 id;
	u16 len;
	u8 data[];
};

enum ifxf_xtlv_option {
	IFXF_XTLV_OPTION_ALIGN32 = BIT(0),
	IFXF_XTLV_OPTION_IDU8 = BIT(1),
	IFXF_XTLV_OPTION_LENU8 = BIT(2),
};

int ifxf_xtlv_data_size(int dlen, u16 opts);
void ifxf_xtlv_pack_header(struct ifxf_xtlv *xtlv, u16 id, u16 len,
			    const u8 *data, u16 opts);
u32 ifxf_pack_xtlv(u16 id, char *data, u32 len,
		    char **buf, u16 *buflen);

#endif /* __IFXF_XTLV_H */
