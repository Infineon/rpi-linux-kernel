// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2019 Broadcom
 */

#include <asm/unaligned.h>

#include <linux/math.h>
#include <linux/string.h>
#include <linux/bug.h>

#include "xtlv.h"

static int ifxf_xtlv_header_size(u16 opts)
{
	int len = (int)offsetof(struct ifxf_xtlv, data);

	if (opts & IFXF_XTLV_OPTION_IDU8)
		--len;
	if (opts & IFXF_XTLV_OPTION_LENU8)
		--len;

	return len;
}

int ifxf_xtlv_data_size(int dlen, u16 opts)
{
	int hsz;

	hsz = ifxf_xtlv_header_size(opts);
	if (opts & IFXF_XTLV_OPTION_ALIGN32)
		return roundup(dlen + hsz, 4);

	return dlen + hsz;
}

void ifxf_xtlv_pack_header(struct ifxf_xtlv *xtlv, u16 id, u16 len,
			    const u8 *data, u16 opts)
{
	u8 *data_buf;
	u16 mask = IFXF_XTLV_OPTION_IDU8 | IFXF_XTLV_OPTION_LENU8;

	if (!(opts & mask)) {
		u8 *idp = (u8 *)xtlv;
		u8 *lenp = idp + sizeof(xtlv->id);

		put_unaligned_le16(id, idp);
		put_unaligned_le16(len, lenp);
		data_buf = lenp + sizeof(u16);
	} else if ((opts & mask) == mask) { /* u8 id and u8 len */
		u8 *idp = (u8 *)xtlv;
		u8 *lenp = idp + 1;

		*idp = (u8)id;
		*lenp = (u8)len;
		data_buf = lenp + sizeof(u8);
	} else if (opts & IFXF_XTLV_OPTION_IDU8) { /* u8 id, u16 len */
		u8 *idp = (u8 *)xtlv;
		u8 *lenp = idp + 1;

		*idp = (u8)id;
		put_unaligned_le16(len, lenp);
		data_buf = lenp + sizeof(u16);
	} else if (opts & IFXF_XTLV_OPTION_LENU8) { /* u16 id, u8 len */
		u8 *idp = (u8 *)xtlv;
		u8 *lenp = idp + sizeof(u16);

		put_unaligned_le16(id, idp);
		*lenp = (u8)len;
		data_buf = lenp + sizeof(u8);
	} else {
		WARN(true, "Unexpected xtlv option");
		return;
	}

	if (opts & IFXF_XTLV_OPTION_LENU8) {
		WARN_ON(len > 0x00ff);
		len &= 0xff;
	}

	if (data)
		memcpy(data_buf, data, len);
}

u32 ifxf_pack_xtlv(u16 id, char *data, u32 len,
		    char **buf, u16 *buflen)
{
	u32 iolen;

	iolen = ifxf_xtlv_data_size(len, IFXF_XTLV_OPTION_ALIGN32);

	if (iolen > *buflen) {
		WARN(true, "xtlv buffer is too short");
		return 0;
	}

	ifxf_xtlv_pack_header((void *)*buf, id, len, data,
			       IFXF_XTLV_OPTION_ALIGN32);

	*buf = *buf + iolen;
	*buflen -= iolen;
	return iolen;
}
