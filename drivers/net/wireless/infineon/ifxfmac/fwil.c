// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2012 Broadcom Corporation
 */

/* FWIL is the Firmware Interface Layer. In this module the support functions
 * are located to set and get variables to and from the firmware.
 */

#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <ifxu_utils.h>
#include <ifxu_wifi.h>
#include "core.h"
#include "bus.h"
#include "debug.h"
#include "tracepoint.h"
#include "xtlv.h"
#include "fwil.h"
#include "proto.h"


#define MAX_HEX_DUMP_LEN	64

#ifdef DEBUG
static const char * const ifxf_fil_errstr[] = {
	"IFXE_OK",
	"IFXE_ERROR",
	"IFXE_BADARG",
	"IFXE_BADOPTION",
	"IFXE_NOTUP",
	"IFXE_NOTDOWN",
	"IFXE_NOTAP",
	"IFXE_NOTSTA",
	"IFXE_BADKEYIDX",
	"IFXE_RADIOOFF",
	"IFXE_NOTBANDLOCKED",
	"IFXE_NOCLK",
	"IFXE_BADRATESET",
	"IFXE_BADBAND",
	"IFXE_BUFTOOSHORT",
	"IFXE_BUFTOOLONG",
	"IFXE_BUSY",
	"IFXE_NOTASSOCIATED",
	"IFXE_BADSSIDLEN",
	"IFXE_OUTOFRANGECHAN",
	"IFXE_BADCHAN",
	"IFXE_BADADDR",
	"IFXE_NORESOURCE",
	"IFXE_UNSUPPORTED",
	"IFXE_BADLEN",
	"IFXE_NOTREADY",
	"IFXE_EPERM",
	"IFXE_NOMEM",
	"IFXE_ASSOCIATED",
	"IFXE_RANGE",
	"IFXE_NOTFOUND",
	"IFXE_WME_NOT_ENABLED",
	"IFXE_TSPEC_NOTFOUND",
	"IFXE_ACM_NOTSUPPORTED",
	"IFXE_NOT_WME_ASSOCIATION",
	"IFXE_SDIO_ERROR",
	"IFXE_DONGLE_DOWN",
	"IFXE_VERSION",
	"IFXE_TXFAIL",
	"IFXE_RXFAIL",
	"IFXE_NODEVICE",
	"IFXE_NMODE_DISABLED",
	"IFXE_NONRESIDENT",
	"IFXE_SCANREJECT",
	"IFXE_USAGE_ERROR",
	"IFXE_IOCTL_ERROR",
	"IFXE_SERIAL_PORT_ERR",
	"IFXE_DISABLED",
	"IFXE_DECERR",
	"IFXE_ENCERR",
	"IFXE_MICERR",
	"IFXE_REPLAY",
	"IFXE_IE_NOTFOUND",
};

static const char *ifxf_fil_get_errstr(u32 err)
{
	if (err >= ARRAY_SIZE(ifxf_fil_errstr))
		return "(unknown)";

	return ifxf_fil_errstr[err];
}
#else
static const char *ifxf_fil_get_errstr(u32 err)
{
	return "";
}
#endif /* DEBUG */

static s32
ifxf_fil_cmd_data(struct ifxf_if *ifp, u32 cmd, void *data, u32 len, bool set)
{
	struct ifxf_pub *drvr = ifp->drvr;
	s32 err, fwerr;

	if (drvr->bus_if->state != IFXF_BUS_UP) {
		bphy_err(drvr, "bus is down. we have nothing to do.\n");
		return -EIO;
	}

	if (data != NULL)
		len = min_t(uint, len, IFXF_DCMD_MAXLEN);
	if (set)
		err = ifxf_proto_set_dcmd(drvr, ifp->ifidx, cmd,
					   data, len, &fwerr);
	else
		err = ifxf_proto_query_dcmd(drvr, ifp->ifidx, cmd,
					     data, len, &fwerr);

	if (err) {
		ifxf_dbg(FIL, "Failed: error=%d\n", err);
	} else if (fwerr < 0) {
		ifxf_dbg(FIL, "Firmware error: %s (%d)\n",
			  ifxf_fil_get_errstr((u32)(-fwerr)), fwerr);
		err = -EBADE;
	}
	if (ifp->fwil_fwerr)
		return fwerr;

	return err;
}

s32
ifxf_fil_cmd_data_set(struct ifxf_if *ifp, u32 cmd, void *data, u32 len)
{
	s32 err;

	mutex_lock(&ifp->drvr->proto_block);

	ifxf_dbg(FIL, "ifidx=%d, cmd=%d, len=%d\n", ifp->ifidx, cmd, len);
	ifxf_dbg_hex_dump(IFXF_FIL_ON(), data,
			   min_t(uint, len, MAX_HEX_DUMP_LEN), "data\n");

	err = ifxf_fil_cmd_data(ifp, cmd, data, len, true);
	mutex_unlock(&ifp->drvr->proto_block);

	return err;
}

s32
ifxf_fil_cmd_data_get(struct ifxf_if *ifp, u32 cmd, void *data, u32 len)
{
	s32 err;

	mutex_lock(&ifp->drvr->proto_block);
	err = ifxf_fil_cmd_data(ifp, cmd, data, len, false);

	ifxf_dbg(FIL, "ifidx=%d, cmd=%d, len=%d, err=%d\n", ifp->ifidx, cmd,
		  len, err);
	ifxf_dbg_hex_dump(IFXF_FIL_ON(), data,
			   min_t(uint, len, MAX_HEX_DUMP_LEN), "data\n");

	mutex_unlock(&ifp->drvr->proto_block);

	return err;
}


s32
ifxf_fil_cmd_int_set(struct ifxf_if *ifp, u32 cmd, u32 data)
{
	s32 err;
	__le32 data_le = cpu_to_le32(data);

	mutex_lock(&ifp->drvr->proto_block);
	ifxf_dbg(FIL, "ifidx=%d, cmd=%d, value=%d\n", ifp->ifidx, cmd, data);
	err = ifxf_fil_cmd_data(ifp, cmd, &data_le, sizeof(data_le), true);
	mutex_unlock(&ifp->drvr->proto_block);

	return err;
}

s32
ifxf_fil_cmd_int_get(struct ifxf_if *ifp, u32 cmd, u32 *data)
{
	s32 err;
	__le32 data_le = cpu_to_le32(*data);

	mutex_lock(&ifp->drvr->proto_block);
	err = ifxf_fil_cmd_data(ifp, cmd, &data_le, sizeof(data_le), false);
	mutex_unlock(&ifp->drvr->proto_block);
	*data = le32_to_cpu(data_le);
	ifxf_dbg(FIL, "ifidx=%d, cmd=%d, value=%d\n", ifp->ifidx, cmd, *data);

	return err;
}

static u32
ifxf_create_iovar(const char *name, const char *data, u32 datalen,
		   char *buf, u32 buflen)
{
	u32 len;

	len = strlen(name) + 1;

	if ((len + datalen) > buflen)
		return 0;

	memcpy(buf, name, len);

	/* append data onto the end of the name string */
	if (data && datalen)
		memcpy(&buf[len], data, datalen);

	return len + datalen;
}


s32
ifxf_fil_iovar_data_set(struct ifxf_if *ifp, const char *name, const void *data,
			 u32 len)
{
	struct ifxf_pub *drvr = ifp->drvr;
	s32 err;
	u32 buflen;

	mutex_lock(&drvr->proto_block);

	ifxf_dbg(FIL, "ifidx=%d, name=%s, len=%d\n", ifp->ifidx, name, len);
	ifxf_dbg_hex_dump(IFXF_FIL_ON(), data,
			   min_t(uint, len, MAX_HEX_DUMP_LEN), "data\n");

	buflen = ifxf_create_iovar(name, data, len, drvr->proto_buf,
				    sizeof(drvr->proto_buf));
	if (buflen) {
		err = ifxf_fil_cmd_data(ifp, IFXF_C_SET_VAR, drvr->proto_buf,
					 buflen, true);
	} else {
		err = -EPERM;
		bphy_err(drvr, "Creating iovar failed\n");
	}

	mutex_unlock(&drvr->proto_block);
	return err;
}

s32
ifxf_fil_iovar_data_get(struct ifxf_if *ifp, const char *name, void *data,
			 u32 len)
{
	struct ifxf_pub *drvr = ifp->drvr;
	s32 err;
	u32 buflen;

	mutex_lock(&drvr->proto_block);

	buflen = ifxf_create_iovar(name, data, len, drvr->proto_buf,
				    sizeof(drvr->proto_buf));
	if (buflen) {
		err = ifxf_fil_cmd_data(ifp, IFXF_C_GET_VAR, drvr->proto_buf,
					 buflen, false);
		if (err == 0)
			memcpy(data, drvr->proto_buf, len);
	} else {
		err = -EPERM;
		bphy_err(drvr, "Creating iovar failed\n");
	}

	ifxf_dbg(FIL, "ifidx=%d, name=%s, len=%d, err=%d\n", ifp->ifidx, name,
		  len, err);
	ifxf_dbg_hex_dump(IFXF_FIL_ON(), data,
			   min_t(uint, len, MAX_HEX_DUMP_LEN), "data\n");

	mutex_unlock(&drvr->proto_block);
	return err;
}

s32
ifxf_fil_iovar_int_set(struct ifxf_if *ifp, const char *name, u32 data)
{
	__le32 data_le = cpu_to_le32(data);

	return ifxf_fil_iovar_data_set(ifp, name, &data_le, sizeof(data_le));
}

s32
ifxf_fil_iovar_int_get(struct ifxf_if *ifp, const char *name, u32 *data)
{
	__le32 data_le = cpu_to_le32(*data);
	s32 err;

	err = ifxf_fil_iovar_data_get(ifp, name, &data_le, sizeof(data_le));
	if (err == 0)
		*data = le32_to_cpu(data_le);
	return err;
}

static u32
ifxf_create_bsscfg(s32 bsscfgidx, const char *name, char *data, u32 datalen,
		    char *buf, u32 buflen)
{
	const s8 *prefix = "bsscfg:";
	s8 *p;
	u32 prefixlen;
	u32 namelen;
	u32 iolen;
	__le32 bsscfgidx_le;

	if (bsscfgidx == 0)
		return ifxf_create_iovar(name, data, datalen, buf, buflen);

	prefixlen = strlen(prefix);
	namelen = strlen(name) + 1; /* length of iovar  name + null */
	iolen = prefixlen + namelen + sizeof(bsscfgidx_le) + datalen;

	if (buflen < iolen) {
		ifxf_err("buffer is too short\n");
		return 0;
	}

	p = buf;

	/* copy prefix, no null */
	memcpy(p, prefix, prefixlen);
	p += prefixlen;

	/* copy iovar name including null */
	memcpy(p, name, namelen);
	p += namelen;

	/* bss config index as first data */
	bsscfgidx_le = cpu_to_le32(bsscfgidx);
	memcpy(p, &bsscfgidx_le, sizeof(bsscfgidx_le));
	p += sizeof(bsscfgidx_le);

	/* parameter buffer follows */
	if (datalen)
		memcpy(p, data, datalen);

	return iolen;
}

s32
ifxf_fil_bsscfg_data_set(struct ifxf_if *ifp, const char *name,
			  void *data, u32 len)
{
	struct ifxf_pub *drvr = ifp->drvr;
	s32 err;
	u32 buflen;

	mutex_lock(&drvr->proto_block);

	ifxf_dbg(FIL, "ifidx=%d, bsscfgidx=%d, name=%s, len=%d\n", ifp->ifidx,
		  ifp->bsscfgidx, name, len);
	ifxf_dbg_hex_dump(IFXF_FIL_ON(), data,
			   min_t(uint, len, MAX_HEX_DUMP_LEN), "data\n");

	buflen = ifxf_create_bsscfg(ifp->bsscfgidx, name, data, len,
				     drvr->proto_buf, sizeof(drvr->proto_buf));
	if (buflen) {
		err = ifxf_fil_cmd_data(ifp, IFXF_C_SET_VAR, drvr->proto_buf,
					 buflen, true);
	} else {
		err = -EPERM;
		bphy_err(drvr, "Creating bsscfg failed\n");
	}

	mutex_unlock(&drvr->proto_block);
	return err;
}

s32
ifxf_fil_bsscfg_data_get(struct ifxf_if *ifp, const char *name,
			  void *data, u32 len)
{
	struct ifxf_pub *drvr = ifp->drvr;
	s32 err;
	u32 buflen;

	mutex_lock(&drvr->proto_block);

	buflen = ifxf_create_bsscfg(ifp->bsscfgidx, name, data, len,
				     drvr->proto_buf, sizeof(drvr->proto_buf));
	if (buflen) {
		err = ifxf_fil_cmd_data(ifp, IFXF_C_GET_VAR, drvr->proto_buf,
					 buflen, false);
		if (err == 0)
			memcpy(data, drvr->proto_buf, len);
	} else {
		err = -EPERM;
		bphy_err(drvr, "Creating bsscfg failed\n");
	}
	ifxf_dbg(FIL, "ifidx=%d, bsscfgidx=%d, name=%s, len=%d, err=%d\n",
		  ifp->ifidx, ifp->bsscfgidx, name, len, err);
	ifxf_dbg_hex_dump(IFXF_FIL_ON(), data,
			   min_t(uint, len, MAX_HEX_DUMP_LEN), "data\n");

	mutex_unlock(&drvr->proto_block);
	return err;
}

s32
ifxf_fil_bsscfg_int_set(struct ifxf_if *ifp, const char *name, u32 data)
{
	__le32 data_le = cpu_to_le32(data);

	return ifxf_fil_bsscfg_data_set(ifp, name, &data_le,
					 sizeof(data_le));
}

s32
ifxf_fil_bsscfg_int_get(struct ifxf_if *ifp, const char *name, u32 *data)
{
	__le32 data_le = cpu_to_le32(*data);
	s32 err;

	err = ifxf_fil_bsscfg_data_get(ifp, name, &data_le,
					sizeof(data_le));
	if (err == 0)
		*data = le32_to_cpu(data_le);
	return err;
}

static u32 ifxf_create_xtlv(const char *name, u16 id, char *data, u32 len,
			     char *buf, u32 buflen)
{
	u32 iolen;
	u32 nmlen;

	nmlen = strlen(name) + 1;
	iolen = nmlen + ifxf_xtlv_data_size(len, IFXF_XTLV_OPTION_ALIGN32);

	if (iolen > buflen) {
		ifxf_err("buffer is too short\n");
		return 0;
	}

	memcpy(buf, name, nmlen);
	ifxf_xtlv_pack_header((void *)(buf + nmlen), id, len, data,
			       IFXF_XTLV_OPTION_ALIGN32);

	return iolen;
}

s32 ifxf_fil_xtlv_data_set(struct ifxf_if *ifp, const char *name, u16 id,
			    void *data, u32 len)
{
	struct ifxf_pub *drvr = ifp->drvr;
	s32 err;
	u32 buflen;

	mutex_lock(&drvr->proto_block);

	ifxf_dbg(FIL, "ifidx=%d, name=%s, id=%u, len=%u\n", ifp->ifidx, name,
		  id, len);
	ifxf_dbg_hex_dump(IFXF_FIL_ON(), data,
			   min_t(uint, len, MAX_HEX_DUMP_LEN), "data\n");

	buflen = ifxf_create_xtlv(name, id, data, len,
				   drvr->proto_buf, sizeof(drvr->proto_buf));
	if (buflen) {
		err = ifxf_fil_cmd_data(ifp, IFXF_C_SET_VAR, drvr->proto_buf,
					 buflen, true);
	} else {
		err = -EPERM;
		bphy_err(drvr, "Creating xtlv failed\n");
	}

	mutex_unlock(&drvr->proto_block);
	return err;
}

s32 ifxf_fil_xtlv_data_get(struct ifxf_if *ifp, const char *name, u16 id,
			    void *data, u32 len)
{
	struct ifxf_pub *drvr = ifp->drvr;
	s32 err;
	u32 buflen;

	mutex_lock(&drvr->proto_block);

	buflen = ifxf_create_xtlv(name, id, data, len,
				   drvr->proto_buf, sizeof(drvr->proto_buf));
	if (buflen) {
		err = ifxf_fil_cmd_data(ifp, IFXF_C_GET_VAR, drvr->proto_buf,
					 buflen, false);
		if (err == 0)
			memcpy(data, drvr->proto_buf, len);
	} else {
		err = -EPERM;
		bphy_err(drvr, "Creating bsscfg failed\n");
	}
	ifxf_dbg(FIL, "ifidx=%d, name=%s, id=%u, len=%u, err=%d\n",
		  ifp->ifidx, name, id, len, err);
	ifxf_dbg_hex_dump(IFXF_FIL_ON(), data,
			   min_t(uint, len, MAX_HEX_DUMP_LEN), "data\n");

	mutex_unlock(&drvr->proto_block);
	return err;
}

s32 ifxf_fil_xtlv_int_set(struct ifxf_if *ifp, const char *name, u16 id, u32 data)
{
	__le32 data_le = cpu_to_le32(data);

	return ifxf_fil_xtlv_data_set(ifp, name, id, &data_le,
					 sizeof(data_le));
}

s32 ifxf_fil_xtlv_int_get(struct ifxf_if *ifp, const char *name, u16 id, u32 *data)
{
	__le32 data_le = cpu_to_le32(*data);
	s32 err;

	err = ifxf_fil_xtlv_data_get(ifp, name, id, &data_le, sizeof(data_le));
	if (err == 0)
		*data = le32_to_cpu(data_le);
	return err;
}

s32 ifxf_fil_xtlv_int8_get(struct ifxf_if *ifp, const char *name, u16 id, u8 *data)
{
	return ifxf_fil_xtlv_data_get(ifp, name, id, data, sizeof(*data));
}

s32 ifxf_fil_xtlv_int16_get(struct ifxf_if *ifp, const char *name, u16 id, u16 *data)
{
	__le16 data_le = cpu_to_le16(*data);
	s32 err;

	err = ifxf_fil_xtlv_data_get(ifp, name, id, &data_le, sizeof(data_le));
	if (err == 0)
		*data = le16_to_cpu(data_le);
	return err;
}

