// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2014 Broadcom Corporation
 */

#include <linux/netdevice.h>
#include <linux/module.h>

#include <ifx_hw_ids.h>
#include <ifxu_wifi.h>
#include "core.h"
#include "bus.h"
#include "debug.h"
#include "fwil.h"
#include "fwil_types.h"
#include "feature.h"
#include "common.h"
#include "xtlv.h"
#include "twt.h"


/*
 * expand feature list to array of feature strings.
 */
#define IFXF_FEAT_DEF(_f) \
	#_f,
static const char *ifxf_feat_names[] = {
	IFXF_FEAT_LIST
};
#undef IFXF_FEAT_DEF

struct ifxf_feat_fwcap {
	enum ifxf_feat_id feature;
	const char * const fwcap_id;
};

static const struct ifxf_feat_fwcap ifxf_fwcap_map[] = {
	{ IFXF_FEAT_MBSS, "mbss" },
	{ IFXF_FEAT_MCHAN, "mchan" },
	{ IFXF_FEAT_P2P, "p2p" },
	{ IFXF_FEAT_MONITOR, "monitor" },
	{ IFXF_FEAT_MONITOR_FLAG, "rtap" },
	{ IFXF_FEAT_MONITOR_FMT_RADIOTAP, "rtap" },
	{ IFXF_FEAT_DOT11H, "802.11h" },
	{ IFXF_FEAT_SAE, "sae " },
	{ IFXF_FEAT_FWAUTH, "idauth" },
	{ IFXF_FEAT_SAE_EXT, "sae_ext " },
	{ IFXF_FEAT_FBT, "fbt " },
	{ IFXF_FEAT_OKC, "okc" },
	{ IFXF_FEAT_GCMP, "gcmp" },
	{ IFXF_FEAT_OFFLOADS, "offloads" },
	{ IFXF_FEAT_ULP, "ulp" },
};

#ifdef DEBUG
/*
 * expand quirk list to array of quirk strings.
 */
#define IFXF_QUIRK_DEF(_q) \
	#_q,
static const char * const ifxf_quirk_names[] = {
	IFXF_QUIRK_LIST
};
#undef IFXF_QUIRK_DEF

/**
 * ifxf_feat_debugfs_read() - expose feature info to debugfs.
 *
 * @seq: sequence for debugfs entry.
 * @data: raw data pointer.
 */
static int ifxf_feat_debugfs_read(struct seq_file *seq, void *data)
{
	struct ifxf_bus *bus_if = dev_get_drvdata(seq->private);
	u32 feats = bus_if->drvr->feat_flags;
	u32 quirks = bus_if->drvr->chip_quirks;
	int id;

	seq_printf(seq, "Features: %08x\n", feats);
	for (id = 0; id < IFXF_FEAT_LAST; id++)
		if (feats & BIT(id))
			seq_printf(seq, "\t%s\n", ifxf_feat_names[id]);
	seq_printf(seq, "\nQuirks:   %08x\n", quirks);
	for (id = 0; id < IFXF_FEAT_QUIRK_LAST; id++)
		if (quirks & BIT(id))
			seq_printf(seq, "\t%s\n", ifxf_quirk_names[id]);
	return 0;
}
#else
static int ifxf_feat_debugfs_read(struct seq_file *seq, void *data)
{
	return 0;
}
#endif /* DEBUG */

struct ifxf_feat_fwfeat {
	const char * const fwid;
	u32 feat_flags;
};

static const struct ifxf_feat_fwfeat ifxf_feat_fwfeat_map[] = {
	/*
	 * cyfmacxxxx-pcie.bin from linux-firmware.git commit yyyyyyyyyyyy
	 * { "01-zzzzzzzz". BIT(IFXF_FEAT_*) },
	 */
};

static void ifxf_feat_firmware_overrides(struct ifxf_pub *drv)
{
	const struct ifxf_feat_fwfeat *e;
	u32 feat_flags = 0;
	int i;

	for (i = 0; i < ARRAY_SIZE(ifxf_feat_fwfeat_map); i++) {
		e = &ifxf_feat_fwfeat_map[i];
		if (!strcmp(e->fwid, drv->fwver)) {
			feat_flags = e->feat_flags;
			break;
		}
	}

	if (!feat_flags)
		return;

	for (i = 0; i < IFXF_FEAT_LAST; i++)
		if (feat_flags & BIT(i))
			ifxf_dbg(INFO, "enabling firmware feature: %s\n",
				  ifxf_feat_names[i]);
	drv->feat_flags |= feat_flags;
}

/**
 * ifxf_feat_iovar_int_get() - determine feature through iovar query.
 *
 * @ifp: interface to query.
 * @id: feature id.
 * @name: iovar name.
 */
static void ifxf_feat_iovar_int_get(struct ifxf_if *ifp,
				     enum ifxf_feat_id id, char *name)
{
	u32 data;
	int err;

	/* we need to know firmware error */
	ifp->fwil_fwerr = true;

	err = ifxf_fil_iovar_int_get(ifp, name, &data);
	if (err != -IFXF_FW_UNSUPPORTED) {
		ifxf_dbg(INFO, "enabling feature: %s\n", ifxf_feat_names[id]);
		ifp->drvr->feat_flags |= BIT(id);
	} else {
		ifxf_dbg(TRACE, "%s feature check failed: %d\n",
			  ifxf_feat_names[id], err);
	}

	ifp->fwil_fwerr = false;
}

static void ifxf_feat_iovar_data_set(struct ifxf_if *ifp,
				      enum ifxf_feat_id id, char *name,
				      const void *data, size_t len)
{
	int err;

	/* we need to know firmware error */
	ifp->fwil_fwerr = true;

	err = ifxf_fil_iovar_data_set(ifp, name, data, len);
	if (err != -IFXF_FW_UNSUPPORTED) {
		ifxf_dbg(INFO, "enabling feature: %s\n", ifxf_feat_names[id]);
		ifp->drvr->feat_flags |= BIT(id);
	} else {
		ifxf_dbg(TRACE, "%s feature check failed: %d\n",
			  ifxf_feat_names[id], err);
	}

	ifp->fwil_fwerr = false;
}

static void ifxf_feat_iovar_enab_get(struct ifxf_if *ifp,
					enum ifxf_feat_id id, char *name,
					u16 subcmd_id)
{
	int err;
	u8 val;

	/* we need to know firmware error */
	ifp->fwil_fwerr = true;

	err = ifxf_fil_xtlv_data_get(ifp, name, subcmd_id,
				      (void *)&val, sizeof(val));

	if (!err) {
		ifxf_dbg(INFO, "enabling feature: %s\n", ifxf_feat_names[id]);
		ifp->drvr->feat_flags |= BIT(id);
	} else {
		ifxf_dbg(TRACE, "%s feature check failed: %d\n",
			  ifxf_feat_names[id], err);
	}

	ifp->fwil_fwerr = false;
}

#define MAX_CAPS_BUFFER_SIZE	768
static void ifxf_feat_firmware_capabilities(struct ifxf_if *ifp)
{
	struct ifxf_pub *drvr = ifp->drvr;
	char caps[MAX_CAPS_BUFFER_SIZE];
	enum ifxf_feat_id id;
	int i, err;

	err = ifxf_fil_iovar_data_get(ifp, "cap", caps, sizeof(caps));
	if (err) {
		bphy_err(drvr, "could not get firmware cap (%d)\n", err);
		return;
	}

	ifxf_dbg(INFO, "[ %s]\n", caps);

	for (i = 0; i < ARRAY_SIZE(ifxf_fwcap_map); i++) {
		if (strnstr(caps, ifxf_fwcap_map[i].fwcap_id, sizeof(caps))) {
			id = ifxf_fwcap_map[i].feature;
			ifxf_dbg(INFO, "enabling feature: %s\n",
				  ifxf_feat_names[id]);
			ifp->drvr->feat_flags |= BIT(id);
		}
	}
}

/**
 * ifxf_feat_fwcap_debugfs_read() - expose firmware capabilities to debugfs.
 *
 * @seq: sequence for debugfs entry.
 * @data: raw data pointer.
 */
static int ifxf_feat_fwcap_debugfs_read(struct seq_file *seq, void *data)
{
	struct ifxf_bus *bus_if = dev_get_drvdata(seq->private);
	struct ifxf_pub *drvr = bus_if->drvr;
	struct ifxf_if *ifp = ifxf_get_ifp(drvr, 0);
	char caps[MAX_CAPS_BUFFER_SIZE + 1] = { };
	char *tmp;
	int err;

	err = ifxf_fil_iovar_data_get(ifp, "cap", caps, sizeof(caps));
	if (err) {
		bphy_err(drvr, "could not get firmware cap (%d)\n", err);
		return err;
	}

	/* Put every capability in a new line */
	for (tmp = caps; *tmp; tmp++) {
		if (*tmp == ' ')
			*tmp = '\n';
	}

	/* Usually there is a space at the end of capabilities string */
	seq_printf(seq, "%s", caps);
	/* So make sure we don't print two line breaks */
	if (tmp > caps && *(tmp - 1) != '\n')
		seq_printf(seq, "\n");

	return 0;
}

void ifxf_feat_attach(struct ifxf_pub *drvr)
{
	struct ifxf_if *ifp = ifxf_get_ifp(drvr, 0);
	struct ifxf_pno_macaddr_le pfn_mac;
	struct ifxf_gscan_config gscan_cfg;
	u32 wowl_cap;
	s32 err;

	ifxf_feat_firmware_capabilities(ifp);
	memset(&gscan_cfg, 0, sizeof(gscan_cfg));
	if (drvr->bus_if->chip != CY_CC_43430_CHIP_ID &&
	    drvr->bus_if->chip != CY_CC_4345_CHIP_ID &&
	    drvr->bus_if->chip != CY_CC_43439_CHIP_ID)
		ifxf_feat_iovar_data_set(ifp, IFXF_FEAT_GSCAN,
					  "pfn_gscan_cfg",
					  &gscan_cfg, sizeof(gscan_cfg));
	ifxf_feat_iovar_int_get(ifp, IFXF_FEAT_PNO, "pfn");
	if (drvr->bus_if->wowl_supported)
		ifxf_feat_iovar_int_get(ifp, IFXF_FEAT_WOWL, "wowl");
	if (ifxf_feat_is_enabled(ifp, IFXF_FEAT_WOWL)) {
		err = ifxf_fil_iovar_int_get(ifp, "wowl_cap", &wowl_cap);
		if (!err) {
			ifp->drvr->feat_flags |= BIT(IFXF_FEAT_WOWL_ARP_ND);
			if (wowl_cap & IFXF_WOWL_PFN_FOUND)
				ifp->drvr->feat_flags |=
					BIT(IFXF_FEAT_WOWL_ND);
			if (wowl_cap & IFXF_WOWL_GTK_FAILURE)
				ifp->drvr->feat_flags |=
					BIT(IFXF_FEAT_WOWL_GTK);
		}
	}
	/* MBSS does not work for all chips */
	switch (drvr->bus_if->chip) {
	case CY_CC_43362_CHIP_ID:
		ifp->drvr->feat_flags &= ~BIT(IFXF_FEAT_MBSS);
		break;
	default:
		break;
	}
	ifxf_feat_iovar_int_get(ifp, IFXF_FEAT_RSDB, "rsdb_mode");
	ifxf_feat_iovar_int_get(ifp, IFXF_FEAT_TDLS, "tdls_enable");
	ifxf_feat_iovar_int_get(ifp, IFXF_FEAT_MFP, "mfp");
	ifxf_feat_iovar_int_get(ifp, IFXF_FEAT_DUMP_OBSS, "dump_obss");

	pfn_mac.version = IFXF_PFN_MACADDR_CFG_VER;
	err = ifxf_fil_iovar_data_get(ifp, "pfn_macaddr", &pfn_mac,
				       sizeof(pfn_mac));
	if (!err)
		ifp->drvr->feat_flags |= BIT(IFXF_FEAT_SCAN_RANDOM_MAC);

	ifxf_feat_iovar_int_get(ifp, IFXF_FEAT_FWSUP, "sup_wpa");
	ifxf_feat_iovar_enab_get(ifp, IFXF_FEAT_TWT, "twt", IFXF_TWT_CMD_ENAB);

	if (drvr->settings->feature_disable) {
		ifxf_dbg(INFO, "Features: 0x%02x, disable: 0x%02x\n",
			  ifp->drvr->feat_flags,
			  drvr->settings->feature_disable);
		ifp->drvr->feat_flags &= ~drvr->settings->feature_disable;
	}

	ifxf_feat_firmware_overrides(drvr);

	/* set chip related quirks */
	switch (drvr->bus_if->chip) {
	default:
		/* no quirks */
		break;
	}
}

void ifxf_feat_debugfs_create(struct ifxf_pub *drvr)
{
	ifxf_debugfs_add_entry(drvr, "features", ifxf_feat_debugfs_read);
	ifxf_debugfs_add_entry(drvr, "fwcap", ifxf_feat_fwcap_debugfs_read);
}

bool ifxf_feat_is_enabled(struct ifxf_if *ifp, enum ifxf_feat_id id)
{
	return (ifp->drvr->feat_flags & BIT(id));
}

bool ifxf_feat_is_quirk_enabled(struct ifxf_if *ifp,
				 enum ifxf_feat_quirk quirk)
{
	return (ifp->drvr->chip_quirks & BIT(quirk));
}

bool ifxf_feat_is_6ghz_enabled(struct ifxf_if *ifp)
{
	return (!ifp->drvr->settings->disable_6ghz);
}

bool ifxf_feat_is_sdio_rxf_in_kthread(struct ifxf_pub *drvr)
{
	if (drvr)
		return drvr->settings->sdio_rxf_in_kthread_enabled;
	else
		return false;
}

bool ifxf_feat_is_offloads_enabled(struct ifxf_if *ifp)
{
	if (ifp && ifp->drvr)
		return ifp->drvr->settings->offload_prof;

	return false;
}
