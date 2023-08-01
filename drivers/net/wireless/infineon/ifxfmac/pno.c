// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2016 Broadcom
 */
#include <linux/netdevice.h>
#include <linux/gcd.h>
#include <net/cfg80211.h>

#include "core.h"
#include "debug.h"
#include "fwil.h"
#include "fwil_types.h"
#include "cfg80211.h"
#include "pno.h"

#define IFXF_PNO_VERSION		2
#define IFXF_PNO_REPEAT		4
#define IFXF_PNO_FREQ_EXPO_MAX		3
#define IFXF_PNO_IMMEDIATE_SCAN_BIT	3
#define IFXF_PNO_ENABLE_BD_SCAN_BIT	5
#define IFXF_PNO_ENABLE_ADAPTSCAN_BIT	6
#define IFXF_PNO_REPORT_SEPARATELY_BIT	11
#define IFXF_PNO_SCAN_INCOMPLETE	0
#define IFXF_PNO_WPA_AUTH_ANY		0xFFFFFFFF
#define IFXF_PNO_HIDDEN_BIT		2
#define IFXF_PNO_SCHED_SCAN_PERIOD	30

#define IFXF_PNO_MAX_BUCKETS		16
#define GSCAN_BATCH_NO_THR_SET			101
#define GSCAN_RETRY_THRESHOLD			3

struct ifxf_pno_info {
	int n_reqs;
	struct cfg80211_sched_scan_request *reqs[IFXF_PNO_MAX_BUCKETS];
	struct mutex req_lock;
};

#define ifp_to_pno(_ifp)	((_ifp)->drvr->config->pno)

static int ifxf_pno_store_request(struct ifxf_pno_info *pi,
				   struct cfg80211_sched_scan_request *req)
{
	if (WARN(pi->n_reqs == IFXF_PNO_MAX_BUCKETS,
		 "pno request storage full\n"))
		return -ENOSPC;

	ifxf_dbg(SCAN, "reqid=%llu\n", req->reqid);
	mutex_lock(&pi->req_lock);
	pi->reqs[pi->n_reqs++] = req;
	mutex_unlock(&pi->req_lock);
	return 0;
}

static int ifxf_pno_remove_request(struct ifxf_pno_info *pi, u64 reqid)
{
	int i, err = 0;

	mutex_lock(&pi->req_lock);

	/* Nothing to do if we have no requests */
	if (pi->n_reqs == 0)
		goto done;

	/* find request */
	for (i = 0; i < pi->n_reqs; i++) {
		if (pi->reqs[i]->reqid == reqid)
			break;
	}
	/* request not found */
	if (WARN(i == pi->n_reqs, "reqid not found\n")) {
		err = -ENOENT;
		goto done;
	}

	ifxf_dbg(SCAN, "reqid=%llu\n", reqid);
	pi->n_reqs--;

	/* if last we are done */
	if (!pi->n_reqs || i == pi->n_reqs)
		goto done;

	/* fill the gap with remaining requests */
	while (i <= pi->n_reqs - 1) {
		pi->reqs[i] = pi->reqs[i + 1];
		i++;
	}

done:
	mutex_unlock(&pi->req_lock);
	return err;
}

static int ifxf_pno_channel_config(struct ifxf_if *ifp,
				    struct ifxf_pno_config_le *cfg)
{
	cfg->reporttype = 0;
	cfg->flags = 0;

	return ifxf_fil_iovar_data_set(ifp, "pfn_cfg", cfg, sizeof(*cfg));
}

static int ifxf_pno_config(struct ifxf_if *ifp, u32 scan_freq,
			    u32 mscan, u32 bestn)
{
	struct ifxf_pub *drvr = ifp->drvr;
	struct ifxf_pno_param_le pfn_param;
	u16 flags;
	u32 pfnmem;
	s32 err;

	memset(&pfn_param, 0, sizeof(pfn_param));
	pfn_param.version = cpu_to_le32(IFXF_PNO_VERSION);

	/* set extra pno params */
	flags = BIT(IFXF_PNO_IMMEDIATE_SCAN_BIT) |
		BIT(IFXF_PNO_ENABLE_ADAPTSCAN_BIT);
	pfn_param.repeat = IFXF_PNO_REPEAT;
	pfn_param.exp = IFXF_PNO_FREQ_EXPO_MAX;

	/* set up pno scan fr */
	pfn_param.scan_freq = cpu_to_le32(scan_freq);

	if (mscan) {
		pfnmem = bestn;

		/* set bestn in firmware */
		err = ifxf_fil_iovar_int_set(ifp, "pfnmem", pfnmem);
		if (err < 0) {
			bphy_err(drvr, "failed to set pfnmem\n");
			goto exit;
		}
		/* get max mscan which the firmware supports */
		err = ifxf_fil_iovar_int_get(ifp, "pfnmem", &pfnmem);
		if (err < 0) {
			bphy_err(drvr, "failed to get pfnmem\n");
			goto exit;
		}
		mscan = min_t(u32, mscan, pfnmem);
		pfn_param.mscan = mscan;
		pfn_param.bestn = bestn;
		flags |= BIT(IFXF_PNO_ENABLE_BD_SCAN_BIT);
		ifxf_dbg(INFO, "mscan=%d, bestn=%d\n", mscan, bestn);
	}

	pfn_param.flags = cpu_to_le16(flags);
	err = ifxf_fil_iovar_data_set(ifp, "pfn_set", &pfn_param,
				       sizeof(pfn_param));
	if (err)
		bphy_err(drvr, "pfn_set failed, err=%d\n", err);

exit:
	return err;
}

static int ifxf_pno_set_random(struct ifxf_if *ifp, struct ifxf_pno_info *pi)
{
	struct ifxf_pub *drvr = ifp->drvr;
	struct ifxf_pno_macaddr_le pfn_mac;
	u8 *mac_addr = NULL;
	u8 *mac_mask = NULL;
	int err, i, ri;

	for (ri = 0; ri < pi->n_reqs; ri++)
		if (pi->reqs[ri]->flags & NL80211_SCAN_FLAG_RANDOM_ADDR) {
			mac_addr = pi->reqs[ri]->mac_addr;
			mac_mask = pi->reqs[ri]->mac_addr_mask;
			break;
		}

	/* no random mac requested */
	if (!mac_addr)
		return 0;

	pfn_mac.version = IFXF_PFN_MACADDR_CFG_VER;
	pfn_mac.flags = IFXF_PFN_MAC_OUI_ONLY | IFXF_PFN_SET_MAC_UNASSOC;

	memcpy(pfn_mac.mac, mac_addr, ETH_ALEN);
	for (i = 0; i < ETH_ALEN; i++) {
		pfn_mac.mac[i] &= mac_mask[i];
		pfn_mac.mac[i] |= get_random_u8() & ~(mac_mask[i]);
	}
	/* Clear multi bit */
	pfn_mac.mac[0] &= 0xFE;
	/* Set locally administered */
	pfn_mac.mac[0] |= 0x02;

	ifxf_dbg(SCAN, "enabling random mac: reqid=%llu mac=%pM\n",
		  pi->reqs[ri]->reqid, pfn_mac.mac);
	err = ifxf_fil_iovar_data_set(ifp, "pfn_macaddr", &pfn_mac,
				       sizeof(pfn_mac));
	if (err)
		bphy_err(drvr, "pfn_macaddr failed, err=%d\n", err);

	return err;
}

static int ifxf_pno_add_ssid(struct ifxf_if *ifp, struct cfg80211_ssid *ssid,
			      bool active)
{
	struct ifxf_pub *drvr = ifp->drvr;
	struct ifxf_pno_net_param_le pfn;
	int err;

	pfn.auth = cpu_to_le32(WLAN_AUTH_OPEN);
	pfn.wpa_auth = cpu_to_le32(IFXF_PNO_WPA_AUTH_ANY);
	pfn.wsec = cpu_to_le32(0);
	pfn.infra = cpu_to_le32(1);
	pfn.flags = 0;
	if (active)
		pfn.flags = cpu_to_le32(1 << IFXF_PNO_HIDDEN_BIT);
	pfn.ssid.SSID_len = cpu_to_le32(ssid->ssid_len);
	memcpy(pfn.ssid.SSID, ssid->ssid, ssid->ssid_len);

	ifxf_dbg(SCAN, "adding ssid=%.32s (active=%d)\n", ssid->ssid, active);
	err = ifxf_fil_iovar_data_set(ifp, "pfn_add", &pfn, sizeof(pfn));
	if (err < 0)
		bphy_err(drvr, "adding failed: err=%d\n", err);
	return err;
}

static int ifxf_pno_add_bssid(struct ifxf_if *ifp, const u8 *bssid)
{
	struct ifxf_pub *drvr = ifp->drvr;
	struct ifxf_pno_bssid_le bssid_cfg;
	int err;

	memcpy(bssid_cfg.bssid, bssid, ETH_ALEN);
	bssid_cfg.flags = 0;

	ifxf_dbg(SCAN, "adding bssid=%pM\n", bssid);
	err = ifxf_fil_iovar_data_set(ifp, "pfn_add_bssid", &bssid_cfg,
				       sizeof(bssid_cfg));
	if (err < 0)
		bphy_err(drvr, "adding failed: err=%d\n", err);
	return err;
}

static bool ifxf_is_ssid_active(struct cfg80211_ssid *ssid,
				 struct cfg80211_sched_scan_request *req)
{
	int i;

	if (!ssid || !req->ssids || !req->n_ssids)
		return false;

	for (i = 0; i < req->n_ssids; i++) {
		if (ssid->ssid_len == req->ssids[i].ssid_len) {
			if (!strncmp(ssid->ssid, req->ssids[i].ssid,
				     ssid->ssid_len))
				return true;
		}
	}
	return false;
}

static int ifxf_pno_clean(struct ifxf_if *ifp)
{
	struct ifxf_pub *drvr = ifp->drvr;
	int ret;

	/* Disable pfn */
	ret = ifxf_fil_iovar_int_set(ifp, "pfn", 0);
	if (ret == 0) {
		/* clear pfn */
		ret = ifxf_fil_iovar_data_set(ifp, "pfnclear", NULL, 0);
	}
	if (ret < 0)
		bphy_err(drvr, "failed code %d\n", ret);

	return ret;
}

static int ifxf_pno_get_bucket_channels(struct cfg80211_sched_scan_request *r,
					 struct ifxf_pno_config_le *pno_cfg)
{
	u32 n_chan = le32_to_cpu(pno_cfg->channel_num);
	u16 chan;
	int i, err = 0;

	for (i = 0; i < r->n_channels; i++) {
		if (n_chan >= IFXF_NUMCHANNELS) {
			err = -ENOSPC;
			goto done;
		}
		chan = r->channels[i]->hw_value;
		ifxf_dbg(SCAN, "[%d] Chan : %u\n", n_chan, chan);
		pno_cfg->channel_list[n_chan++] = cpu_to_le16(chan);
	}
	/* return number of channels */
	err = n_chan;
done:
	pno_cfg->channel_num = cpu_to_le32(n_chan);
	return err;
}

static int ifxf_pno_prep_fwconfig(struct ifxf_pno_info *pi,
				   struct ifxf_pno_config_le *pno_cfg,
				   struct ifxf_gscan_bucket_config **buckets,
				   u32 *scan_freq)
{
	struct cfg80211_sched_scan_request *sr;
	struct ifxf_gscan_bucket_config *fw_buckets;
	int i, err, chidx;

	ifxf_dbg(SCAN, "n_reqs=%d\n", pi->n_reqs);
	if (WARN_ON(!pi->n_reqs))
		return -ENODATA;

	/*
	 * actual scan period is determined using gcd() for each
	 * scheduled scan period.
	 */
	*scan_freq = pi->reqs[0]->scan_plans[0].interval;
	for (i = 1; i < pi->n_reqs; i++) {
		sr = pi->reqs[i];
		*scan_freq = gcd(sr->scan_plans[0].interval, *scan_freq);
	}
	if (*scan_freq < IFXF_PNO_SCHED_SCAN_MIN_PERIOD) {
		ifxf_dbg(SCAN, "scan period too small, using minimum\n");
		*scan_freq = IFXF_PNO_SCHED_SCAN_MIN_PERIOD;
	}

	*buckets = NULL;
	fw_buckets = kcalloc(pi->n_reqs, sizeof(*fw_buckets), GFP_KERNEL);
	if (!fw_buckets)
		return -ENOMEM;

	memset(pno_cfg, 0, sizeof(*pno_cfg));
	for (i = 0; i < pi->n_reqs; i++) {
		sr = pi->reqs[i];
		chidx = ifxf_pno_get_bucket_channels(sr, pno_cfg);
		if (chidx < 0) {
			err = chidx;
			goto fail;
		}
		fw_buckets[i].bucket_end_index = chidx - 1;
		fw_buckets[i].bucket_freq_multiple =
			sr->scan_plans[0].interval / *scan_freq;
		/* assure period is non-zero */
		if (!fw_buckets[i].bucket_freq_multiple)
			fw_buckets[i].bucket_freq_multiple = 1;
		fw_buckets[i].flag = IFXF_PNO_REPORT_NO_BATCH;
	}

	if (IFXF_SCAN_ON()) {
		ifxf_err("base period=%u\n", *scan_freq);
		for (i = 0; i < pi->n_reqs; i++) {
			ifxf_err("[%d] period %u max %u repeat %u flag %x idx %u\n",
				  i, fw_buckets[i].bucket_freq_multiple,
				  le16_to_cpu(fw_buckets[i].max_freq_multiple),
				  fw_buckets[i].repeat, fw_buckets[i].flag,
				  fw_buckets[i].bucket_end_index);
		}
	}
	*buckets = fw_buckets;
	return pi->n_reqs;

fail:
	kfree(fw_buckets);
	return err;
}

static int ifxf_pno_config_networks(struct ifxf_if *ifp,
				     struct ifxf_pno_info *pi)
{
	struct cfg80211_sched_scan_request *r;
	struct cfg80211_match_set *ms;
	bool active;
	int i, j, err = 0;

	for (i = 0; i < pi->n_reqs; i++) {
		r = pi->reqs[i];

		for (j = 0; j < r->n_match_sets; j++) {
			ms = &r->match_sets[j];
			if (ms->ssid.ssid_len) {
				active = ifxf_is_ssid_active(&ms->ssid, r);
				err = ifxf_pno_add_ssid(ifp, &ms->ssid,
							 active);
			}
			if (!err && is_valid_ether_addr(ms->bssid))
				err = ifxf_pno_add_bssid(ifp, ms->bssid);

			if (err < 0)
				return err;
		}
	}
	return 0;
}

static int ifxf_pno_config_sched_scans(struct ifxf_if *ifp)
{
	struct ifxf_pub *drvr = ifp->drvr;
	struct ifxf_pno_info *pi;
	struct ifxf_gscan_config *gscan_cfg;
	struct ifxf_gscan_bucket_config *buckets;
	struct ifxf_pno_config_le pno_cfg;
	size_t gsz;
	u32 scan_freq;
	int err, n_buckets;

	pi = ifp_to_pno(ifp);
	n_buckets = ifxf_pno_prep_fwconfig(pi, &pno_cfg, &buckets,
					    &scan_freq);
	if (n_buckets < 0)
		return n_buckets;

	gsz = sizeof(*gscan_cfg) + (n_buckets - 1) * sizeof(*buckets);
	gscan_cfg = kzalloc(gsz, GFP_KERNEL);
	if (!gscan_cfg) {
		err = -ENOMEM;
		goto free_buckets;
	}

	/* clean up everything */
	err = ifxf_pno_clean(ifp);
	if  (err < 0) {
		bphy_err(drvr, "failed error=%d\n", err);
		goto free_gscan;
	}

	/* configure pno */
	err = ifxf_pno_config(ifp, scan_freq, 0, 0);
	if (err < 0)
		goto free_gscan;

	err = ifxf_pno_channel_config(ifp, &pno_cfg);
	if (err < 0)
		goto clean;

	gscan_cfg->version = cpu_to_le16(IFXF_GSCAN_CFG_VERSION);
	gscan_cfg->retry_threshold = GSCAN_RETRY_THRESHOLD;
	gscan_cfg->buffer_threshold = GSCAN_BATCH_NO_THR_SET;
	gscan_cfg->flags = IFXF_GSCAN_CFG_ALL_BUCKETS_IN_1ST_SCAN;

	gscan_cfg->count_of_channel_buckets = n_buckets;
	memcpy(&gscan_cfg->bucket[0], buckets,
	       n_buckets * sizeof(*buckets));

	err = ifxf_fil_iovar_data_set(ifp, "pfn_gscan_cfg", gscan_cfg, gsz);

	if (err < 0)
		goto clean;

	/* configure random mac */
	err = ifxf_pno_set_random(ifp, pi);
	if (err < 0)
		goto clean;

	err = ifxf_pno_config_networks(ifp, pi);
	if (err < 0)
		goto clean;

	/* Enable the PNO */
	err = ifxf_fil_iovar_int_set(ifp, "pfn", 1);

clean:
	if (err < 0)
		ifxf_pno_clean(ifp);
free_gscan:
	kfree(gscan_cfg);
free_buckets:
	kfree(buckets);
	return err;
}

int ifxf_pno_start_sched_scan(struct ifxf_if *ifp,
			       struct cfg80211_sched_scan_request *req)
{
	struct ifxf_pno_info *pi;
	int ret;

	ifxf_dbg(TRACE, "reqid=%llu\n", req->reqid);

	pi = ifp_to_pno(ifp);
	ret = ifxf_pno_store_request(pi, req);
	if (ret < 0)
		return ret;

	ret = ifxf_pno_config_sched_scans(ifp);
	if (ret < 0) {
		ifxf_pno_remove_request(pi, req->reqid);
		if (pi->n_reqs)
			(void)ifxf_pno_config_sched_scans(ifp);
		return ret;
	}
	return 0;
}

int ifxf_pno_stop_sched_scan(struct ifxf_if *ifp, u64 reqid)
{
	struct ifxf_pno_info *pi;
	int err;

	ifxf_dbg(TRACE, "reqid=%llu\n", reqid);

	pi = ifp_to_pno(ifp);

	/* No PNO request */
	if (!pi->n_reqs)
		return 0;

	err = ifxf_pno_remove_request(pi, reqid);
	if (err)
		return err;

	ifxf_pno_clean(ifp);

	if (pi->n_reqs)
		(void)ifxf_pno_config_sched_scans(ifp);

	return 0;
}

int ifxf_pno_attach(struct ifxf_cfg80211_info *cfg)
{
	struct ifxf_pno_info *pi;

	ifxf_dbg(TRACE, "enter\n");
	pi = kzalloc(sizeof(*pi), GFP_KERNEL);
	if (!pi)
		return -ENOMEM;

	cfg->pno = pi;
	mutex_init(&pi->req_lock);
	return 0;
}

void ifxf_pno_detach(struct ifxf_cfg80211_info *cfg)
{
	struct ifxf_pno_info *pi;

	ifxf_dbg(TRACE, "enter\n");
	pi = cfg->pno;
	cfg->pno = NULL;

	WARN_ON(pi->n_reqs);
	mutex_destroy(&pi->req_lock);
	kfree(pi);
}

void ifxf_pno_wiphy_params(struct wiphy *wiphy, bool gscan)
{
	/* scheduled scan settings */
	wiphy->max_sched_scan_reqs = gscan ? IFXF_PNO_MAX_BUCKETS : 1;
	wiphy->max_sched_scan_ssids = IFXF_PNO_MAX_PFN_COUNT;
	wiphy->max_match_sets = IFXF_PNO_MAX_PFN_COUNT;
	wiphy->max_sched_scan_ie_len = IFXF_SCAN_IE_LEN_MAX;
	wiphy->max_sched_scan_plan_interval = IFXF_PNO_SCHED_SCAN_MAX_PERIOD;
}

u64 ifxf_pno_find_reqid_by_bucket(struct ifxf_pno_info *pi, u32 bucket)
{
	u64 reqid = 0;

	mutex_lock(&pi->req_lock);

	if (bucket < pi->n_reqs)
		reqid = pi->reqs[bucket]->reqid;

	mutex_unlock(&pi->req_lock);
	return reqid;
}

u32 ifxf_pno_get_bucket_map(struct ifxf_pno_info *pi,
			     struct ifxf_pno_net_info_le *ni)
{
	struct cfg80211_sched_scan_request *req;
	struct cfg80211_match_set *ms;
	u32 bucket_map = 0;
	int i, j;

	mutex_lock(&pi->req_lock);
	for (i = 0; i < pi->n_reqs; i++) {
		req = pi->reqs[i];

		if (!req->n_match_sets)
			continue;
		for (j = 0; j < req->n_match_sets; j++) {
			ms = &req->match_sets[j];
			if (ms->ssid.ssid_len == ni->SSID_len &&
			    !memcmp(ms->ssid.ssid, ni->SSID, ni->SSID_len)) {
				bucket_map |= BIT(i);
				break;
			}
			if (is_valid_ether_addr(ms->bssid) &&
			    !memcmp(ms->bssid, ni->bssid, ETH_ALEN)) {
				bucket_map |= BIT(i);
				break;
			}
		}
	}
	mutex_unlock(&pi->req_lock);
	return bucket_map;
}
