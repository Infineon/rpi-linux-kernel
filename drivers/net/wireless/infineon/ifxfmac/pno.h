// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2016 Broadcom
 */
#ifndef _IFXF_PNO_H
#define _IFXF_PNO_H

#define IFXF_PNO_SCAN_COMPLETE			1
#define IFXF_PNO_MAX_PFN_COUNT			16
#define IFXF_PNO_SCHED_SCAN_MIN_PERIOD	10
#define IFXF_PNO_SCHED_SCAN_MAX_PERIOD	508

/* forward declaration */
struct ifxf_pno_info;

/**
 * ifxf_pno_start_sched_scan - initiate scheduled scan on device.
 *
 * @ifp: interface object used.
 * @req: configuration parameters for scheduled scan.
 */
int ifxf_pno_start_sched_scan(struct ifxf_if *ifp,
			       struct cfg80211_sched_scan_request *req);

/**
 * ifxf_pno_stop_sched_scan - terminate scheduled scan on device.
 *
 * @ifp: interface object used.
 * @reqid: unique identifier of scan to be stopped.
 */
int ifxf_pno_stop_sched_scan(struct ifxf_if *ifp, u64 reqid);

/**
 * ifxf_pno_wiphy_params - fill scheduled scan parameters in wiphy instance.
 *
 * @wiphy: wiphy instance to be used.
 * @gscan: indicates whether the device has support for g-scan feature.
 */
void ifxf_pno_wiphy_params(struct wiphy *wiphy, bool gscan);

/**
 * ifxf_pno_attach - allocate and attach module information.
 *
 * @cfg: cfg80211 context used.
 */
int ifxf_pno_attach(struct ifxf_cfg80211_info *cfg);

/**
 * ifxf_pno_detach - detach and free module information.
 *
 * @cfg: cfg80211 context used.
 */
void ifxf_pno_detach(struct ifxf_cfg80211_info *cfg);

/**
 * ifxf_pno_find_reqid_by_bucket - find request id for given bucket index.
 *
 * @pi: pno instance used.
 * @bucket: index of firmware bucket.
 */
u64 ifxf_pno_find_reqid_by_bucket(struct ifxf_pno_info *pi, u32 bucket);

/**
 * ifxf_pno_get_bucket_map - determine bucket map for given netinfo.
 *
 * @pi: pno instance used.
 * @netinfo: netinfo to compare with bucket configuration.
 */
u32 ifxf_pno_get_bucket_map(struct ifxf_pno_info *pi,
			     struct ifxf_pno_net_info_le *netinfo);

#endif /* _IFXF_PNO_H */
