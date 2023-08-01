// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2014 Broadcom Corporation
 */
#ifndef IFXFMAC_COMMON_H
#define IFXFMAC_COMMON_H

#include <linux/platform_device.h>
#include <linux/platform_data/ifxfmac.h>
#include "fwil_types.h"

#define IFXF_FW_ALTPATH_LEN			256

/* Definitions for the module global and device specific settings are defined
 * here. Two structs are used for them. ifxf_mp_global_t and ifxf_mp_device.
 * The mp_global is instantiated once in a global struct and gets initialized
 * by the common_attach function which should be called before any other
 * (module) initiliazation takes place. The device specific settings is part
 * of the drvr struct and should be initialized on every ifxf_attach.
 */

/**
 * struct ifxf_mp_global_t - Global module paramaters.
 *
 * @firmware_path: Alternative firmware path.
 */
struct ifxf_mp_global_t {
	char	firmware_path[IFXF_FW_ALTPATH_LEN];
};

extern struct ifxf_mp_global_t ifxf_mp_global;

/**
 * struct ifxf_mp_device - Device module paramaters.
 *
 * @p2p_enable: Legacy P2P0 enable (old wpa_supplicant).
 * @feature_disable: Feature_disable bitmask.
 * @fcmode: FWS flow control.
 * @roamoff: Firmware roaming off?
 * @eap_restrict: Not allow data tx/rx until 802.1X auth succeeds
 * @default_pm: default power management (PM) mode.
 * @ignore_probe_fail: Ignore probe failure.
 * @trivial_ccode_map: Assume firmware uses ISO3166 country codes with rev 0
 * @fw_ap_select: Allow FW to select AP.
 * @disable_6ghz: Disable 6GHz operation
 * @sdio_in_isr: Handle SDIO DPC in ISR.
 * @offload_prof: Enable offloads configuration power profile (Low,Mid,High)
 * @offload_feat: offloads feature flags to be enabled for selected pwr profile
 * @country_codes: If available, pointer to struct for translating country codes
 * @bus: Bus specific platform data. Only SDIO at the mmoment.
 * @pkt_prio: Support customer dscp to WMM up mapping.
 */
struct ifxf_mp_device {
	bool		p2p_enable;
	unsigned int	feature_disable;
	int		fcmode;
	bool		roamoff;
	bool		iapp;
	bool		eap_restrict;
	int		default_pm;
	bool		ignore_probe_fail;
	bool		trivial_ccode_map;
	bool		fw_ap_select;
	bool		disable_6ghz;
	bool		sdio_in_isr;
	bool		sdio_rxf_in_kthread_enabled;
	unsigned int	offload_prof;
	unsigned int	offload_feat;
	struct ifxfmac_pd_cc *country_codes;
	const char	*board_type;
	unsigned char	mac[ETH_ALEN];
	const char	*antenna_sku;
	union {
		struct ifxfmac_sdio_pd sdio;
	} bus;
	bool		pkt_prio;
};

void ifxf_c_set_joinpref_default(struct ifxf_if *ifp);

struct ifxf_mp_device *ifxf_get_module_param(struct device *dev,
					       enum ifxf_bus_type bus_type,
					       u32 chip, u32 chiprev);
void ifxf_release_module_param(struct ifxf_mp_device *module_param);

/* Sets dongle media info (drv_version, mac address). */
int ifxf_c_preinit_dcmds(struct ifxf_if *ifp);
int ifxf_c_set_cur_etheraddr(struct ifxf_if *ifp, const u8 *addr);

#ifdef CONFIG_DMI
void ifxf_dmi_probe(struct ifxf_mp_device *settings, u32 chip, u32 chiprev);
#else
static inline void
ifxf_dmi_probe(struct ifxf_mp_device *settings, u32 chip, u32 chiprev) {}
#endif

u8 ifxf_map_prio_to_prec(void *cfg, u8 prio);

u8 ifxf_map_prio_to_aci(void *cfg, u8 prio);

void ifxf_generic_offload_config(struct ifxf_if *ifp, unsigned int ol_feat,
				  unsigned int ol_profile, bool reset);
void ifxf_generic_offload_enable(struct ifxf_if *ifp, unsigned int ol_feat,
				  bool enable);
void ifxf_generic_offload_host_ipv4_update(struct ifxf_if *ifp, unsigned int ol_feat,
					    u32 ipaddr, bool is_add);
int ifxf_generic_offload_host_ipv6_update(struct ifxf_if *ifp, unsigned int ol_feat,
					   void *ptr, u8 type, bool is_add);

#endif /* IFXFMAC_COMMON_H */
