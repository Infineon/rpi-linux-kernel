// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2013 Broadcom Corporation
 */
#ifndef WL_BTCOEX_H_
#define WL_BTCOEX_H_

enum ifxf_btcoex_mode {
	IFXF_BTCOEX_DISABLED,
	IFXF_BTCOEX_ENABLED
};

int ifxf_btcoex_attach(struct ifxf_cfg80211_info *cfg);
void ifxf_btcoex_detach(struct ifxf_cfg80211_info *cfg);
int ifxf_btcoex_set_mode(struct ifxf_cfg80211_vif *vif,
			  enum ifxf_btcoex_mode mode, u16 duration);

#endif /* WL_BTCOEX_H_ */
