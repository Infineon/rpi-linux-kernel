// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2013 Broadcom Corporation
 */
#include <linux/slab.h>
#include <linux/netdevice.h>
#include <net/cfg80211.h>

#include <ifxu_wifi.h>
#include <ifxu_utils.h>
#include <defs.h>
#include "core.h"
#include "debug.h"
#include "fwil.h"
#include "fwil_types.h"
#include "btcoex.h"
#include "p2p.h"
#include "cfg80211.h"

/* T1 start SCO/eSCO priority suppression */
#define IFXF_BTCOEX_OPPR_WIN_TIME   msecs_to_jiffies(2000)

/* BT registers values during DHCP */
#define IFXF_BT_DHCP_REG50 0x8022
#define IFXF_BT_DHCP_REG51 0
#define IFXF_BT_DHCP_REG64 0
#define IFXF_BT_DHCP_REG65 0
#define IFXF_BT_DHCP_REG71 0
#define IFXF_BT_DHCP_REG66 0x2710
#define IFXF_BT_DHCP_REG41 0x33
#define IFXF_BT_DHCP_REG68 0x190

/* number of samples for SCO detection */
#define IFXF_BT_SCO_SAMPLES 12

/**
* enum ifxf_btcoex_state - BT coex DHCP state machine states
* @IFXF_BT_DHCP_IDLE: DCHP is idle
* @IFXF_BT_DHCP_START: DHCP started, wait before
*	boosting wifi priority
* @IFXF_BT_DHCP_OPPR_WIN: graceful DHCP opportunity ended,
*	boost wifi priority
* @IFXF_BT_DHCP_FLAG_FORCE_TIMEOUT: wifi priority boost end,
*	restore defaults
*/
enum ifxf_btcoex_state {
	IFXF_BT_DHCP_IDLE,
	IFXF_BT_DHCP_START,
	IFXF_BT_DHCP_OPPR_WIN,
	IFXF_BT_DHCP_FLAG_FORCE_TIMEOUT
};

/**
 * struct ifxf_btcoex_info - BT coex related information
 * @vif: interface for which request was done.
 * @timer: timer for DHCP state machine
 * @timeout: configured timeout.
 * @timer_on:  DHCP timer active
 * @dhcp_done: DHCP finished before T1/T2 timer expiration
 * @bt_state: DHCP state machine state
 * @work: DHCP state machine work
 * @cfg: driver private data for cfg80211 interface
 * @reg66: saved value of btc_params 66
 * @reg41: saved value of btc_params 41
 * @reg68: saved value of btc_params 68
 * @saved_regs_part1: flag indicating regs 66,41,68
 *	have been saved
 * @reg50: saved value of btc_params 50
 * @reg51: saved value of btc_params 51
 * @reg64: saved value of btc_params 64
 * @reg65: saved value of btc_params 65
 * @reg71: saved value of btc_params 71
 * @saved_regs_part2: flag indicating regs 50,51,64,65,71
 *	have been saved
 */
struct ifxf_btcoex_info {
	struct ifxf_cfg80211_vif *vif;
	struct timer_list timer;
	u16 timeout;
	bool timer_on;
	bool dhcp_done;
	enum ifxf_btcoex_state bt_state;
	struct work_struct work;
	struct ifxf_cfg80211_info *cfg;
	u32 reg66;
	u32 reg41;
	u32 reg68;
	bool saved_regs_part1;
	u32 reg50;
	u32 reg51;
	u32 reg64;
	u32 reg65;
	u32 reg71;
	bool saved_regs_part2;
};

/**
 * ifxf_btcoex_params_write() - write btc_params firmware variable
 * @ifp: interface
 * @addr: btc_params register number
 * @data: data to write
 */
static s32 ifxf_btcoex_params_write(struct ifxf_if *ifp, u32 addr, u32 data)
{
	struct {
		__le32 addr;
		__le32 data;
	} reg_write;

	reg_write.addr = cpu_to_le32(addr);
	reg_write.data = cpu_to_le32(data);
	return ifxf_fil_iovar_data_set(ifp, "btc_params",
					&reg_write, sizeof(reg_write));
}

/**
 * ifxf_btcoex_params_read() - read btc_params firmware variable
 * @ifp: interface
 * @addr: btc_params register number
 * @data: read data
 */
static s32 ifxf_btcoex_params_read(struct ifxf_if *ifp, u32 addr, u32 *data)
{
	*data = addr;

	return ifxf_fil_iovar_int_get(ifp, "btc_params", data);
}

/**
 * ifxf_btcoex_boost_wifi() - control BT SCO/eSCO parameters
 * @btci: BT coex info
 * @trump_sco:
 *	true - set SCO/eSCO parameters for compatibility
 *		during DHCP window
 *	false - restore saved parameter values
 *
 * Enhanced BT COEX settings for eSCO compatibility during DHCP window
 */
static void ifxf_btcoex_boost_wifi(struct ifxf_btcoex_info *btci,
				    bool trump_sco)
{
	struct ifxf_if *ifp = ifxf_get_ifp(btci->cfg->pub, 0);

	if (trump_sco && !btci->saved_regs_part2) {
		/* this should reduce eSCO agressive
		 * retransmit w/o breaking it
		 */

		/* save current */
		ifxf_dbg(INFO, "new SCO/eSCO coex algo {save & override}\n");
		ifxf_btcoex_params_read(ifp, 50, &btci->reg50);
		ifxf_btcoex_params_read(ifp, 51, &btci->reg51);
		ifxf_btcoex_params_read(ifp, 64, &btci->reg64);
		ifxf_btcoex_params_read(ifp, 65, &btci->reg65);
		ifxf_btcoex_params_read(ifp, 71, &btci->reg71);

		btci->saved_regs_part2 = true;
		ifxf_dbg(INFO,
			  "saved bt_params[50,51,64,65,71]: 0x%x 0x%x 0x%x 0x%x 0x%x\n",
			  btci->reg50, btci->reg51, btci->reg64,
			  btci->reg65, btci->reg71);

		/* pacify the eSco   */
		ifxf_btcoex_params_write(ifp, 50, IFXF_BT_DHCP_REG50);
		ifxf_btcoex_params_write(ifp, 51, IFXF_BT_DHCP_REG51);
		ifxf_btcoex_params_write(ifp, 64, IFXF_BT_DHCP_REG64);
		ifxf_btcoex_params_write(ifp, 65, IFXF_BT_DHCP_REG65);
		ifxf_btcoex_params_write(ifp, 71, IFXF_BT_DHCP_REG71);

	} else if (btci->saved_regs_part2) {
		/* restore previously saved bt params */
		ifxf_dbg(INFO, "Do new SCO/eSCO coex algo {restore}\n");
		ifxf_btcoex_params_write(ifp, 50, btci->reg50);
		ifxf_btcoex_params_write(ifp, 51, btci->reg51);
		ifxf_btcoex_params_write(ifp, 64, btci->reg64);
		ifxf_btcoex_params_write(ifp, 65, btci->reg65);
		ifxf_btcoex_params_write(ifp, 71, btci->reg71);

		ifxf_dbg(INFO,
			  "restored bt_params[50,51,64,65,71]: 0x%x 0x%x 0x%x 0x%x 0x%x\n",
			  btci->reg50, btci->reg51, btci->reg64,
			  btci->reg65, btci->reg71);

		btci->saved_regs_part2 = false;
	} else {
		ifxf_dbg(INFO, "attempted to restore not saved BTCOEX params\n");
	}
}

/**
 * ifxf_btcoex_is_sco_active() - check if SCO/eSCO is active
 * @ifp: interface
 *
 * return: true if SCO/eSCO session is active
 */
static bool ifxf_btcoex_is_sco_active(struct ifxf_if *ifp)
{
	int ioc_res = 0;
	bool res = false;
	int sco_id_cnt = 0;
	u32 param27;
	int i;

	for (i = 0; i < IFXF_BT_SCO_SAMPLES; i++) {
		ioc_res = ifxf_btcoex_params_read(ifp, 27, &param27);

		if (ioc_res < 0) {
			ifxf_err("ioc read btc params error\n");
			break;
		}

		ifxf_dbg(INFO, "sample[%d], btc_params 27:%x\n", i, param27);

		if ((param27 & 0x6) == 2) { /* count both sco & esco  */
			sco_id_cnt++;
		}

		if (sco_id_cnt > 2) {
			ifxf_dbg(INFO,
				  "sco/esco detected, pkt id_cnt:%d samples:%d\n",
				  sco_id_cnt, i);
			res = true;
			break;
		}
	}
	ifxf_dbg(TRACE, "exit: result=%d\n", res);
	return res;
}

/*
 * btcmf_btcoex_save_part1() - save first step parameters.
 */
static void btcmf_btcoex_save_part1(struct ifxf_btcoex_info *btci)
{
	struct ifxf_if *ifp = btci->vif->ifp;

	if (!btci->saved_regs_part1) {
		/* Retrieve and save original reg value */
		ifxf_btcoex_params_read(ifp, 66, &btci->reg66);
		ifxf_btcoex_params_read(ifp, 41, &btci->reg41);
		ifxf_btcoex_params_read(ifp, 68, &btci->reg68);
		btci->saved_regs_part1 = true;
		ifxf_dbg(INFO,
			  "saved btc_params regs (66,41,68) 0x%x 0x%x 0x%x\n",
			  btci->reg66, btci->reg41,
			  btci->reg68);
	}
}

/*
 * ifxf_btcoex_restore_part1() - restore first step parameters.
 */
static void ifxf_btcoex_restore_part1(struct ifxf_btcoex_info *btci)
{
	struct ifxf_if *ifp;

	if (btci->saved_regs_part1) {
		btci->saved_regs_part1 = false;
		ifp = btci->vif->ifp;
		ifxf_btcoex_params_write(ifp, 66, btci->reg66);
		ifxf_btcoex_params_write(ifp, 41, btci->reg41);
		ifxf_btcoex_params_write(ifp, 68, btci->reg68);
		ifxf_dbg(INFO,
			  "restored btc_params regs {66,41,68} 0x%x 0x%x 0x%x\n",
			  btci->reg66, btci->reg41,
			  btci->reg68);
	}
}

/*
 * ifxf_btcoex_timerfunc() - BT coex timer callback
 */
static void ifxf_btcoex_timerfunc(struct timer_list *t)
{
	struct ifxf_btcoex_info *bt_local = from_timer(bt_local, t, timer);
	ifxf_dbg(TRACE, "enter\n");

	bt_local->timer_on = false;
	schedule_work(&bt_local->work);
}

/**
 * ifxf_btcoex_handler() - BT coex state machine work handler
 * @work: work
 */
static void ifxf_btcoex_handler(struct work_struct *work)
{
	struct ifxf_btcoex_info *btci;
	btci = container_of(work, struct ifxf_btcoex_info, work);
	if (btci->timer_on) {
		btci->timer_on = false;
		del_timer_sync(&btci->timer);
	}

	switch (btci->bt_state) {
	case IFXF_BT_DHCP_START:
		/* DHCP started provide OPPORTUNITY window
		   to get DHCP address
		*/
		ifxf_dbg(INFO, "DHCP started\n");
		btci->bt_state = IFXF_BT_DHCP_OPPR_WIN;
		if (btci->timeout < IFXF_BTCOEX_OPPR_WIN_TIME) {
			mod_timer(&btci->timer, btci->timer.expires);
		} else {
			btci->timeout -= IFXF_BTCOEX_OPPR_WIN_TIME;
			mod_timer(&btci->timer,
				  jiffies + IFXF_BTCOEX_OPPR_WIN_TIME);
		}
		btci->timer_on = true;
		break;

	case IFXF_BT_DHCP_OPPR_WIN:
		if (btci->dhcp_done) {
			ifxf_dbg(INFO, "DHCP done before T1 expiration\n");
			goto idle;
		}

		/* DHCP is not over yet, start lowering BT priority */
		ifxf_dbg(INFO, "DHCP T1:%d expired\n",
			  jiffies_to_msecs(IFXF_BTCOEX_OPPR_WIN_TIME));
		ifxf_btcoex_boost_wifi(btci, true);

		btci->bt_state = IFXF_BT_DHCP_FLAG_FORCE_TIMEOUT;
		mod_timer(&btci->timer, jiffies + btci->timeout);
		btci->timer_on = true;
		break;

	case IFXF_BT_DHCP_FLAG_FORCE_TIMEOUT:
		if (btci->dhcp_done)
			ifxf_dbg(INFO, "DHCP done before T2 expiration\n");
		else
			ifxf_dbg(INFO, "DHCP T2:%d expired\n",
				  IFXF_BT_DHCP_FLAG_FORCE_TIMEOUT);

		goto idle;

	default:
		ifxf_err("invalid state=%d !!!\n", btci->bt_state);
		goto idle;
	}

	return;

idle:
	btci->bt_state = IFXF_BT_DHCP_IDLE;
	btci->timer_on = false;
	ifxf_btcoex_boost_wifi(btci, false);
	cfg80211_crit_proto_stopped(&btci->vif->wdev, GFP_KERNEL);
	ifxf_btcoex_restore_part1(btci);
	btci->vif = NULL;
}

/**
 * ifxf_btcoex_attach() - initialize BT coex data
 * @cfg: driver private cfg80211 data
 *
 * return: 0 on success
 */
int ifxf_btcoex_attach(struct ifxf_cfg80211_info *cfg)
{
	struct ifxf_btcoex_info *btci = NULL;
	ifxf_dbg(TRACE, "enter\n");

	btci = kmalloc(sizeof(struct ifxf_btcoex_info), GFP_KERNEL);
	if (!btci)
		return -ENOMEM;

	btci->bt_state = IFXF_BT_DHCP_IDLE;

	/* Set up timer for BT  */
	btci->timer_on = false;
	btci->timeout = IFXF_BTCOEX_OPPR_WIN_TIME;
	timer_setup(&btci->timer, ifxf_btcoex_timerfunc, 0);
	btci->cfg = cfg;
	btci->saved_regs_part1 = false;
	btci->saved_regs_part2 = false;

	INIT_WORK(&btci->work, ifxf_btcoex_handler);

	cfg->btcoex = btci;
	return 0;
}

/**
 * ifxf_btcoex_detach - clean BT coex data
 * @cfg: driver private cfg80211 data
 */
void ifxf_btcoex_detach(struct ifxf_cfg80211_info *cfg)
{
	ifxf_dbg(TRACE, "enter\n");

	if (!cfg->btcoex)
		return;

	if (cfg->btcoex->timer_on) {
		cfg->btcoex->timer_on = false;
		del_timer_sync(&cfg->btcoex->timer);
	}

	cancel_work_sync(&cfg->btcoex->work);

	ifxf_btcoex_boost_wifi(cfg->btcoex, false);
	ifxf_btcoex_restore_part1(cfg->btcoex);

	kfree(cfg->btcoex);
	cfg->btcoex = NULL;
}

static void ifxf_btcoex_dhcp_start(struct ifxf_btcoex_info *btci)
{
	struct ifxf_if *ifp = btci->vif->ifp;

	btcmf_btcoex_save_part1(btci);
	/* set new regs values */
	ifxf_btcoex_params_write(ifp, 66, IFXF_BT_DHCP_REG66);
	ifxf_btcoex_params_write(ifp, 41, IFXF_BT_DHCP_REG41);
	ifxf_btcoex_params_write(ifp, 68, IFXF_BT_DHCP_REG68);
	btci->dhcp_done = false;
	btci->bt_state = IFXF_BT_DHCP_START;
	schedule_work(&btci->work);
	ifxf_dbg(TRACE, "enable BT DHCP Timer\n");
}

static void ifxf_btcoex_dhcp_end(struct ifxf_btcoex_info *btci)
{
	/* Stop any bt timer because DHCP session is done */
	btci->dhcp_done = true;
	if (btci->timer_on) {
		ifxf_dbg(INFO, "disable BT DHCP Timer\n");
		btci->timer_on = false;
		del_timer_sync(&btci->timer);

		/* schedule worker if transition to IDLE is needed */
		if (btci->bt_state != IFXF_BT_DHCP_IDLE) {
			ifxf_dbg(INFO, "bt_state:%d\n",
				  btci->bt_state);
			schedule_work(&btci->work);
		}
	} else {
		/* Restore original values */
		ifxf_btcoex_restore_part1(btci);
	}
}

/*
 * ifxf_btcoex_set_mode - set BT coex mode
 * @mode: Wifi-Bluetooth coexistence mode
 *
 * return: 0 on success
 */
int ifxf_btcoex_set_mode(struct ifxf_cfg80211_vif *vif,
			  enum ifxf_btcoex_mode mode, u16 duration)
{
	struct ifxf_cfg80211_info *cfg = wiphy_to_cfg(vif->wdev.wiphy);
	struct ifxf_btcoex_info *btci = cfg->btcoex;
	struct ifxf_if *ifp = ifxf_get_ifp(cfg->pub, 0);

	switch (mode) {
	case IFXF_BTCOEX_DISABLED:
		ifxf_dbg(INFO, "DHCP session starts\n");
		if (btci->bt_state != IFXF_BT_DHCP_IDLE)
			return -EBUSY;
		/* Start BT timer only for SCO connection */
		if (ifxf_btcoex_is_sco_active(ifp)) {
			btci->timeout = msecs_to_jiffies(duration);
			btci->vif = vif;
			ifxf_btcoex_dhcp_start(btci);
		}
		break;

	case IFXF_BTCOEX_ENABLED:
		ifxf_dbg(INFO, "DHCP session ends\n");
		if (btci->bt_state != IFXF_BT_DHCP_IDLE &&
		    vif == btci->vif) {
			ifxf_btcoex_dhcp_end(btci);
		}
		break;
	default:
		ifxf_dbg(INFO, "Unknown mode, ignored\n");
	}
	return 0;
}
