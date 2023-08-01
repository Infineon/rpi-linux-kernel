// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2014 Broadcom Corporation
 */
#ifndef IFXF_CHIP_H
#define IFXF_CHIP_H

#include <linux/types.h>

#define CORE_CC_REG(base, field) \
		((base) + offsetof(struct chipcregs, field))

#define CORE_GCI_REG(base, field) \
		((base) + offsetof(struct chipgciregs, field))

struct ifxf_blhs;

/**
 * struct ifxf_chip - chip level information.
 *
 * @chip: chip identifier.
 * @chiprev: chip revision.
 * @enum_base: base address of core enumeration space.
 * @cc_caps: chipcommon core capabilities.
 * @cc_caps_ext: chipcommon core extended capabilities.
 * @pmucaps: PMU capabilities.
 * @pmurev: PMU revision.
 * @rambase: RAM base address (only applicable for ARM CR4 chips).
 * @ramsize: amount of RAM on chip including retention.
 * @srsize: amount of retention RAM on chip.
 * @name: string representation of the chip identifier.
 * @blhs: bootlooder handshake handle.
 */
struct ifxf_chip {
	u32 chip;
	u32 chiprev;
	u32 enum_base;
	u32 cc_caps;
	u32 cc_caps_ext;
	u32 pmucaps;
	u32 pmurev;
	u32 rambase;
	u32 ramsize;
	u32 srsize;
	char name[12];
	struct ifxf_blhs *blhs;
	struct ifxf_ccsec *ccsec;
};

/**
 * struct ifxf_core - core related information.
 *
 * @id: core identifier.
 * @rev: core revision.
 * @base: base address of core register space.
 */
struct ifxf_core {
	u16 id;
	u16 rev;
	u32 base;
};

/**
 * struct ifxf_buscore_ops - buscore specific callbacks.
 *
 * @read32: read 32-bit value over bus.
 * @write32: write 32-bit value over bus.
 * @prepare: prepare bus for core configuration.
 * @setup: bus-specific core setup.
 * @active: chip becomes active.
 *	The callback should use the provided @rstvec when non-zero.
 * @blhs_attach: attach bootloader handshake handle
 */
struct ifxf_buscore_ops {
	u32 (*read32)(void *ctx, u32 addr);
	void (*write32)(void *ctx, u32 addr, u32 value);
	int (*prepare)(void *ctx);
	int (*reset)(void *ctx, struct ifxf_chip *chip);
	int (*setup)(void *ctx, struct ifxf_chip *chip);
	void (*activate)(void *ctx, struct ifxf_chip *chip, u32 rstvec);
	int (*sec_attach)(void *ctx, struct ifxf_blhs **blhs, struct ifxf_ccsec **ccsec,
			  u32 flag, uint timeout, uint interval);
};

/**
 * struct ifxf_blhs - bootloader handshake handle related information.
 *
 * @d2h: offset of dongle to host register for the handshake.
 * @h2d: offset of host to dongle register for the handshake.
 * @init: bootloader handshake initialization.
 * @prep_fwdl: handshake before firmware download.
 * @post_fwdl: handshake after firmware download.
 * @post_nvramdl: handshake after nvram download.
 * @chk_validation: handshake for firmware validation check.
 * @post_wdreset: handshake after watchdog reset.
 * @read: read value with register offset for the handshake.
 * @write: write value with register offset for the handshake.
 */
struct ifxf_blhs {
	u32 d2h;
	u32 h2d;
	void (*init)(struct ifxf_chip *pub);
	int (*prep_fwdl)(struct ifxf_chip *pub);
	int (*post_fwdl)(struct ifxf_chip *pub);
	void (*post_nvramdl)(struct ifxf_chip *pub);
	int (*chk_validation)(struct ifxf_chip *pub);
	int (*post_wdreset)(struct ifxf_chip *pub);
	u32 (*read)(void *ctx, u32 addr);
	void (*write)(void *ctx, u32 addr, u32 value);
};

struct ifxf_ccsec {
	u32	bus_corebase;
	u32 erombase;
	u32 chipid;
};

int ifxf_chip_get_raminfo(struct ifxf_chip *pub);
struct ifxf_chip *ifxf_chip_attach(void *ctx, u16 devid,
				     const struct ifxf_buscore_ops *ops);
void ifxf_chip_detach(struct ifxf_chip *chip);
struct ifxf_core *ifxf_chip_get_core(struct ifxf_chip *chip, u16 coreid);
struct ifxf_core *ifxf_chip_get_d11core(struct ifxf_chip *pub, u8 unit);
struct ifxf_core *ifxf_chip_get_chipcommon(struct ifxf_chip *chip);
struct ifxf_core *ifxf_chip_get_pmu(struct ifxf_chip *pub);
bool ifxf_chip_iscoreup(struct ifxf_core *core);
void ifxf_chip_coredisable(struct ifxf_core *core, u32 prereset, u32 reset);
void ifxf_chip_resetcore(struct ifxf_core *core, u32 prereset, u32 reset,
			  u32 postreset);
void ifxf_chip_set_passive(struct ifxf_chip *ci);
bool ifxf_chip_set_active(struct ifxf_chip *ci, u32 rstvec);
bool ifxf_chip_sr_capable(struct ifxf_chip *pub);
char *ifxf_chip_name(u32 chipid, u32 chiprev, char *buf, uint len);
u32 ifxf_chip_enum_base(u16 devid);
void ifxf_chip_reset_watchdog(struct ifxf_chip *pub);
void ifxf_chip_ulp_reset_lhl_regs(struct ifxf_chip *pub);
void ifxf_chip_reset_pmu_regs(struct ifxf_chip *pub);
void ifxf_chip_set_default_min_res_mask(struct ifxf_chip *pub);

#endif /* IFXF_AXIDMP_H */
