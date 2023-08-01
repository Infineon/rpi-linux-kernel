// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2013 Broadcom Corporation
 */
#ifndef IFXFMAC_FIRMWARE_H
#define IFXFMAC_FIRMWARE_H

#define IFXF_FW_REQF_OPTIONAL		0x0001

#define	IFXF_FW_NAME_LEN		320

#define IFXF_FW_MAX_BOARD_TYPES	8

#define CY_FW_DEFAULT_PATH		"cypress/"

/**
 * struct ifxf_firmware_mapping - Used to map chipid/revmask to firmware
 *	filename and nvram filename. Each bus type implementation should create
 *	a table of firmware mappings (using the macros defined below).
 *
 * @chipid: ID of chip.
 * @revmask: bitmask of revisions, e.g. 0x10 means rev 4 only, 0xf means rev 0-3
 * @fw: name of the firmware file.
 * @nvram: name of nvram file.
 */
struct ifxf_firmware_mapping {
	u32 chipid;
	u32 revmask;
	const char *fw_base;
};

/* Firmware and Country Local Matrix files */
#define CY_FW_DEF(fw_name, fw_base) \
static const char IFX_ ## fw_name ## _FIRMWARE_BASENAME[] = \
	CY_FW_DEFAULT_PATH fw_base; \
MODULE_FIRMWARE(CY_FW_DEFAULT_PATH fw_base ".bin")

#define CY_FW_TRXSE_DEF(fw_name, fw_base) \
static const char IFX_ ## fw_name ## _FIRMWARE_BASENAME[] = \
	CY_FW_DEFAULT_PATH fw_base; \
MODULE_FIRMWARE(CY_FW_DEFAULT_PATH fw_base ".trxse")

#define CYF_FW_ENTRY(chipid, mask, name) \
	{ chipid, mask, IFX_ ## name ## _FIRMWARE_BASENAME }

void ifxf_fw_nvram_free(void *nvram);

enum ifxf_fw_type {
	IFXF_FW_TYPE_BINARY,
	IFXF_FW_TYPE_NVRAM,
	IFXF_FW_TYPE_TRXSE
};

struct ifxf_fw_item {
	const char *path;
	enum ifxf_fw_type type;
	u16 flags;
	union {
		const struct firmware *binary;
		struct {
			void *data;
			u32 len;
		} nv_data;
	};
};

struct ifxf_fw_request {
	u16 domain_nr;
	u16 bus_nr;
	u32 n_items;
	const char *board_types[IFXF_FW_MAX_BOARD_TYPES];
	struct ifxf_fw_item items[];
};

struct ifxf_fw_name {
	const char *extension;
	char *path;
};

struct ifxf_fw_request *
ifxf_fw_alloc_request(u32 chip, u32 chiprev,
		       const struct ifxf_firmware_mapping mapping_table[],
		       u32 table_size, struct ifxf_fw_name *fwnames,
		       u32 n_fwnames);

/*
 * Request firmware(s) asynchronously. When the asynchronous request
 * fails it will not use the callback, but call device_release_driver()
 * instead which will call the driver .remove() callback.
 */
int ifxf_fw_get_firmwares(struct device *dev, struct ifxf_fw_request *req,
			   void (*fw_cb)(struct device *dev, int err,
					 struct ifxf_fw_request *req));

#endif /* IFXFMAC_FIRMWARE_H */
