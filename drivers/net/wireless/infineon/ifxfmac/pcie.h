// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2014 Broadcom Corporation
 */
#ifndef IFXFMAC_PCIE_H
#define IFXFMAC_PCIE_H


struct ifxf_pciedev {
	struct ifxf_bus *bus;
	struct ifxf_pciedev_info *devinfo;
};

void ifxf_pcie_handle_mb_data(struct ifxf_bus *bus_if, u32 d2h_mb_data);

#endif /* IFXFMAC_PCIE_H */
