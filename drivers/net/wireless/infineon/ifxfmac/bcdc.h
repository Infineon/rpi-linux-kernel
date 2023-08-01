// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2013 Broadcom Corporation
 */
#ifndef IFXFMAC_BCDC_H
#define IFXFMAC_BCDC_H

#ifdef CONFIG_IFXFMAC_PROTO_BCDC
int ifxf_proto_bcdc_attach(struct ifxf_pub *drvr);
void ifxf_proto_bcdc_detach(struct ifxf_pub *drvr);
void ifxf_proto_bcdc_txflowblock(struct device *dev, bool state);
void ifxf_proto_bcdc_txcomplete(struct device *dev, struct sk_buff *txp,
				 bool success);
struct ifxf_fws_info *drvr_to_fws(struct ifxf_pub *drvr);
#else
static inline int ifxf_proto_bcdc_attach(struct ifxf_pub *drvr) { return 0; }
static inline void ifxf_proto_bcdc_detach(struct ifxf_pub *drvr) {}
#endif

#endif /* IFXFMAC_BCDC_H */
