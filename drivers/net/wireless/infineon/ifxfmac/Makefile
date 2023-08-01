# SPDX-License-Identifier: ISC
#
# Makefile fragment for Broadcom 802.11 Networking Device Driver
#
# Copyright (c) 2010 Broadcom Corporation
#

subdir-ccflags-y += -DBCM_TAG_STR=\"$(shell git describe --abbrev=4 --dirty --always --tags)\"
subdir-ccflags-y += -DBCM_SHAID_STR=\"$(shell git rev-parse --short HEAD)\"

ccflags-y += \
	-I $(srctree)/$(src) \
	-I $(srctree)/$(src)/../include

obj-$(CONFIG_IFXFMAC) += ifxfmac.o
ifxfmac-objs += \
		cfg80211.o \
		chip.o \
		fwil.o \
		fweh.o \
		p2p.o \
		proto.o \
		common.o \
		core.o \
		firmware.o \
		feature.o \
		btcoex.o \
		vendor.o \
		pno.o \
		xtlv.o \
		vendor_ifx.o \
		twt.o
ifxfmac-$(CONFIG_IFXFMAC_PROTO_BCDC) += \
		bcdc.o \
		fwsignal.o
ifxfmac-$(CONFIG_IFXFMAC_PROTO_MSGBUF) += \
		commonring.o \
		flowring.o \
		msgbuf.o
ifxfmac-$(CONFIG_IFXFMAC_SDIO) += \
		sdio.o \
		ifxsdh.o
ifxfmac-$(CONFIG_IFXFMAC_USB) += \
		usb.o
ifxfmac-$(CONFIG_IFXFMAC_PCIE) += \
		pcie.o
ifxfmac-$(CONFIG_IFXDBG) += \
		debug.o
ifxfmac-$(CONFIG_IFX_TRACING) += \
		tracepoint.o
ifxfmac-$(CONFIG_OF) += \
		of.o
ifxfmac-$(CONFIG_DMI) += \
		dmi.o
ifxfmac-${CONFIG_IFXFMAC_BT_SHARED_SDIO} += \
		bt_shared_sdio.o
