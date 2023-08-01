// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2010 Broadcom Corporation
 */

#ifndef IFXFMAC_DEBUG_H
#define IFXFMAC_DEBUG_H

#include <linux/net.h>	/* net_ratelimit() */

/* message levels */
#define IFXF_TRACE_VAL		0x00000002
#define IFXF_INFO_VAL		0x00000004
#define IFXF_DATA_VAL		0x00000008
#define IFXF_CTL_VAL		0x00000010
#define IFXF_TIMER_VAL		0x00000020
#define IFXF_HDRS_VAL		0x00000040
#define IFXF_BYTES_VAL		0x00000080
#define IFXF_INTR_VAL		0x00000100
#define IFXF_GLOM_VAL		0x00000200
#define IFXF_EVENT_VAL		0x00000400
#define IFXF_BTA_VAL		0x00000800
#define IFXF_FIL_VAL		0x00001000
#define IFXF_USB_VAL		0x00002000
#define IFXF_SCAN_VAL		0x00004000
#define IFXF_CONN_VAL		0x00008000
#define IFXF_BCDC_VAL		0x00010000
#define IFXF_SDIO_VAL		0x00020000
#define IFXF_MSGBUF_VAL	0x00040000
#define IFXF_PCIE_VAL		0x00080000
#define IFXF_FWCON_VAL		0x00100000
#define IFXF_ULP_VAL		0x00200000
#define IFXF_TWT_VAL		0x00400000

/* set default print format */
#undef pr_fmt
#define pr_fmt(fmt)		KBUILD_MODNAME ": " fmt

struct ifxf_bus;

__printf(3, 4)
void __ifxf_err(struct ifxf_bus *bus, const char *func, const char *fmt, ...);
/* Macro for error messages. When debugging / tracing the driver all error
 * messages are important to us.
 */
#ifndef ifxf_err
#define ifxf_err(fmt, ...)						\
	do {								\
		if (IS_ENABLED(CONFIG_IFXDBG) ||			\
		    IS_ENABLED(CONFIG_IFX_TRACING) ||			\
		    net_ratelimit())					\
			__ifxf_err(NULL, __func__, fmt, ##__VA_ARGS__);\
	} while (0)
#endif

#define bphy_err(drvr, fmt, ...)					\
	do {								\
		if (IS_ENABLED(CONFIG_IFXDBG) ||			\
		    IS_ENABLED(CONFIG_IFX_TRACING) ||			\
		    net_ratelimit())					\
			wiphy_err((drvr)->wiphy, "%s: " fmt, __func__,	\
				  ##__VA_ARGS__);			\
	} while (0)

#define bphy_info_once(drvr, fmt, ...)					\
	wiphy_info_once((drvr)->wiphy, "%s: " fmt, __func__,		\
			##__VA_ARGS__)

#if defined(DEBUG) || defined(CONFIG_IFX_TRACING)

/* For debug/tracing purposes treat info messages as errors */
// #define ifxf_info ifxf_err

#define ifxf_info(fmt, ...)						\
	do {								\
		pr_info("%s: " fmt, __func__, ##__VA_ARGS__);		\
	} while (0)

__printf(3, 4)
void __ifxf_dbg(u32 level, const char *func, const char *fmt, ...);
#define ifxf_dbg(level, fmt, ...)				\
do {								\
	__ifxf_dbg(IFXF_##level##_VAL, __func__,		\
		    fmt, ##__VA_ARGS__);			\
} while (0)
#define IFXF_DATA_ON()		(ifxf_msg_level & IFXF_DATA_VAL)
#define IFXF_CTL_ON()		(ifxf_msg_level & IFXF_CTL_VAL)
#define IFXF_HDRS_ON()		(ifxf_msg_level & IFXF_HDRS_VAL)
#define IFXF_BYTES_ON()	(ifxf_msg_level & IFXF_BYTES_VAL)
#define IFXF_GLOM_ON()		(ifxf_msg_level & IFXF_GLOM_VAL)
#define IFXF_EVENT_ON()	(ifxf_msg_level & IFXF_EVENT_VAL)
#define IFXF_FIL_ON()		(ifxf_msg_level & IFXF_FIL_VAL)
#define IFXF_FWCON_ON()	(ifxf_msg_level & IFXF_FWCON_VAL)
#define IFXF_SCAN_ON()		(ifxf_msg_level & IFXF_SCAN_VAL)

#else /* defined(DEBUG) || defined(CONFIG_IFX_TRACING) */

#define ifxf_info(fmt, ...)						\
	do {								\
		pr_info("%s: " fmt, __func__, ##__VA_ARGS__);		\
	} while (0)

#define ifxf_dbg(level, fmt, ...) no_printk(fmt, ##__VA_ARGS__)

#define IFXF_DATA_ON()		0
#define IFXF_CTL_ON()		0
#define IFXF_HDRS_ON()		0
#define IFXF_BYTES_ON()	0
#define IFXF_GLOM_ON()		0
#define IFXF_EVENT_ON()	0
#define IFXF_FIL_ON()		0
#define IFXF_FWCON_ON()	0
#define IFXF_SCAN_ON()		0

#endif /* defined(DEBUG) || defined(CONFIG_IFX_TRACING) */

#define MSGTRACE_VERSION 1
#define MSGTRACE_HDR_TYPE_MSG 0
#define MSGTRACE_HDR_TYPE_LOG 1

#define ifxf_dbg_hex_dump(test, data, len, fmt, ...)			\
do {									\
	trace_ifxf_hexdump((void *)data, len);				\
	if (test)							\
		ifxu_dbg_hex_dump(data, len, fmt, ##__VA_ARGS__);	\
} while (0)

extern int ifxf_msg_level;

struct ifxf_pub;
#ifdef DEBUG
struct dentry *ifxf_debugfs_get_devdir(struct ifxf_pub *drvr);
void ifxf_debugfs_add_entry(struct ifxf_pub *drvr, const char *fn,
			     int (*read_fn)(struct seq_file *seq, void *data));
int ifxf_debug_create_memdump(struct ifxf_bus *bus, const void *data,
			       size_t len);
int ifxf_debug_fwlog_init(struct ifxf_pub *drvr);
#else
static inline struct dentry *ifxf_debugfs_get_devdir(struct ifxf_pub *drvr)
{
	return ERR_PTR(-ENOENT);
}
static inline
void ifxf_debugfs_add_entry(struct ifxf_pub *drvr, const char *fn,
			     int (*read_fn)(struct seq_file *seq, void *data))
{ }
static inline
int ifxf_debug_create_memdump(struct ifxf_bus *bus, const void *data,
			       size_t len)
{
	return 0;
}

static inline
int ifxf_debug_fwlog_init(struct ifxf_pub *drvr)
{
	return 0;
}
#endif

/* Message trace header */
struct msgtrace_hdr {
	u8	version;
	u8	trace_type;
	u16	len;    /* Len of the trace */
	u32	seqnum; /* Sequence number of message */
	/* Number of discarded bytes because of trace overflow  */
	u32	discarded_bytes;
	/* Number of discarded printf because of trace overflow */
	u32	discarded_printf;
};

#define MSGTRACE_HDRLEN		sizeof(struct msgtrace_hdr)
#endif /* IFXFMAC_DEBUG_H */
