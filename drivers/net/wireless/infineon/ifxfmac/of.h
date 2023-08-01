// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2014 Broadcom Corporation
 */
#ifdef CONFIG_OF
void ifxf_of_probe(struct device *dev, enum ifxf_bus_type bus_type,
		    struct ifxf_mp_device *settings);
struct ifxf_firmware_mapping *
ifxf_of_fwnames(struct device *dev, u32 *map_count);
#else
static void ifxf_of_probe(struct device *dev, enum ifxf_bus_type bus_type,
			   struct ifxf_mp_device *settings)
{
}
static struct ifxf_firmware_mapping *
ifxf_of_fwnames(struct device *dev, u32 *map_count)
{
	return NULL;
}
#endif /* CONFIG_OF */
