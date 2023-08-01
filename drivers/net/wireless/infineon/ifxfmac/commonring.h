// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2014 Broadcom Corporation
 */
#ifndef IFXFMAC_COMMONRING_H
#define IFXFMAC_COMMONRING_H


struct ifxf_commonring {
	u16 r_ptr;
	u16 w_ptr;
	u16 f_ptr;
	u16 depth;
	u16 item_len;

	void *buf_addr;

	int (*cr_ring_bell)(void *ctx);
	int (*cr_update_rptr)(void *ctx);
	int (*cr_update_wptr)(void *ctx);
	int (*cr_write_rptr)(void *ctx);
	int (*cr_write_wptr)(void *ctx);

	void *cr_ctx;

	spinlock_t lock;
	unsigned long flags;
	bool inited;
	bool was_full;

	atomic_t outstanding_tx;
};


void ifxf_commonring_register_cb(struct ifxf_commonring *commonring,
				  int (*cr_ring_bell)(void *ctx),
				  int (*cr_update_rptr)(void *ctx),
				  int (*cr_update_wptr)(void *ctx),
				  int (*cr_write_rptr)(void *ctx),
				  int (*cr_write_wptr)(void *ctx), void *ctx);
void ifxf_commonring_config(struct ifxf_commonring *commonring, u16 depth,
			     u16 item_len, void *buf_addr);
void ifxf_commonring_lock(struct ifxf_commonring *commonring);
void ifxf_commonring_unlock(struct ifxf_commonring *commonring);
bool ifxf_commonring_write_available(struct ifxf_commonring *commonring);
void *ifxf_commonring_reserve_for_write(struct ifxf_commonring *commonring);
void *
ifxf_commonring_reserve_for_write_multiple(struct ifxf_commonring *commonring,
					    u16 n_items, u16 *alloced);
int ifxf_commonring_write_complete(struct ifxf_commonring *commonring);
void ifxf_commonring_write_cancel(struct ifxf_commonring *commonring,
				   u16 n_items);
void *ifxf_commonring_get_read_ptr(struct ifxf_commonring *commonring,
				    u16 *n_items);
int ifxf_commonring_read_complete(struct ifxf_commonring *commonring,
				   u16 n_items);

#define ifxf_commonring_n_items(commonring) (commonring->depth)
#define ifxf_commonring_len_item(commonring) (commonring->item_len)


#endif /* IFXFMAC_COMMONRING_H */
