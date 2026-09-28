/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2026 Gaspare Iengo <gaspare@katapy.com>. All Rights Reserved.
 */

#ifndef _WG_ALLOWEDROUTES_H
#define _WG_ALLOWEDROUTES_H

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/list.h>
#include <linux/mutex.h>

struct wg_peer;

enum wg_allowedroute_action {
	WG_ALLOWEDROUTE_ACTION_ALLOW = 1,
	WG_ALLOWEDROUTE_ACTION_DENY = 2,
};

struct allowedroute {
	struct list_head peer_list;
	struct rcu_head rcu;
	u16 src_family;
	u16 dst_family;
	u8 src_cidr;
	u8 dst_cidr;
	u8 action;
	u8 src[16];
	u8 dst[16];
};

struct allowedroutes {
	u64 seq;
};

void wg_allowedroutes_init(struct allowedroutes *table);
void wg_allowedroutes_free(struct allowedroutes *table);
int wg_allowedroutes_insert_v4(struct allowedroutes *table, struct wg_peer *peer,
				       const struct in_addr *src, u8 src_cidr,
				       const struct in_addr *dst, u8 dst_cidr,
				       u8 action, struct mutex *lock);
int wg_allowedroutes_insert_v6(struct allowedroutes *table, struct wg_peer *peer,
				       const struct in6_addr *src, u8 src_cidr,
				       const struct in6_addr *dst, u8 dst_cidr,
				       u8 action, struct mutex *lock);
int wg_allowedroutes_remove_v4(struct allowedroutes *table, struct wg_peer *peer,
				       const struct in_addr *src, u8 src_cidr,
				       const struct in_addr *dst, u8 dst_cidr,
				       u8 action, struct mutex *lock);
int wg_allowedroutes_remove_v6(struct allowedroutes *table, struct wg_peer *peer,
				       const struct in6_addr *src, u8 src_cidr,
				       const struct in6_addr *dst, u8 dst_cidr,
				       u8 action, struct mutex *lock);
void wg_allowedroutes_remove_by_peer(struct allowedroutes *table,
				     struct wg_peer *peer, struct mutex *lock);
bool wg_allowedroutes_check(struct wg_peer *peer, struct sk_buff *skb);
int wg_allowedroutes_read_rule(struct allowedroute *rule, u8 src[16], u8 *src_cidr,
			       int *src_family, u8 dst[16], u8 *dst_cidr,
			       int *dst_family, u8 *action);

int __init wg_allowedroutes_slab_init(void);
void wg_allowedroutes_slab_uninit(void);

#endif /* _WG_ALLOWEDROUTES_H */