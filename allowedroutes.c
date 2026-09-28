// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026 Gaspare Iengo <gaspare@katapy.com>. All Rights Reserved.
 */

#include "allowedroutes.h"
#include "peer.h"

static struct kmem_cache *allowedroute_cache;

static bool valid_action(u8 action)
{
	return action == WG_ALLOWEDROUTE_ACTION_ALLOW ||
	       action == WG_ALLOWEDROUTE_ACTION_DENY;
}

static bool prefix_match(const u8 *addr, const u8 *prefix, u8 cidr, u8 size)
{
	u8 bytes = cidr / 8U;
	u8 rem = cidr % 8U;

	if (bytes > size)
		return false;
	if (bytes && memcmp(addr, prefix, bytes))
		return false;
	if (!rem || bytes == size)
		return true;
	return (addr[bytes] & (~0U << (8U - rem))) ==
	       (prefix[bytes] & (~0U << (8U - rem)));
}

static bool allowedroute_match(const struct allowedroute *rule, int family,
			       const u8 *src, const u8 *dst, u8 size)
{
	return rule->src_family == family && rule->dst_family == family &&
	       prefix_match(src, rule->src, rule->src_cidr, size) &&
	       prefix_match(dst, rule->dst, rule->dst_cidr, size);
}

static int add(struct allowedroutes *table, struct wg_peer *peer,
	       int family, const void *src, u8 src_cidr, const void *dst,
	       u8 dst_cidr, u8 action)
{
	struct allowedroute *rule;
	u8 size;

	if (!peer || !valid_action(action))
		return -EINVAL;
	if (family == AF_INET) {
		if (src_cidr > 32 || dst_cidr > 32)
			return -EINVAL;
		size = sizeof(struct in_addr);
	} else if (family == AF_INET6) {
		if (src_cidr > 128 || dst_cidr > 128)
			return -EINVAL;
		size = sizeof(struct in6_addr);
	} else {
		return -EINVAL;
	}

	rule = kmem_cache_zalloc(allowedroute_cache, GFP_KERNEL);
	if (!rule)
		return -ENOMEM;
	INIT_LIST_HEAD(&rule->peer_list);
	rule->src_family = family;
	rule->dst_family = family;
	rule->src_cidr = src_cidr;
	rule->dst_cidr = dst_cidr;
	rule->action = action;
	memcpy(rule->src, src, size);
	memcpy(rule->dst, dst, size);
	list_add_tail_rcu(&rule->peer_list, &peer->allowedroutes_list);
	++table->seq;
	return 0;
}

static int remove(struct allowedroutes *table, struct wg_peer *peer,
		  int family, const void *src, u8 src_cidr, const void *dst,
		  u8 dst_cidr, u8 action)
{
	struct allowedroute *rule;
	u8 size;

	if (!peer || !valid_action(action))
		return -EINVAL;
	if (family == AF_INET) {
		if (src_cidr > 32 || dst_cidr > 32)
			return -EINVAL;
		size = sizeof(struct in_addr);
	} else if (family == AF_INET6) {
		if (src_cidr > 128 || dst_cidr > 128)
			return -EINVAL;
		size = sizeof(struct in6_addr);
	} else {
		return -EINVAL;
	}

	list_for_each_entry(rule, &peer->allowedroutes_list, peer_list) {
		if (rule->src_family != family || rule->dst_family != family ||
		    rule->src_cidr != src_cidr || rule->dst_cidr != dst_cidr ||
		    rule->action != action)
			continue;
		if (memcmp(rule->src, src, size) || memcmp(rule->dst, dst, size))
			continue;
		list_del_rcu(&rule->peer_list);
		kfree_rcu(rule, rcu);
		++table->seq;
		break;
	}
	return 0;
}

void wg_allowedroutes_init(struct allowedroutes *table)
{
	table->seq = 1;
}

void wg_allowedroutes_free(struct allowedroutes *table)
{
	++table->seq;
}

int wg_allowedroutes_insert_v4(struct allowedroutes *table, struct wg_peer *peer,
				       const struct in_addr *src, u8 src_cidr,
				       const struct in_addr *dst, u8 dst_cidr,
				       u8 action, struct mutex *lock)
{
	lockdep_assert_held(lock);
	return add(table, peer, AF_INET, src, src_cidr, dst, dst_cidr, action);
}

int wg_allowedroutes_insert_v6(struct allowedroutes *table, struct wg_peer *peer,
				       const struct in6_addr *src, u8 src_cidr,
				       const struct in6_addr *dst, u8 dst_cidr,
				       u8 action, struct mutex *lock)
{
	lockdep_assert_held(lock);
	return add(table, peer, AF_INET6, src, src_cidr, dst, dst_cidr, action);
}

int wg_allowedroutes_remove_v4(struct allowedroutes *table, struct wg_peer *peer,
				       const struct in_addr *src, u8 src_cidr,
				       const struct in_addr *dst, u8 dst_cidr,
				       u8 action, struct mutex *lock)
{
	lockdep_assert_held(lock);
	return remove(table, peer, AF_INET, src, src_cidr, dst, dst_cidr, action);
}

int wg_allowedroutes_remove_v6(struct allowedroutes *table, struct wg_peer *peer,
				       const struct in6_addr *src, u8 src_cidr,
				       const struct in6_addr *dst, u8 dst_cidr,
				       u8 action, struct mutex *lock)
{
	lockdep_assert_held(lock);
	return remove(table, peer, AF_INET6, src, src_cidr, dst, dst_cidr, action);
}

void wg_allowedroutes_remove_by_peer(struct allowedroutes *table,
				     struct wg_peer *peer, struct mutex *lock)
{
	struct allowedroute *rule, *tmp;

	lockdep_assert_held(lock);
	list_for_each_entry_safe(rule, tmp, &peer->allowedroutes_list, peer_list) {
		list_del_rcu(&rule->peer_list);
		kfree_rcu(rule, rcu);
		++table->seq;
	}
}

bool wg_allowedroutes_check(struct wg_peer *peer, struct sk_buff *skb)
{
	struct allowedroute *rule;
	const u8 *src;
	const u8 *dst;
	int family;
	u8 size;

	if (list_empty(&peer->allowedroutes_list))
		return true;
	if (skb->protocol == htons(ETH_P_IP)) {
		family = AF_INET;
		src = (const u8 *)&ip_hdr(skb)->saddr;
		dst = (const u8 *)&ip_hdr(skb)->daddr;
		size = sizeof(struct in_addr);
	} else if (skb->protocol == htons(ETH_P_IPV6)) {
		family = AF_INET6;
		src = (const u8 *)&ipv6_hdr(skb)->saddr;
		dst = (const u8 *)&ipv6_hdr(skb)->daddr;
		size = sizeof(struct in6_addr);
	} else {
		return false;
	}

	rcu_read_lock_bh();
	list_for_each_entry_rcu(rule, &peer->allowedroutes_list, peer_list) {
		if (!allowedroute_match(rule, family, src, dst, size))
			continue;
		rcu_read_unlock_bh();
		return rule->action == WG_ALLOWEDROUTE_ACTION_ALLOW;
	}
	rcu_read_unlock_bh();
	return false;
}

int wg_allowedroutes_read_rule(struct allowedroute *rule, u8 src[16], u8 *src_cidr,
			       int *src_family, u8 dst[16], u8 *dst_cidr,
			       int *dst_family, u8 *action)
{
	u8 src_size;
	u8 dst_size;

	if (rule->src_family == AF_INET)
		src_size = sizeof(struct in_addr);
	else if (rule->src_family == AF_INET6)
		src_size = sizeof(struct in6_addr);
	else
		return -EINVAL;

	if (rule->dst_family == AF_INET)
		dst_size = sizeof(struct in_addr);
	else if (rule->dst_family == AF_INET6)
		dst_size = sizeof(struct in6_addr);
	else
		return -EINVAL;

	memcpy(src, rule->src, src_size);
	memcpy(dst, rule->dst, dst_size);
	*src_cidr = rule->src_cidr;
	*dst_cidr = rule->dst_cidr;
	*src_family = rule->src_family;
	*dst_family = rule->dst_family;
	*action = rule->action;
	return 0;
}

int __init wg_allowedroutes_slab_init(void)
{
	allowedroute_cache = KMEM_CACHE(allowedroute, 0);
	return allowedroute_cache ? 0 : -ENOMEM;
}

void wg_allowedroutes_slab_uninit(void)
{
	rcu_barrier();
	kmem_cache_destroy(allowedroute_cache);
}