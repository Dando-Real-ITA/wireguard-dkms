// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026 Gaspare Iengo <gaspare@katapy.com>. All Rights Reserved.
 */

#ifdef DEBUG

#include <linux/skbuff.h>

static __init struct wg_peer *init_allowedroutes_peer(void)
{
	struct wg_peer *peer = kzalloc(sizeof(*peer), GFP_KERNEL);

	if (!peer)
		return NULL;
	INIT_LIST_HEAD(&peer->allowedroutes_list);
	return peer;
}

static __init struct sk_buff *init_skb4(__be32 saddr, __be32 daddr)
{
	struct sk_buff *skb = alloc_skb(sizeof(struct iphdr), GFP_KERNEL);
	struct iphdr *hdr;

	if (!skb)
		return NULL;
	skb->protocol = htons(ETH_P_IP);
	skb_reset_network_header(skb);
	hdr = skb_put_zero(skb, sizeof(*hdr));
	hdr->saddr = saddr;
	hdr->daddr = daddr;
	return skb;
}

static __init struct sk_buff *init_skb6(const struct in6_addr *saddr,
					const struct in6_addr *daddr)
{
	struct sk_buff *skb = alloc_skb(sizeof(struct ipv6hdr), GFP_KERNEL);
	struct ipv6hdr *hdr;

	if (!skb)
		return NULL;
	skb->protocol = htons(ETH_P_IPV6);
	skb_reset_network_header(skb);
	hdr = skb_put_zero(skb, sizeof(*hdr));
	hdr->saddr = *saddr;
	hdr->daddr = *daddr;
	return skb;
}

bool __init wg_allowedroutes_selftest(void)
{
	struct allowedroutes table;
	struct wg_peer *peer = init_allowedroutes_peer();
	struct sk_buff *skb4 = NULL, *skb6 = NULL;
	DEFINE_MUTEX(lock);
	struct in_addr src4 = { .s_addr = htonl(0x0a000001) };
	struct in_addr dst4 = { .s_addr = htonl(0xc0a80001) };
	struct in_addr src4_subnet = { .s_addr = htonl(0x0a000000) };
	struct in_addr dst4_subnet = { .s_addr = htonl(0xc0a80000) };
	struct in6_addr src6 = IN6ADDR_LOOPBACK_INIT;
	struct in6_addr dst6 = IN6ADDR_LOOPBACK_INIT;
	struct in6_addr src6_subnet = IN6ADDR_LOOPBACK_INIT;
	struct in6_addr dst6_subnet = IN6ADDR_LOOPBACK_INIT;
	struct allowedroute *first_rule;
	u8 action, src_cidr, dst_cidr, src_buf[16], dst_buf[16];
	int src_family, dst_family;
	bool success = false;

	if (!peer) {
		pr_err("allowedroutes self-test malloc: FAIL\n");
		return false;
	}

	wg_allowedroutes_init(&table);
	mutex_init(&lock);
	mutex_lock(&lock);

	skb4 = init_skb4(src4.s_addr, dst4.s_addr);
	if (!skb4)
		goto out;
	if (!wg_allowedroutes_check(peer, skb4)) {
		pr_err("allowedroutes self-test default allow ipv4: FAIL\n");
		goto out;
	}

	if (wg_allowedroutes_insert_v4(&table, peer, &src4_subnet, 24,
				      &dst4_subnet, 24,
				      WG_ALLOWEDROUTE_ACTION_DENY, &lock)) {
		pr_err("allowedroutes self-test insert deny ipv4: FAIL\n");
		goto out;
	}
	if (wg_allowedroutes_check(peer, skb4)) {
		pr_err("allowedroutes self-test deny ipv4: FAIL\n");
		goto out;
	}

	if (wg_allowedroutes_insert_v4(&table, peer, &src4, 32, &dst4, 32,
				      WG_ALLOWEDROUTE_ACTION_ALLOW, &lock)) {
		pr_err("allowedroutes self-test insert allow ipv4: FAIL\n");
		goto out;
	}
	if (wg_allowedroutes_check(peer, skb4)) {
		pr_err("allowedroutes self-test first match order ipv4: FAIL\n");
		goto out;
	}

	first_rule = list_first_entry(&peer->allowedroutes_list,
				      struct allowedroute, peer_list);
		if (wg_allowedroutes_read_rule(first_rule, src_buf, &src_cidr,
					      &src_family, dst_buf, &dst_cidr,
					      &dst_family, &action) ||
		    action != WG_ALLOWEDROUTE_ACTION_DENY ||
		    src_family != AF_INET || dst_family != AF_INET ||
		    src_cidr != 24 || dst_cidr != 24) {
		pr_err("allowedroutes self-test read first rule ipv4: FAIL\n");
		goto out;
	}

	if (wg_allowedroutes_remove_v4(&table, peer, &src4_subnet, 24,
				      &dst4_subnet, 24,
				      WG_ALLOWEDROUTE_ACTION_DENY, &lock)) {
		pr_err("allowedroutes self-test remove deny ipv4: FAIL\n");
		goto out;
	}
	if (!wg_allowedroutes_check(peer, skb4)) {
		pr_err("allowedroutes self-test allow after remove ipv4: FAIL\n");
		goto out;
	}

	if (wg_allowedroutes_remove_v4(&table, peer, &src4, 32, &dst4, 32,
				      WG_ALLOWEDROUTE_ACTION_ALLOW, &lock)) {
		pr_err("allowedroutes self-test remove allow ipv4: FAIL\n");
		goto out;
	}
	if (!wg_allowedroutes_check(peer, skb4)) {
		pr_err("allowedroutes self-test default allow after empty ipv4: FAIL\n");
		goto out;
	}

	src6.in6_u.u6_addr32[0] = htonl(0x20010db8);
	src6.in6_u.u6_addr32[3] = htonl(1);
	dst6.in6_u.u6_addr32[0] = htonl(0x20010db9);
	dst6.in6_u.u6_addr32[3] = htonl(1);
	src6_subnet = src6;
	src6_subnet.in6_u.u6_addr32[3] = 0;
	dst6_subnet = dst6;
	dst6_subnet.in6_u.u6_addr32[3] = 0;

	skb6 = init_skb6(&src6, &dst6);
	if (!skb6)
		goto out;
	if (!wg_allowedroutes_check(peer, skb6)) {
		pr_err("allowedroutes self-test default allow ipv6: FAIL\n");
		goto out;
	}
	if (wg_allowedroutes_insert_v6(&table, peer, &src6_subnet, 64,
				      &dst6_subnet, 64,
				      WG_ALLOWEDROUTE_ACTION_ALLOW, &lock)) {
		pr_err("allowedroutes self-test insert allow ipv6: FAIL\n");
		goto out;
	}
	if (!wg_allowedroutes_check(peer, skb6)) {
		pr_err("allowedroutes self-test allow ipv6: FAIL\n");
		goto out;
	}

	wg_allowedroutes_remove_by_peer(&table, peer, &lock);
	if (!wg_allowedroutes_check(peer, skb4) || !wg_allowedroutes_check(peer, skb6)) {
		pr_err("allowedroutes self-test remove_by_peer default allow: FAIL\n");
		goto out;
	}

	if (wg_allowedroutes_insert_v4(&table, peer, &src4, 33, &dst4, 32,
				      WG_ALLOWEDROUTE_ACTION_ALLOW, &lock) != -EINVAL) {
		pr_err("allowedroutes self-test invalid cidr: FAIL\n");
		goto out;
	}
	if (wg_allowedroutes_insert_v4(&table, peer, &src4, 32, &dst4, 32,
				      0, &lock) != -EINVAL) {
		pr_err("allowedroutes self-test invalid action: FAIL\n");
		goto out;
	}

	success = true;
	pr_info("allowedroutes self-tests: pass\n");

out:
	dev_kfree_skb(skb4);
	dev_kfree_skb(skb6);
	wg_allowedroutes_remove_by_peer(&table, peer, &lock);
	wg_allowedroutes_free(&table);
	mutex_unlock(&lock);
	kfree(peer);
	return success;
}

#endif