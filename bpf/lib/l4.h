/* SPDX-License-Identifier: GPL-2.0 */
#pragma once

#include "common.h"

#ifndef IP_MF
#define IP_MF 0x2000
#define IP_OFFSET 0x1FFF
#endif

/* What NAT needs to know about an IPv4 packet's transport header. */
struct l4 {
	__u8 proto;
	__u8 is_echo;   /* ICMP echo request/reply: "ports" are the identifier */
	__u16 csum_off; /* absolute offset of the L4 checksum */
	__u32 off;      /* absolute offset of the L4 header */
	__be16 sport;
	__be16 dport;
};

/* parse_l4 fills l for TCP, UDP and ICMP echo packets that aren't
 * fragments. Returns false for anything NAT can't handle.
 */
static __always_inline bool parse_l4(struct __sk_buff *skb, struct iphdr *ip, struct l4 *l)
{
	if (ip->frag_off & bpf_htons(IP_MF | IP_OFFSET))
		return false;
	__u32 ihl = ip->ihl & 0xF;
	if (ihl < 5)
		return false;
	l->off = ETH_HLEN + ihl * 4;
	l->proto = ip->protocol;
	l->is_echo = 0;

	switch (ip->protocol) {
	case IPPROTO_TCP:
	case IPPROTO_UDP: {
		__be16 ports[2];
		if (bpf_skb_load_bytes(skb, l->off, ports, sizeof(ports)) < 0)
			return false;
		l->sport = ports[0];
		l->dport = ports[1];
		l->csum_off = l->off + (ip->protocol == IPPROTO_TCP ?
					__builtin_offsetof(struct tcphdr, check) :
					__builtin_offsetof(struct udphdr, check));
		return true;
	}
	case IPPROTO_ICMP: {
		struct icmp_echo ic;
		if (bpf_skb_load_bytes(skb, l->off, &ic, sizeof(ic)) < 0)
			return false;
		if (ic.type != ICMP_ECHO && ic.type != ICMP_ECHOREPLY)
			return false;
		l->is_echo = 1;
		l->sport = ic.id;
		l->dport = ic.id;
		l->csum_off = l->off + __builtin_offsetof(struct icmp_echo, checksum);
		return true;
	}
	git add -A && git commit -F .git/NETKER_M3_COMMIT_MSG}
	return false;
}

static __always_inline __u64 l4_csum_flags(const struct l4 *l)
{
	return l->proto == IPPROTO_UDP ? BPF_F_MARK_MANGLED_0 : 0;
}

/* rewrite_addr replaces the source (src=true) or destination IPv4 address
 * and fixes the IP and, for TCP/UDP, the pseudo-header checksum.
 */
static __always_inline int rewrite_addr(struct __sk_buff *skb, const struct l4 *l,
					bool src, __be32 old, __be32 new)
{
	if (old == new)
		return 0;
	if (!l->is_echo &&
	    bpf_l4_csum_replace(skb, l->csum_off, old, new,
				BPF_F_PSEUDO_HDR | sizeof(new) | l4_csum_flags(l)) < 0)
		return -1;
	if (bpf_l3_csum_replace(skb, IP_CSUM_OFF, old, new, sizeof(new)) < 0)
		return -1;
	return bpf_skb_store_bytes(skb, src ? IP_SADDR_OFF : IP_DADDR_OFF, &new, sizeof(new), 0);
}

/* rewrite_port replaces the source or destination port (the identifier for
 * ICMP echo) and fixes the L4 checksum.
 */
static __always_inline int rewrite_port(struct __sk_buff *skb, const struct l4 *l,
					bool src, __be16 old, __be16 new)
{
	__u32 off;

	if (old == new)
		return 0;
	if (l->is_echo)
		off = l->off + __builtin_offsetof(struct icmp_echo, id);
	else
		off = l->off + (src ? 0 : sizeof(__be16));
	if (bpf_l4_csum_replace(skb, l->csum_off, old, new, sizeof(new) | l4_csum_flags(l)) < 0)
		return -1;
	return bpf_skb_store_bytes(skb, off, &new, sizeof(new), 0);
}

/* dec_ttl decrements the TTL like a router. Returns -1 if the packet must go
 * to the stack instead (TTL expiring: the kernel sends ICMP time exceeded).
 */
static __always_inline int dec_ttl(struct __sk_buff *skb)
{
	__u8 ttl;

	if (bpf_skb_load_bytes(skb, IP_TTL_OFF, &ttl, 1) < 0 || ttl <= 1)
		return -1;
	/* TTL and protocol share one 16-bit checksum word; TTL is the high byte. */
	__be16 old = bpf_htons((__u16)ttl << 8);
	__be16 new = bpf_htons((__u16)(ttl - 1) << 8);
	__u8 new_ttl = ttl - 1;

	if (bpf_l3_csum_replace(skb, IP_CSUM_OFF, old, new, sizeof(new)) < 0)
		return -1;
	return bpf_skb_store_bytes(skb, IP_TTL_OFF, &new_ttl, 1, 0);
}
