/* SPDX-License-Identifier: GPL-2.0 */
#pragma once

#include "maps.h"
#include "l4.h"
#include "nat.h"

static __always_inline bool addr6_eq(const __u8 *a, const __u8 *b)
{
	for (int i = 0; i < 16; i++)
		if (a[i] != b[i])
			return false;
	return true;
}

static __always_inline bool addr6_is_zero(const __u8 *a)
{
	for (int i = 0; i < 16; i++)
		if (a[i])
			return false;
	return true;
}

#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif
#define ICMPV6_ECHO_REQUEST 128
#define ICMPV6_ECHO_REPLY 129

#define IP6_SADDR_OFF (ETH_HLEN + __builtin_offsetof(struct ipv6hdr, saddr))
#define IP6_DADDR_OFF (ETH_HLEN + __builtin_offsetof(struct ipv6hdr, daddr))

/* parse_l4_6 is parse_l4 for IPv6: TCP, UDP and ICMPv6 echo directly after
 * the fixed header. Extension headers aren't followed, so such packets
 * aren't translated in BPF.
 */
static __always_inline bool parse_l4_6(struct __sk_buff *skb, struct ipv6hdr *ip6, struct l4 *l)
{
	l->off = ETH_HLEN + sizeof(struct ipv6hdr);
	l->proto = ip6->nexthdr;
	l->is_echo = 0;

	switch (ip6->nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP: {
		__be16 ports[2];

		if (bpf_skb_load_bytes(skb, l->off, ports, sizeof(ports)) < 0)
			return false;
		l->sport = ports[0];
		l->dport = ports[1];
		l->csum_off = l->off + (ip6->nexthdr == IPPROTO_TCP ?
					__builtin_offsetof(struct tcphdr, check) :
					__builtin_offsetof(struct udphdr, check));
		return true;
	}
	case IPPROTO_ICMPV6: {
		struct icmp_echo ic;

		if (bpf_skb_load_bytes(skb, l->off, &ic, sizeof(ic)) < 0)
			return false;
		if (ic.type != ICMPV6_ECHO_REQUEST && ic.type != ICMPV6_ECHO_REPLY)
			return false;
		l->is_echo = 1;
		l->sport = ic.id;
		l->dport = ic.id;
		l->csum_off = l->off + __builtin_offsetof(struct icmp_echo, checksum);
		return true;
	}
	}
	return false;
}

/* rewrite_addr6 replaces the source or destination address. IPv6 has no
 * header checksum, but TCP, UDP and ICMPv6 all cover the addresses in their
 * pseudo-header.
 */
static __always_inline int rewrite_addr6(struct __sk_buff *skb, const struct l4 *l, bool src,
					 const __u8 *old, const __u8 *new)
{
	__u32 o[4], n[4];

	__builtin_memcpy(o, old, 16);
	__builtin_memcpy(n, new, 16);
	__s64 diff = bpf_csum_diff(o, sizeof(o), n, sizeof(n), 0);

	if (diff < 0)
		return -1;
	if (bpf_l4_csum_replace(skb, l->csum_off, 0, diff, BPF_F_PSEUDO_HDR | l4_csum_flags(l)) < 0)
		return -1;
	return bpf_skb_store_bytes(skb, src ? IP6_SADDR_OFF : IP6_DADDR_OFF, n, sizeof(n), 0);
}

/* snat6_lookup_or_alloc is snat_lookup_or_alloc for IPv6. */
static __noinline struct nat6_val *
snat6_lookup_or_alloc(const struct l4 *l, const __u8 *ctr, const __u8 *remote, const __u8 *nat_addr,
		      __u32 ctr_ifindex)
{
	struct nat6_key out = {
		.sport = l->sport, .dport = l->dport, .proto = l->proto, .dir = NAT_SNAT_OUT,
	};
	struct nat6_key in = { .proto = l->proto, .dir = NAT_SNAT_IN };
	struct nat6_val *v;

	__builtin_memcpy(out.saddr, ctr, 16);
	__builtin_memcpy(out.daddr, remote, 16);
	v = bpf_map_lookup_elem(&netker_nat6, &out);
	if (v && addr6_eq(v->addr, nat_addr))
		return v;

	struct config *cfg = get_config();

	if (!cfg || cfg->nat_port_max <= cfg->nat_port_min)
		return NULL;
	__u32 span = (__u32)cfg->nat_port_max - cfg->nat_port_min + 1;
	struct nat6_val rev = { .port = l->sport, .ifindex = ctr_ifindex };

	__builtin_memcpy(rev.addr, ctr, 16);
	__builtin_memcpy(in.saddr, remote, 16);
	__builtin_memcpy(in.daddr, nat_addr, 16);

	for (int i = 0; i < NAT_ALLOC_TRIES; i++) {
		__be16 nport = bpf_htons(cfg->nat_port_min + bpf_get_prandom_u32() % span);

		in.sport = l->is_echo ? nport : l->dport;
		in.dport = nport;
		if (bpf_map_update_elem(&netker_nat6, &in, &rev, BPF_NOEXIST) != 0)
			continue;
		struct nat6_val fwd = { .port = nport };

		__builtin_memcpy(fwd.addr, nat_addr, 16);
		if (bpf_map_update_elem(&netker_nat6, &out, &fwd, BPF_ANY) != 0) {
			bpf_map_delete_elem(&netker_nat6, &in);
			return NULL;
		}
		return bpf_map_lookup_elem(&netker_nat6, &out);
	}
	return NULL;
}
