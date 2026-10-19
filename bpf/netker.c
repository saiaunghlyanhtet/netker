// SPDX-License-Identifier: GPL-2.0
/* netker eBPF datapath, attached to netkit devices (drivers/net/netkit.c),
 * to the host's uplinks (tcx ingress) and to the root cgroup.
 *
 * nk_from_container  BPF_NETKIT_PEER: the container's egress, run after
 *                    netkit switched the skb into the host netns
 *                    (skb->dev is the primary).
 * nk_to_container    BPF_NETKIT_PRIMARY: traffic into the container that
 *                    came through the host stack or a local redirect
 *                    (skb->dev is already the container's eth device).
 * nk_from_world      tcx ingress on uplinks: replies to masqueraded flows
 *                    and published ports, delivered with bpf_redirect_peer.
 * nk_from_lo         tcx ingress on lo: the host connecting to one of its
 *                    own addresses on a published port.
 * nk_sock_connect4   cgroup connect4 in the host netns: connections to
 *                    127.0.0.0/8 on a published port go straight to the
 *                    container (after DNAT the container couldn't reply to
 *                    a loopback source).
 */
#include "lib/common.h"
#include "lib/maps.h"
#include "lib/l4.h"
#include "lib/nat.h"
#include "lib/nat6.h"

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif
#define LOOPBACK_IFINDEX 1 /* lo is ifindex 1 in every netns */

static __always_inline bool is_mcast_or_bcast(__be32 addr)
{
	__u32 a = bpf_ntohl(addr);
	return (a & 0xf0000000) == 0xe0000000 || a == 0xffffffff;
}

/* Send a packet to a local container's primary: address it like the host
 * stack would (netkit marks frames PACKET_OTHERHOST unless the destination
 * MAC is the receiving device's) and redirect to the primary's egress, where
 * netkit switches into the container's netns. bpf_redirect_peer() isn't
 * usable here: it needs tc ingress, and this runs on netkit's xmit path.
 */
static __attribute__((noinline)) int to_local(struct __sk_buff *skb, __u32 self, struct endpoint *dst, __u8 reason, bool v6)
{
	__u32 dst_ifindex = dst->ifindex;
	__u8 macs[12];

	__builtin_memcpy(macs, dst->peer_mac, 6);
	__builtin_memcpy(macs + 6, dst->mac, 6);
	if ((v6 ? dec_hoplimit(skb) : dec_ttl(skb)) < 0) {
		count(skb, self, DIR_EGRESS, REASON_PASS_STACK);
		return NETKIT_PASS;
	}
	if (bpf_skb_store_bytes(skb, 0, macs, sizeof(macs), 0) < 0) {
		count(skb, self, DIR_EGRESS, REASON_DROP_MALFORMED);
		return NETKIT_DROP;
	}
	count(skb, self, DIR_EGRESS, reason);
	return bpf_redirect(dst_ifindex, 0);
}

static __always_inline bool mac_eq(const __u8 *a, const __u8 *b)
{
	for (int i = 0; i < 6; i++)
		if (a[i] != b[i])
			return false;
	return true;
}

/* Ethernet/IPv4 ARP payload. */
struct arp_eth {
	__be16 htype;
	__be16 ptype;
	__u8 hlen;
	__u8 plen;
	__be16 op;
	__u8 sha[6];
	__be32 sip;
	__u8 tha[6];
	__be32 tip;
} __attribute__((packed));

/* from_container_arp lets a container's ARP through only if it speaks for
 * its own address, and on L2 networks with its own MAC; otherwise it could
 * poison the host's ARP cache with another container's IP.
 */
static __always_inline int from_container_arp(struct __sk_buff *skb, struct ethhdr *eth, __u32 self)
{
	struct arp_eth arp;

	if (bpf_skb_load_bytes(skb, ETH_HLEN, &arp, sizeof(arp)) < 0) {
		count(skb, self, DIR_EGRESS, REASON_DROP_MALFORMED);
		return NETKIT_DROP;
	}
	__be32 sip = arp.sip;
	struct endpoint *ep = bpf_map_lookup_elem(&netker_endpoints, &sip);
	if (!ep || ep->ifindex != self) {
		count(skb, self, DIR_EGRESS, REASON_DROP_SPOOF);
		return NETKIT_DROP;
	}
	if ((ep->flags & EP_F_L2) &&
	    (!mac_eq(arp.sha, ep->peer_mac) || !mac_eq(eth->h_source, ep->peer_mac))) {
		count(skb, self, DIR_EGRESS, REASON_DROP_SPOOF_MAC);
		return NETKIT_DROP;
	}
	count(skb, self, DIR_EGRESS, REASON_PASS_ARP);
	return NETKIT_PASS;
}

static __always_inline bool ip6_is_mcast(const struct in6_addr *a)
{
	return a->in6_u.u6_addr8[0] == 0xff;
}

/* from_container6 is nk_from_container for IPv6, with the same steps:
 * anti-spoofing, replies from published ports, isolation and local
 * redirect, published-port hairpin, and SNAT66 to an uplink. It's a
 * separate BPF function (not inlined) because the IPv6 NAT keys don't fit
 * the 512-byte stack next to the IPv4 path.
 */
static __attribute__((noinline)) int from_container6(struct __sk_buff *skb, __u32 self)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	struct ipv6hdr *ip6 = (void *)(eth + 1);
	struct l4 l = {};

	if ((void *)(ip6 + 1) > data_end) {
		count(skb, self, DIR_EGRESS, REASON_DROP_MALFORMED);
		return NETKIT_DROP;
	}
	/* E.g. the container's MLD reports for its solicited-node groups. */
	if (ip6_is_mcast(&ip6->daddr)) {
		count(skb, self, DIR_EGRESS, REASON_DROP_MCAST);
		return NETKIT_DROP;
	}
	__u8 saddr[16], daddr[16];
	__builtin_memcpy(saddr, &ip6->saddr, 16);
	__builtin_memcpy(daddr, &ip6->daddr, 16);

	struct endpoint *src = bpf_map_lookup_elem(&netker_endpoints6, saddr);
	if (!src || src->ifindex != self) {
		count(skb, self, DIR_EGRESS, REASON_DROP_SPOOF);
		return NETKIT_DROP;
	}
	if ((src->flags & EP_F_L2) && !mac_eq(eth->h_source, src->peer_mac)) {
		count(skb, self, DIR_EGRESS, REASON_DROP_SPOOF_MAC);
		return NETKIT_DROP;
	}
	__u32 src_netid = src->netid;
	__u32 src_flags = src->flags;
	bool has_l4 = parse_l4_6(skb, ip6, &l);
	bool rev_dnat = false;

	/* A reply from a published port: restore the address the client used. */
	if (has_l4) {
		struct nat6_key k = { .sport = l.sport, .dport = l.dport, .proto = l.proto, .dir = NAT_DNAT_REPLY };
		__builtin_memcpy(k.saddr, saddr, 16);
		__builtin_memcpy(k.daddr, daddr, 16);
		struct nat6_val *v = bpf_map_lookup_elem(&netker_nat6, &k);
		if (v) {
			__u8 orig[16];
			__be16 orig_port = v->port;
			__builtin_memcpy(orig, v->addr, 16);
			if (rewrite_port(skb, &l, true, l.sport, orig_port) < 0 ||
			    rewrite_addr6(skb, &l, true, saddr, orig) < 0) {
				count(skb, self, DIR_EGRESS, REASON_DROP_MALFORMED);
				return NETKIT_DROP;
			}
			__builtin_memcpy(saddr, orig, 16);
			l.sport = orig_port;
			rev_dnat = true;
		}
	}

	struct endpoint *dst = bpf_map_lookup_elem(&netker_endpoints6, daddr);
	if (dst) {
		if (!rev_dnat && dst->netid != src_netid) {
			count(skb, self, DIR_EGRESS, REASON_DROP_POLICY);
			return NETKIT_DROP;
		}
		if (!rev_dnat && (src_flags & EP_F_NO_ICC)) {
			count(skb, self, DIR_EGRESS, REASON_DROP_ICC);
			return NETKIT_DROP;
		}
		return to_local(skb, self, dst, rev_dnat ? REASON_REV_DNAT : REASON_FORWARD_LOCAL, true);
	}

	struct bpf_fib_lookup *fib = scratch_fib();
	if (!fib) {
		count(skb, self, DIR_EGRESS, REASON_PASS_STACK);
		return NETKIT_PASS;
	}
	fib->family = AF_INET6;
	fib->ifindex = self;
	__builtin_memcpy(fib->ipv6_src, saddr, 16);
	__builtin_memcpy(fib->ipv6_dst, daddr, 16);
	long rc = bpf_fib_lookup(skb, fib, sizeof(*fib), BPF_FIB_LOOKUP_SRC);

	if (rc == BPF_FIB_LKUP_RET_NOT_FWDED && rev_dnat) {
		/* Reply to the host's connection to its own address: back
		 * through lo, as for IPv4.
		 */
		__u8 zero_mac[6] = {};
		if (bpf_skb_store_bytes(skb, 0, zero_mac, sizeof(zero_mac), 0) < 0) {
			count(skb, self, DIR_EGRESS, REASON_DROP_MALFORMED);
			return NETKIT_DROP;
		}
		count(skb, self, DIR_EGRESS, REASON_REV_DNAT);
		return bpf_redirect(LOOPBACK_IFINDEX, BPF_F_INGRESS);
	}
	if (rc == BPF_FIB_LKUP_RET_NOT_FWDED) {
		/* A host address: published port means hairpin to its owner. */
		struct port6_val *pv = NULL;
		if (has_l4 && !l.is_echo)
			pv = lookup_port6(daddr, l.dport, l.proto, true);
		if (!pv) {
			count(skb, self, DIR_EGRESS, REASON_PASS_STACK);
			return NETKIT_PASS;
		}
		__u8 ctr[16];
		__be16 ctr_port = pv->ctr_port;
		__builtin_memcpy(ctr, pv->ctr_addr, 16);
		struct nat6_key k = { .sport = ctr_port, .dport = l.sport, .proto = l.proto, .dir = NAT_DNAT_REPLY };
		__builtin_memcpy(k.saddr, ctr, 16);
		__builtin_memcpy(k.daddr, saddr, 16);
		struct nat6_val v = { .port = l.dport };
		__builtin_memcpy(v.addr, daddr, 16);
		if (bpf_map_update_elem(&netker_nat6, &k, &v, BPF_ANY) != 0 ||
		    rewrite_port(skb, &l, false, l.dport, ctr_port) < 0 ||
		    rewrite_addr6(skb, &l, false, daddr, ctr) < 0) {
			count(skb, self, DIR_EGRESS, REASON_DROP_MALFORMED);
			return NETKIT_DROP;
		}
		dst = bpf_map_lookup_elem(&netker_endpoints6, ctr);
		if (!dst) {
			count(skb, self, DIR_EGRESS, REASON_DROP_NOT_OURS);
			return NETKIT_DROP;
		}
		return to_local(skb, self, dst, REASON_DNAT, true);
	}
	if (rc != BPF_FIB_LKUP_RET_SUCCESS && rc != BPF_FIB_LKUP_RET_NO_NEIGH) {
		count(skb, self, DIR_EGRESS, REASON_PASS_STACK);
		return NETKIT_PASS;
	}

	/* Out through an uplink. */
	if (src_flags & EP_F_INTERNAL) {
		count(skb, self, DIR_EGRESS, REASON_DROP_POLICY);
		return NETKIT_DROP;
	}
	__u32 out_ifindex = fib->ifindex;
	if (!rev_dnat) {
		__u8 nat_addr[16];
		__builtin_memcpy(nat_addr, fib->ipv6_src, 16);
		if (!has_l4 || addr6_is_zero(nat_addr)) {
			/* Extension headers, fragments, other protocols: the
			 * host stack and nftables masquerade handle it.
			 */
			count(skb, self, DIR_EGRESS, REASON_PASS_STACK);
			return NETKIT_PASS;
		}
		struct nat6_val *nv = snat6_lookup_or_alloc(&l, saddr, daddr, nat_addr, self);
		if (!nv) {
			count(skb, self, DIR_EGRESS, REASON_DROP_NAT_EXHAUSTED);
			return NETKIT_DROP;
		}
		__be16 nat_port = nv->port;
		if (rewrite_port(skb, &l, true, l.sport, nat_port) < 0 ||
		    rewrite_addr6(skb, &l, true, saddr, nat_addr) < 0) {
			count(skb, self, DIR_EGRESS, REASON_DROP_MALFORMED);
			return NETKIT_DROP;
		}
	}
	if (dec_hoplimit(skb) < 0) {
		count(skb, self, DIR_EGRESS, REASON_PASS_STACK);
		return NETKIT_PASS;
	}
	count(skb, self, DIR_EGRESS, rev_dnat ? REASON_REV_DNAT : REASON_SNAT);
	return bpf_redirect_neigh(out_ifindex, NULL, 0, 0);
}

/* to_container6 delivers only IPv6 addressed to this endpoint. */
static __always_inline int to_container6(struct __sk_buff *skb, struct ethhdr *eth, __u32 self_peer)
{
	void *data_end = (void *)(long)skb->data_end;
	struct ipv6hdr *ip6 = (void *)(eth + 1);

	if ((void *)(ip6 + 1) > data_end)
		return NETKIT_DROP;
	if (ip6_is_mcast(&ip6->daddr)) {
		count(skb, 0, DIR_INGRESS, REASON_DROP_MCAST);
		return NETKIT_DROP;
	}
	struct ip6_key dkey;
	__builtin_memcpy(dkey.addr, &ip6->daddr, 16);
	struct endpoint *dst = bpf_map_lookup_elem(&netker_endpoints6, &dkey);
	if (!dst || dst->peer_ifindex != self_peer) {
		count(skb, dst ? dst->ifindex : 0, DIR_INGRESS, REASON_DROP_NOT_OURS);
		return NETKIT_DROP;
	}
	count(skb, dst->ifindex, DIR_INGRESS, REASON_DELIVER);
	return NETKIT_PASS;
}

/* from_container4 is nk_from_container's IPv4 path. Like from_container6
 * it's its own BPF function: the verifier adds up the stack frames of
 * caller and callee, so neither family's locals may sit in the caller.
 */
static __attribute__((noinline)) int from_container4(struct __sk_buff *skb, __u32 self)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	struct l4 l = {};

	if ((void *)(eth + 1) > data_end) {
		count(skb, self, DIR_EGRESS, REASON_DROP_MALFORMED);
		return NETKIT_DROP;
	}
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end) {
		count(skb, self, DIR_EGRESS, REASON_DROP_MALFORMED);
		return NETKIT_DROP;
	}

	__be32 saddr = ip->saddr, daddr = ip->daddr;
	struct endpoint *src = bpf_map_lookup_elem(&netker_endpoints, &saddr);
	if (!src || src->ifindex != self) {
		count(skb, self, DIR_EGRESS, REASON_DROP_SPOOF);
		return NETKIT_DROP;
	}
	/* On L2 networks the container could change its MAC (netkit allows
	 * live address changes); only its recorded MAC may send.
	 */
	if ((src->flags & EP_F_L2) && !mac_eq(eth->h_source, src->peer_mac)) {
		count(skb, self, DIR_EGRESS, REASON_DROP_SPOOF_MAC);
		return NETKIT_DROP;
	}
	__u32 src_netid = src->netid;
	bool internal = src->flags & EP_F_INTERNAL;
	bool no_icc = src->flags & EP_F_NO_ICC;
	bool has_l4 = parse_l4(skb, ip, &l);
	bool rev_dnat = false;

	/* A reply from a published port: restore the address the client
	 * connected to.
	 */
	if (has_l4) {
		struct nat_key k = {
			.saddr = saddr, .daddr = daddr, .sport = l.sport, .dport = l.dport,
			.proto = l.proto, .dir = NAT_DNAT_REPLY,
		};
		struct nat_val *v = bpf_map_lookup_elem(&netker_nat, &k);
		if (v) {
			__be32 orig_addr = v->addr;
			__be16 orig_port = v->port;
			if (rewrite_port(skb, &l, true, l.sport, orig_port) < 0 ||
			    rewrite_addr(skb, &l, true, saddr, orig_addr) < 0) {
				count(skb, self, DIR_EGRESS, REASON_DROP_MALFORMED);
				return NETKIT_DROP;
			}
			saddr = orig_addr;
			l.sport = orig_port;
			rev_dnat = true;
		}
	}

	struct endpoint *dst = bpf_map_lookup_elem(&netker_endpoints, &daddr);
	if (dst) {
		/* Replies on a published port may cross networks: the client
		 * connected to a host address, not to this container.
		 */
		if (!rev_dnat && dst->netid != src_netid) {
			count(skb, self, DIR_EGRESS, REASON_DROP_POLICY);
			return NETKIT_DROP;
		}
		/* --icc=false: no direct traffic between the network's
		 * containers. Published ports (hairpin, below) and their
		 * replies stay reachable, as they were exposed on purpose.
		 */
		if (!rev_dnat && no_icc) {
			count(skb, self, DIR_EGRESS, REASON_DROP_ICC);
			return NETKIT_DROP;
		}
		return to_local(skb, self, dst, rev_dnat ? REASON_REV_DNAT : REASON_FORWARD_LOCAL, false);
	}

	struct bpf_fib_lookup *fib = scratch_fib();
	if (!fib) {
		count(skb, self, DIR_EGRESS, REASON_PASS_STACK);
		return NETKIT_PASS;
	}
	fib->family = AF_INET;
	fib->ifindex = self;
	fib->ipv4_src = saddr;
	fib->ipv4_dst = daddr;
	long rc = bpf_fib_lookup(skb, fib, sizeof(*fib), BPF_FIB_LOOKUP_SRC);

	if (rc == BPF_FIB_LKUP_RET_NOT_FWDED && rev_dnat) {
		/* Reply to the host itself, which connected to one of its own
		 * addresses (see nk_from_lo). The source is now a local address,
		 * so the stack would drop it as a martian on this device; hand
		 * it back through lo, where the request came from.
		 */
		__u8 zero_mac[6] = {};
		if (bpf_skb_store_bytes(skb, 0, zero_mac, sizeof(zero_mac), 0) < 0) {
			count(skb, self, DIR_EGRESS, REASON_DROP_MALFORMED);
			return NETKIT_DROP;
		}
		count(skb, self, DIR_EGRESS, REASON_REV_DNAT);
		return bpf_redirect(LOOPBACK_IFINDEX, BPF_F_INGRESS);
	}
	if (rc == BPF_FIB_LKUP_RET_NOT_FWDED) {
		/* A host address (or broadcast). Published port: hairpin
		 * straight to the container that owns it.
		 */
		struct port_val *pv = NULL;
		if (has_l4 && !rev_dnat && !is_mcast_or_bcast(daddr))
			pv = lookup_port(daddr, l.dport, l.proto, true);
		if (!pv) {
			count(skb, self, DIR_EGRESS, REASON_PASS_STACK);
			return NETKIT_PASS;
		}
		__be32 ctr_addr = pv->ctr_addr;
		__be16 ctr_port = pv->ctr_port;
		struct nat_key k = {
			.saddr = ctr_addr, .daddr = saddr, .sport = ctr_port, .dport = l.sport,
			.proto = l.proto, .dir = NAT_DNAT_REPLY,
		};
		struct nat_val v = { .addr = daddr, .port = l.dport };
		if (bpf_map_update_elem(&netker_nat, &k, &v, BPF_ANY) != 0 ||
		    rewrite_port(skb, &l, false, l.dport, ctr_port) < 0 ||
		    rewrite_addr(skb, &l, false, daddr, ctr_addr) < 0) {
			count(skb, self, DIR_EGRESS, REASON_DROP_MALFORMED);
			return NETKIT_DROP;
		}
		dst = bpf_map_lookup_elem(&netker_endpoints, &ctr_addr);
		if (!dst) {
			count(skb, self, DIR_EGRESS, REASON_DROP_NOT_OURS);
			return NETKIT_DROP;
		}
		return to_local(skb, self, dst, REASON_DNAT, false);
	}
	if (rc != BPF_FIB_LKUP_RET_SUCCESS && rc != BPF_FIB_LKUP_RET_NO_NEIGH) {
		/* Unreachable, prohibited, ...: the stack answers with ICMP. */
		count(skb, self, DIR_EGRESS, REASON_PASS_STACK);
		return NETKIT_PASS;
	}

	/* Out through an uplink. */
	if (internal) {
		count(skb, self, DIR_EGRESS, REASON_DROP_POLICY);
		return NETKIT_DROP;
	}
	__u32 out_ifindex = fib->ifindex;
	if (!rev_dnat) {
		if (!has_l4 || !fib->ipv4_src) {
			/* Fragments, other protocols, or no source address on
			 * the uplink: the stack and nftables masquerade handle it.
			 */
			count(skb, self, DIR_EGRESS, REASON_PASS_STACK);
			return NETKIT_PASS;
		}
		struct nat_val *nv = snat_lookup_or_alloc(&l, saddr, daddr, fib->ipv4_src, self);
		if (!nv) {
			count(skb, self, DIR_EGRESS, REASON_DROP_NAT_EXHAUSTED);
			return NETKIT_DROP;
		}
		__be32 nat_addr = nv->addr;
		__be16 nat_port = nv->port;
		if (rewrite_port(skb, &l, true, l.sport, nat_port) < 0 ||
		    rewrite_addr(skb, &l, true, saddr, nat_addr) < 0) {
			count(skb, self, DIR_EGRESS, REASON_DROP_MALFORMED);
			return NETKIT_DROP;
		}
	}
	if (dec_ttl(skb) < 0) {
		count(skb, self, DIR_EGRESS, REASON_PASS_STACK);
		return NETKIT_PASS;
	}
	count(skb, self, DIR_EGRESS, rev_dnat ? REASON_REV_DNAT : REASON_SNAT);
	/* The neighbour subsystem resolves the next hop and fills in the MACs. */
	return bpf_redirect_neigh(out_ifindex, NULL, 0, 0);
}

SEC("netkit/peer")
int nk_from_container(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	__u32 self = skb->ifindex;

	if ((void *)(eth + 1) > data_end) {
		count(skb, self, DIR_EGRESS, REASON_DROP_MALFORMED);
		return NETKIT_DROP;
	}
	switch (eth->h_proto) {
	case bpf_htons(ETH_P_ARP):
		return from_container_arp(skb, eth, self);
	case bpf_htons(ETH_P_IP):
		return from_container4(skb, self);
	case bpf_htons(ETH_P_IPV6):
		return from_container6(skb, self);
	}
	count(skb, self, DIR_EGRESS, REASON_DROP_PROTO);
	return NETKIT_DROP;
}

SEC("netkit/primary")
int nk_to_container(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	/* skb->dev is the container's device here; count against the primary. */
	__u32 self_peer = skb->ifindex;

	if ((void *)(eth + 1) > data_end)
		return NETKIT_DROP;
	if (eth->h_proto == bpf_htons(ETH_P_ARP))
		return NETKIT_PASS;
	if (eth->h_proto == bpf_htons(ETH_P_IPV6))
		return to_container6(skb, eth, self_peer);
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return NETKIT_DROP;
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return NETKIT_DROP;

	__be32 daddr = ip->daddr;
	if (is_mcast_or_bcast(daddr)) {
		count(skb, 0, DIR_INGRESS, REASON_DROP_MCAST);
		return NETKIT_DROP;
	}
	struct endpoint *dst = bpf_map_lookup_elem(&netker_endpoints, &daddr);
	if (!dst || dst->peer_ifindex != self_peer) {
		count(skb, dst ? dst->ifindex : 0, DIR_INGRESS, REASON_DROP_NOT_OURS);
		return NETKIT_DROP;
	}
	count(skb, dst->ifindex, DIR_INGRESS, REASON_DELIVER);
	return NETKIT_PASS;
}

static __always_inline bool is_loopback(__be32 addr)
{
	return (bpf_ntohl(addr) >> 24) == 127;
}

/* host_ingress translates replies to masqueraded flows and connections to
 * published ports, then sends them straight into the container.
 */
static __attribute__((noinline)) int host_ingress(struct __sk_buff *skb, bool on_lo)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	struct l4 l = {};

	if ((void *)(eth + 1) > data_end || eth->h_proto != bpf_htons(ETH_P_IP))
		return TCX_NEXT;
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return TCX_NEXT;
	__be32 saddr = ip->saddr, daddr = ip->daddr;
	/* 127.0.0.0/8 is handled at connect() time by nk_sock_connect4. */
	if (on_lo && is_loopback(daddr))
		return TCX_NEXT;
	if (!parse_l4(skb, ip, &l))
		return TCX_NEXT;

	__be32 new_addr;
	__be16 new_port;
	__u32 ifindex;
	__u8 reason;
	struct nat_val *v = NULL;

	if (!on_lo) {
		struct nat_key k = {
			.saddr = saddr, .daddr = daddr, .sport = l.sport, .dport = l.dport,
			.proto = l.proto, .dir = NAT_SNAT_IN,
		};
		v = bpf_map_lookup_elem(&netker_nat, &k);
	}
	if (v) {
		new_addr = v->addr;
		new_port = v->port;
		ifindex = v->ifindex;
		reason = REASON_REV_SNAT;
	} else {
		struct port_val *pv = lookup_port(daddr, l.dport, l.proto, false);
		if (!pv) {
			/* Wildcard entry: only for the host's own addresses.
			 * Everything arriving on lo is local; on an uplink ask
			 * the FIB (RTN_LOCAL comes back as NOT_FWDED).
			 */
			bool local = on_lo;
			if (!local) {
				struct bpf_fib_lookup fib = {
					.family = AF_INET,
					.ifindex = skb->ingress_ifindex,
					.ipv4_src = saddr,
					.ipv4_dst = daddr,
				};
				local = bpf_fib_lookup(skb, &fib, sizeof(fib), 0) == BPF_FIB_LKUP_RET_NOT_FWDED;
			}
			if (!local)
				return TCX_NEXT;
			pv = lookup_port(0, l.dport, l.proto, false);
			if (!pv)
				return TCX_NEXT;
		}
		new_addr = pv->ctr_addr;
		new_port = pv->ctr_port;
		ifindex = pv->ifindex;
		reason = REASON_DNAT;
		/* Containers on internal networks aren't reachable from outside. */
		if (!on_lo) {
			struct endpoint *ep = bpf_map_lookup_elem(&netker_endpoints, &new_addr);
			if (!ep || (ep->flags & EP_F_INTERNAL))
				return TCX_NEXT;
		}
		struct nat_key rk = {
			.saddr = new_addr, .daddr = saddr, .sport = new_port, .dport = l.sport,
			.proto = l.proto, .dir = NAT_DNAT_REPLY,
		};
		struct nat_val rv = { .addr = daddr, .port = l.dport };
		if (bpf_map_update_elem(&netker_nat, &rk, &rv, BPF_ANY) != 0)
			return TCX_DROP;
	}
	if (rewrite_port(skb, &l, false, l.dport, new_port) < 0 ||
	    rewrite_addr(skb, &l, false, daddr, new_addr) < 0) {
		count(skb, ifindex, DIR_INGRESS, REASON_DROP_MALFORMED);
		return TCX_DROP;
	}
	if (!on_lo && dec_ttl(skb) < 0)
		return TCX_NEXT;
	count(skb, ifindex, DIR_INGRESS, reason);
	/* Straight into the container's netns: tc ingress -> peer ingress, no
	 * backlog queue and no host stack.
	 */
	return bpf_redirect_peer(ifindex, 0);
}

static __always_inline bool ip6_is_loopback(const __u8 *a)
{
	for (int i = 0; i < 15; i++)
		if (a[i])
			return false;
	return a[15] == 1;
}

/* host_ingress6 is host_ingress for IPv6: reverse SNAT66 for replies on an
 * uplink, DNAT for published ports, then straight into the container.
 */
static __attribute__((noinline)) int host_ingress6(struct __sk_buff *skb, bool on_lo)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	struct ipv6hdr *ip6 = (void *)(eth + 1);
	struct l4 l = {};

	if ((void *)(ip6 + 1) > data_end)
		return TCX_NEXT;
	__u8 saddr[16], daddr[16];
	__builtin_memcpy(saddr, &ip6->saddr, 16);
	__builtin_memcpy(daddr, &ip6->daddr, 16);
	/* [::1] is handled at connect() time by nk_sock_connect6. */
	if (on_lo && ip6_is_loopback(daddr))
		return TCX_NEXT;
	if (!parse_l4_6(skb, ip6, &l))
		return TCX_NEXT;

	__u8 new_addr[16];
	__be16 new_port;
	__u32 ifindex;
	__u8 reason;
	struct nat6_val *v = NULL;

	if (!on_lo) {
		struct nat6_key k = { .sport = l.sport, .dport = l.dport, .proto = l.proto, .dir = NAT_SNAT_IN };
		__builtin_memcpy(k.saddr, saddr, 16);
		__builtin_memcpy(k.daddr, daddr, 16);
		v = bpf_map_lookup_elem(&netker_nat6, &k);
	}
	if (v) {
		__builtin_memcpy(new_addr, v->addr, 16);
		new_port = v->port;
		ifindex = v->ifindex;
		reason = REASON_REV_SNAT;
	} else {
		struct port6_val *pv = lookup_port6(daddr, l.dport, l.proto, false);
		if (!pv) {
			bool local = on_lo;
			if (!local) {
				struct bpf_fib_lookup fib = {
					.family = AF_INET6,
					.ifindex = skb->ingress_ifindex,
				};
				__builtin_memcpy(fib.ipv6_src, saddr, 16);
				__builtin_memcpy(fib.ipv6_dst, daddr, 16);
				local = bpf_fib_lookup(skb, &fib, sizeof(fib), 0) == BPF_FIB_LKUP_RET_NOT_FWDED;
			}
			if (!local)
				return TCX_NEXT;
			__u8 any[16] = {};
			pv = lookup_port6(any, l.dport, l.proto, false);
			if (!pv)
				return TCX_NEXT;
		}
		__builtin_memcpy(new_addr, pv->ctr_addr, 16);
		new_port = pv->ctr_port;
		ifindex = pv->ifindex;
		reason = REASON_DNAT;
		if (!on_lo) {
			struct endpoint *ep = bpf_map_lookup_elem(&netker_endpoints6, new_addr);
			if (!ep || (ep->flags & EP_F_INTERNAL))
				return TCX_NEXT;
		}
		struct nat6_key rk = { .sport = new_port, .dport = l.sport, .proto = l.proto, .dir = NAT_DNAT_REPLY };
		__builtin_memcpy(rk.saddr, new_addr, 16);
		__builtin_memcpy(rk.daddr, saddr, 16);
		struct nat6_val rv = { .port = l.dport };
		__builtin_memcpy(rv.addr, daddr, 16);
		if (bpf_map_update_elem(&netker_nat6, &rk, &rv, BPF_ANY) != 0)
			return TCX_DROP;
	}
	if (rewrite_port(skb, &l, false, l.dport, new_port) < 0 ||
	    rewrite_addr6(skb, &l, false, daddr, new_addr) < 0) {
		count(skb, ifindex, DIR_INGRESS, REASON_DROP_MALFORMED);
		return TCX_DROP;
	}
	if (!on_lo && dec_hoplimit(skb) < 0)
		return TCX_NEXT;
	count(skb, ifindex, DIR_INGRESS, reason);
	return bpf_redirect_peer(ifindex, 0);
}

static __always_inline bool is_ipv6(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;

	return (void *)(eth + 1) <= data_end && eth->h_proto == bpf_htons(ETH_P_IPV6);
}

SEC("tcx/ingress")
int nk_from_world(struct __sk_buff *skb)
{
	if (is_ipv6(skb))
		return host_ingress6(skb, false);
	return host_ingress(skb, false);
}

SEC("tcx/ingress")
int nk_from_lo(struct __sk_buff *skb)
{
	if (is_ipv6(skb))
		return host_ingress6(skb, true);
	return host_ingress(skb, true);
}

SEC("cgroup/connect4")
int nk_sock_connect4(struct bpf_sock_addr *ctx)
{
	struct config *cfg = get_config();

	/* Inside containers 127.0.0.1 is the container's own loopback. */
	if (!cfg || bpf_get_netns_cookie(ctx) != cfg->host_netns_cookie)
		return 1;
	if (ctx->protocol != IPPROTO_TCP && ctx->protocol != IPPROTO_UDP)
		return 1;
	__be32 dst = ctx->user_ip4;
	__be16 port = (__be16)ctx->user_port;
	if (!is_loopback(dst))
		return 1;
	struct port_val *pv = lookup_port(dst, port, ctx->protocol, true);
	if (!pv)
		return 1;
	ctx->user_ip4 = pv->ctr_addr;
	ctx->user_port = pv->ctr_port;
	count_sock(pv->ifindex, DIR_INGRESS, REASON_DNAT);
	return 1;
}

SEC("cgroup/connect6")
int nk_sock_connect6(struct bpf_sock_addr *ctx)
{
	struct config *cfg = get_config();

	/* Inside containers [::1] is the container's own loopback. */
	if (!cfg || bpf_get_netns_cookie(ctx) != cfg->host_netns_cookie)
		return 1;
	if (ctx->protocol != IPPROTO_TCP && ctx->protocol != IPPROTO_UDP)
		return 1;
	__u32 dst[4] = { ctx->user_ip6[0], ctx->user_ip6[1], ctx->user_ip6[2], ctx->user_ip6[3] };
	if (!ip6_is_loopback((__u8 *)dst))
		return 1;
	struct port6_val *pv = lookup_port6((__u8 *)dst, (__be16)ctx->user_port, ctx->protocol, true);
	if (!pv)
		return 1;
	__u32 ctr[4];
	__builtin_memcpy(ctr, pv->ctr_addr, 16);
	ctx->user_ip6[0] = ctr[0];
	ctx->user_ip6[1] = ctr[1];
	ctx->user_ip6[2] = ctr[2];
	ctx->user_ip6[3] = ctr[3];
	ctx->user_port = pv->ctr_port;
	count_sock(pv->ifindex, DIR_INGRESS, REASON_DNAT);
	return 1;
}

char __license[] SEC("license") = "GPL";
