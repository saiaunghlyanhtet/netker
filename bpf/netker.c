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

#ifndef AF_INET
#define AF_INET 2
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
static __always_inline int to_local(struct __sk_buff *skb, __u32 self, struct endpoint *dst, __u8 reason)
{
	__u32 dst_ifindex = dst->ifindex;
	__u8 macs[12];

	__builtin_memcpy(macs, dst->peer_mac, 6);
	__builtin_memcpy(macs + 6, dst->mac, 6);
	if (dec_ttl(skb) < 0) {
		count(self, DIR_EGRESS, REASON_PASS_STACK, skb->len);
		return NETKIT_PASS;
	}
	if (bpf_skb_store_bytes(skb, 0, macs, sizeof(macs), 0) < 0) {
		count(self, DIR_EGRESS, REASON_DROP_MALFORMED, skb->len);
		return NETKIT_DROP;
	}
	count(self, DIR_EGRESS, reason, skb->len);
	return bpf_redirect(dst_ifindex, 0);
}

SEC("netkit/peer")
int nk_from_container(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	__u32 self = skb->ifindex;
	struct l4 l = {};

	if ((void *)(eth + 1) > data_end) {
		count(self, DIR_EGRESS, REASON_DROP_MALFORMED, skb->len);
		return NETKIT_DROP;
	}
	if (eth->h_proto == bpf_htons(ETH_P_ARP)) {
		count(self, DIR_EGRESS, REASON_PASS_ARP, skb->len);
		return NETKIT_PASS;
	}
	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		count(self, DIR_EGRESS, REASON_DROP_PROTO, skb->len);
		return NETKIT_DROP;
	}
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end) {
		count(self, DIR_EGRESS, REASON_DROP_MALFORMED, skb->len);
		return NETKIT_DROP;
	}

	__be32 saddr = ip->saddr, daddr = ip->daddr;
	struct endpoint *src = bpf_map_lookup_elem(&netker_endpoints, &saddr);
	if (!src || src->ifindex != self) {
		count(self, DIR_EGRESS, REASON_DROP_SPOOF, skb->len);
		return NETKIT_DROP;
	}
	__u32 src_netid = src->netid;
	bool internal = src->flags & EP_F_INTERNAL;
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
				count(self, DIR_EGRESS, REASON_DROP_MALFORMED, skb->len);
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
			count(self, DIR_EGRESS, REASON_DROP_POLICY, skb->len);
			return NETKIT_DROP;
		}
		return to_local(skb, self, dst, rev_dnat ? REASON_REV_DNAT : REASON_FORWARD_LOCAL);
	}

	struct bpf_fib_lookup fib = {
		.family = AF_INET,
		.ifindex = self,
		.ipv4_src = saddr,
		.ipv4_dst = daddr,
	};
	long rc = bpf_fib_lookup(skb, &fib, sizeof(fib), BPF_FIB_LOOKUP_SRC);

	if (rc == BPF_FIB_LKUP_RET_NOT_FWDED && rev_dnat) {
		/* Reply to the host itself, which connected to one of its own
		 * addresses (see nk_from_lo). The source is now a local address,
		 * so the stack would drop it as a martian on this device; hand
		 * it back through lo, where the request came from.
		 */
		__u8 zero_mac[6] = {};
		if (bpf_skb_store_bytes(skb, 0, zero_mac, sizeof(zero_mac), 0) < 0) {
			count(self, DIR_EGRESS, REASON_DROP_MALFORMED, skb->len);
			return NETKIT_DROP;
		}
		count(self, DIR_EGRESS, REASON_REV_DNAT, skb->len);
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
			count(self, DIR_EGRESS, REASON_PASS_STACK, skb->len);
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
			count(self, DIR_EGRESS, REASON_DROP_MALFORMED, skb->len);
			return NETKIT_DROP;
		}
		dst = bpf_map_lookup_elem(&netker_endpoints, &ctr_addr);
		if (!dst) {
			count(self, DIR_EGRESS, REASON_DROP_NOT_OURS, skb->len);
			return NETKIT_DROP;
		}
		return to_local(skb, self, dst, REASON_DNAT);
	}
	if (rc != BPF_FIB_LKUP_RET_SUCCESS && rc != BPF_FIB_LKUP_RET_NO_NEIGH) {
		/* Unreachable, prohibited, ...: the stack answers with ICMP. */
		count(self, DIR_EGRESS, REASON_PASS_STACK, skb->len);
		return NETKIT_PASS;
	}

	/* Out through an uplink. */
	if (internal) {
		count(self, DIR_EGRESS, REASON_DROP_POLICY, skb->len);
		return NETKIT_DROP;
	}
	__u32 out_ifindex = fib.ifindex;
	if (!rev_dnat) {
		if (!has_l4 || !fib.ipv4_src) {
			/* Fragments, other protocols, or no source address on
			 * the uplink: the stack and nftables masquerade handle it.
			 */
			count(self, DIR_EGRESS, REASON_PASS_STACK, skb->len);
			return NETKIT_PASS;
		}
		struct nat_val *nv = snat_lookup_or_alloc(&l, saddr, daddr, fib.ipv4_src, self);
		if (!nv) {
			count(self, DIR_EGRESS, REASON_DROP_NAT_EXHAUSTED, skb->len);
			return NETKIT_DROP;
		}
		__be32 nat_addr = nv->addr;
		__be16 nat_port = nv->port;
		if (rewrite_port(skb, &l, true, l.sport, nat_port) < 0 ||
		    rewrite_addr(skb, &l, true, saddr, nat_addr) < 0) {
			count(self, DIR_EGRESS, REASON_DROP_MALFORMED, skb->len);
			return NETKIT_DROP;
		}
	}
	if (dec_ttl(skb) < 0) {
		count(self, DIR_EGRESS, REASON_PASS_STACK, skb->len);
		return NETKIT_PASS;
	}
	count(self, DIR_EGRESS, rev_dnat ? REASON_REV_DNAT : REASON_SNAT, skb->len);
	/* The neighbour subsystem resolves the next hop and fills in the MACs. */
	return bpf_redirect_neigh(out_ifindex, NULL, 0, 0);
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
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return NETKIT_DROP;
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return NETKIT_DROP;

	__be32 daddr = ip->daddr;
	if (is_mcast_or_bcast(daddr)) {
		count(0, DIR_INGRESS, REASON_DROP_MCAST, skb->len);
		return NETKIT_DROP;
	}
	struct endpoint *dst = bpf_map_lookup_elem(&netker_endpoints, &daddr);
	if (!dst || dst->peer_ifindex != self_peer) {
		count(dst ? dst->ifindex : 0, DIR_INGRESS, REASON_DROP_NOT_OURS, skb->len);
		return NETKIT_DROP;
	}
	count(dst->ifindex, DIR_INGRESS, REASON_DELIVER, skb->len);
	return NETKIT_PASS;
}

static __always_inline bool is_loopback(__be32 addr)
{
	return (bpf_ntohl(addr) >> 24) == 127;
}

/* host_ingress translates replies to masqueraded flows and connections to
 * published ports, then sends them straight into the container.
 */
static __always_inline int host_ingress(struct __sk_buff *skb, bool on_lo)
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
		count(ifindex, DIR_INGRESS, REASON_DROP_MALFORMED, skb->len);
		return TCX_DROP;
	}
	if (!on_lo && dec_ttl(skb) < 0)
		return TCX_NEXT;
	count(ifindex, DIR_INGRESS, reason, skb->len);
	/* Straight into the container's netns: tc ingress -> peer ingress, no
	 * backlog queue and no host stack.
	 */
	return bpf_redirect_peer(ifindex, 0);
}

SEC("tcx/ingress")
int nk_from_world(struct __sk_buff *skb)
{
	return host_ingress(skb, false);
}

SEC("tcx/ingress")
int nk_from_lo(struct __sk_buff *skb)
{
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
	count(pv->ifindex, DIR_INGRESS, REASON_DNAT, 0);
	return 1;
}

char __license[] SEC("license") = "GPL";
