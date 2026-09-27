// SPDX-License-Identifier: GPL-2.0
/* netker eBPF datapath, attached to netkit devices (drivers/net/netkit.c).
 *
 * nk_from_container runs on BPF_NETKIT_PEER: the container's egress, after
 * netkit has switched the skb into the host netns (skb->dev is the primary).
 * nk_to_container runs on BPF_NETKIT_PRIMARY: traffic into the container
 * (skb->dev is already the container's eth device).
 *
 * Container-to-container traffic on the same host is redirected straight to
 * the destination's primary device, skipping the host stack. Everything else
 * is passed to the host stack, which routes and NATs it (nftables), until
 * the BPF NAT path lands.
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/* Verdicts, identical to enum netkit_action / TCX. */
#define NETKIT_NEXT -1
#define NETKIT_PASS 0
#define NETKIT_DROP 2
#define NETKIT_REDIRECT 7

enum reason {
	REASON_FORWARD_LOCAL = 1, /* redirected to a local container */
	REASON_PASS_STACK = 2,    /* handed to the host stack */
	REASON_PASS_ARP = 3,
	REASON_DELIVER = 4,       /* delivered into the container */
	REASON_DROP_SPOOF = 10,   /* source IP isn't the container's */
	REASON_DROP_POLICY = 11,  /* destination on another network */
	REASON_DROP_NOT_OURS = 12,/* packet for another container's IP */
	REASON_DROP_PROTO = 13,   /* not IPv4 or ARP */
	REASON_DROP_MALFORMED = 14,
};

enum direction {
	DIR_EGRESS = 0,  /* from the container */
	DIR_INGRESS = 1, /* to the container */
};

struct endpoint {
	__u32 ifindex;      /* primary, host netns */
	__u32 peer_ifindex; /* container's eth device, container netns */
	__u32 netid;
	__u32 flags;
	__u8 mac[6];        /* primary's MAC (zero in L3 mode) */
	__u8 peer_mac[6];   /* container's MAC (zero in L3 mode) */
};

struct metrics_key {
	__u32 ifindex; /* primary ifindex of the endpoint */
	__u8 dir;
	__u8 reason;
	__u16 pad;
};

struct metrics_val {
	__u64 packets;
	__u64 bytes;
};

/* Container IPv4 address (network byte order) -> endpoint. Written by netker. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __be32);
	__type(value, struct endpoint);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} netker_endpoints SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct metrics_key);
	__type(value, struct metrics_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} netker_metrics SEC(".maps");

static __always_inline void count(__u32 ifindex, __u8 dir, __u8 reason, __u32 len)
{
	struct metrics_key key = { .ifindex = ifindex, .dir = dir, .reason = reason };
	struct metrics_val *val = bpf_map_lookup_elem(&netker_metrics, &key);

	if (val) {
		val->packets++;
		val->bytes += len;
		return;
	}
	struct metrics_val init = { .packets = 1, .bytes = len };
	bpf_map_update_elem(&netker_metrics, &key, &init, BPF_NOEXIST);
}

#define IP_CSUM_OFF (ETH_HLEN + __builtin_offsetof(struct iphdr, check))
#define IP_TTL_OFF (ETH_HLEN + __builtin_offsetof(struct iphdr, ttl))

/* Decrement TTL like a router would. Returns -1 if the packet must go to
 * the stack instead (TTL expiring: let the kernel send ICMP time exceeded).
 */
static __always_inline int dec_ttl(struct __sk_buff *skb, struct iphdr *ip)
{
	__u8 ttl = ip->ttl;

	if (ttl <= 1)
		return -1;
	/* TTL and protocol share one 16-bit checksum word. */
	__be16 old = *(__be16 *)&ip->ttl;
	__u8 new_ttl = ttl - 1;
	__be16 new;

	__builtin_memcpy(&new, &old, sizeof(new));
	((__u8 *)&new)[0] = new_ttl;
	if (bpf_l3_csum_replace(skb, IP_CSUM_OFF, old, new, sizeof(new)) < 0)
		return -1;
	if (bpf_skb_store_bytes(skb, IP_TTL_OFF, &new_ttl, 1, 0) < 0)
		return -1;
	return 0;
}

SEC("netkit/peer")
int nk_from_container(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	__u32 self = skb->ifindex;

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

	struct endpoint *dst = bpf_map_lookup_elem(&netker_endpoints, &daddr);
	if (!dst) {
		/* Gateway, host or outside world: the host stack routes it. */
		count(self, DIR_EGRESS, REASON_PASS_STACK, skb->len);
		return NETKIT_PASS;
	}
	if (dst->netid != src->netid) {
		count(self, DIR_EGRESS, REASON_DROP_POLICY, skb->len);
		return NETKIT_DROP;
	}
	/* Copy before the helpers below invalidate packet pointers. */
	__u32 dst_ifindex = dst->ifindex;
	__u8 macs[12];
	__builtin_memcpy(macs, dst->peer_mac, 6);
	__builtin_memcpy(macs + 6, dst->mac, 6);

	if (dec_ttl(skb, ip) < 0) {
		count(self, DIR_EGRESS, REASON_PASS_STACK, skb->len);
		return NETKIT_PASS;
	}
	/* netkit marks the skb PACKET_OTHERHOST unless the destination MAC is
	 * the receiving device's, so address it like the host stack would.
	 */
	if (bpf_skb_store_bytes(skb, 0, macs, sizeof(macs), 0) < 0) {
		count(self, DIR_EGRESS, REASON_DROP_MALFORMED, skb->len);
		return NETKIT_DROP;
	}
	count(self, DIR_EGRESS, REASON_FORWARD_LOCAL, skb->len);
	/* Egress of the destination's primary: netkit switches into its netns.
	 * bpf_redirect_peer() isn't usable here, it needs tc ingress.
	 */
	return bpf_redirect(dst_ifindex, 0);
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
	struct endpoint *dst = bpf_map_lookup_elem(&netker_endpoints, &daddr);
	if (!dst || dst->peer_ifindex != self_peer) {
		count(dst ? dst->ifindex : 0, DIR_INGRESS, REASON_DROP_NOT_OURS, skb->len);
		return NETKIT_DROP;
	}
	count(dst->ifindex, DIR_INGRESS, REASON_DELIVER, skb->len);
	return NETKIT_PASS;
}

char __license[] SEC("license") = "GPL";
