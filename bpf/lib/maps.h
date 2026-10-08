/* SPDX-License-Identifier: GPL-2.0 */
#pragma once

#include "common.h"

#define EP_F_INTERNAL 0x1 /* network has no external connectivity */
#define EP_F_NO_ICC 0x2   /* no traffic between containers of the network */

struct endpoint {
	__u32 ifindex;      /* primary, host netns */
	__u32 peer_ifindex; /* container's eth device, container netns */
	__u32 netid;
	__u32 flags;        /* EP_F_* */
	__u8 mac[6];        /* primary's MAC (zero in L3 mode) */
	__u8 peer_mac[6];   /* container's MAC (zero in L3 mode) */
};

/* Container IPv4 address (network byte order) -> endpoint. Written by netker. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __be32);
	__type(value, struct endpoint);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} netker_endpoints SEC(".maps");

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

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct metrics_key);
	__type(value, struct metrics_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} netker_metrics SEC(".maps");

/* Published ports. addr is a specific host address, or 0 for all of them. */
struct port_key {
	__be32 addr;
	__be16 port;
	__u8 proto;
	__u8 pad;
};

struct port_val {
	__be32 ctr_addr;
	__be16 ctr_port;
	__u16 pad;
	__u32 ifindex; /* primary of the container */
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, struct port_key);
	__type(value, struct port_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} netker_ports SEC(".maps");

enum nat_dir {
	NAT_SNAT_OUT = 1,   /* container flow -> masqueraded address/port */
	NAT_SNAT_IN = 2,    /* reply to masqueraded address/port -> container */
	NAT_DNAT_REPLY = 3, /* container reply on a published port -> original dst */
};

/* A flow as seen on the wire. For ICMP echo both ports hold the identifier. */
struct nat_key {
	__be32 saddr;
	__be32 daddr;
	__be16 sport;
	__be16 dport;
	__u8 proto;
	__u8 dir;
	__u16 pad;
};

struct nat_val {
	__be32 addr;
	__be16 port;
	__u16 pad;
	__u32 ifindex; /* NAT_SNAT_IN: primary of the container */
	__u32 pad2;
};

/* Connection tracking for NAT. LRU: idle flows are evicted when it fills. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 262144);
	__type(key, struct nat_key);
	__type(value, struct nat_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} netker_nat SEC(".maps");

struct config {
	__u64 host_netns_cookie;
	__u16 nat_port_min; /* host byte order */
	__u16 nat_port_max;
	__u32 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct config);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} netker_config SEC(".maps");

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

static __always_inline struct config *get_config(void)
{
	__u32 zero = 0;
	return bpf_map_lookup_elem(&netker_config, &zero);
}

static __always_inline struct port_val *lookup_port(__be32 addr, __be16 port, __u8 proto, bool addr_is_local)
{
	struct port_key key = { .addr = addr, .port = port, .proto = proto };
	struct port_val *v = bpf_map_lookup_elem(&netker_ports, &key);

	if (v || !addr_is_local)
		return v;
	key.addr = 0;
	return bpf_map_lookup_elem(&netker_ports, &key);
}
