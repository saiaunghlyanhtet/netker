/* SPDX-License-Identifier: GPL-2.0 */
#pragma once

#include "common.h"

#define EP_F_INTERNAL 0x1 /* network has no external connectivity */
#define EP_F_NO_ICC 0x2   /* no traffic between containers of the network */
#define EP_F_L2 0x4       /* netkit L2 mode: frames carry the container's MAC */

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

/* An IPv6 address as a map key. */
struct ip6_key {
	__u8 addr[16];
};

/* Container IPv6 address -> endpoint, for networks with an IPv6 subnet. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct ip6_key);
	__type(value, struct endpoint);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} netker_endpoints6 SEC(".maps");

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

/* Datapath events for "netker net trace", read through a perf buffer like
 * Cilium's cilium_events. The kernel appends the start of the packet to
 * each event (BPF_F_CTXLEN_MASK), so nothing is parsed here; netker
 * decodes the headers. Without a reader the output fails right away, so
 * events cost close to nothing until someone traces.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} netker_events SEC(".maps");

enum event_type {
	EVENT_DROP = 1,  /* always sent */
	EVENT_TRACE = 2, /* any other verdict, while a tracer holds the lease */
};

struct event_hdr {
	__u8 type;
	__u8 reason;
	__u8 dir;
	__u8 pad;
	__u32 ifindex;
	__u32 len;     /* packet length */
	__u32 cap_len; /* packet bytes after this header */
	__u64 ts;      /* bpf_ktime_get_ns() */
};

#define EVENT_CAP_LEN 128

/* Tracing of non-drop verdicts. A tracer keeps until_ns a few seconds
 * ahead; if it dies, tracing switches itself off.
 */
#define TRACE_F_IFINDEX 0x1 /* only devices in netker_trace_ifindex */

struct trace_cfg {
	__u64 until_ns;
	__u32 flags;
	__u32 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct trace_cfg);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} netker_trace SEC(".maps");

/* Primary ifindexes a tracer watches, with TRACE_F_IFINDEX. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u8);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} netker_trace_ifindex SEC(".maps");

/* Per-CPU scratch space for the 64-byte FIB lookup parameters, which would
 * otherwise take a large share of the 512-byte stack. Nothing runs nested
 * on the same CPU while a program uses it. Not pinned: it holds no state.
 */
/* Opaque to Go: bpf2go can't generate the anonymous unions inside. */
struct fib_scratch {
	__u8 buf[sizeof(struct bpf_fib_lookup)];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct fib_scratch);
} netker_scratch_fib SEC(".maps");

static __always_inline struct bpf_fib_lookup *scratch_fib(void)
{
	__u32 zero = 0;
	struct bpf_fib_lookup *fib = (void *)bpf_map_lookup_elem(&netker_scratch_fib, &zero);

	if (fib)
		__builtin_memset(fib, 0, sizeof(*fib));
	return fib;
}

static __always_inline bool is_drop(__u8 reason)
{
	return reason >= 10;
}

static __always_inline bool tracing(__u32 ifindex)
{
	__u32 zero = 0;
	struct trace_cfg *cfg = bpf_map_lookup_elem(&netker_trace, &zero);

	if (!cfg || cfg->until_ns < bpf_ktime_get_ns())
		return false;
	if ((cfg->flags & TRACE_F_IFINDEX) && !bpf_map_lookup_elem(&netker_trace_ifindex, &ifindex))
		return false;
	return true;
}

static __always_inline void add_metric(__u32 ifindex, __u8 dir, __u8 reason, __u32 len)
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

/* count records a verdict in the metrics and, for drops or while tracing,
 * sends an event with the start of the packet. It's a BPF function of its
 * own rather than inlined: it's called from dozens of places, and inlined
 * copies of the event header pushed the IPv6 path over the 512-byte stack.
 */
static __noinline void count(struct __sk_buff *skb, __u32 ifindex, __u8 dir, __u8 reason)
{
	add_metric(ifindex, dir, reason, skb->len);

	bool drop = is_drop(reason);

	if (!drop && !tracing(ifindex))
		return;
	struct event_hdr ev = {
		.type = drop ? EVENT_DROP : EVENT_TRACE,
		.reason = reason,
		.dir = dir,
		.ifindex = ifindex,
		.len = skb->len,
		.cap_len = skb->len < EVENT_CAP_LEN ? skb->len : EVENT_CAP_LEN,
		.ts = bpf_ktime_get_ns(),
	};
	__u64 flags = ((__u64)ev.cap_len << 32) | BPF_F_CURRENT_CPU;

	bpf_perf_event_output(skb, &netker_events, flags, &ev, sizeof(ev));
}

/* count_sock is count for socket hooks, which have no packet. */
static __always_inline void count_sock(__u32 ifindex, __u8 dir, __u8 reason)
{
	add_metric(ifindex, dir, reason, 0);
}

static __always_inline struct config *get_config(void)
{
	__u32 zero = 0;

	return bpf_map_lookup_elem(&netker_config, &zero);
}

static __always_inline struct port_val *
lookup_port(__be32 addr, __be16 port, __u8 proto, bool addr_is_local)
{
	struct port_key key = { .addr = addr, .port = port, .proto = proto };
	struct port_val *v = bpf_map_lookup_elem(&netker_ports, &key);

	if (v || !addr_is_local)
		return v;
	key.addr = 0;
	return bpf_map_lookup_elem(&netker_ports, &key);
}

/* IPv6 NAT: the same directions as netker_nat, with IPv6 addresses. */
struct nat6_key {
	__u8 saddr[16];
	__u8 daddr[16];
	__be16 sport;
	__be16 dport;
	__u8 proto;
	__u8 dir;
	__u16 pad;
};

struct nat6_val {
	__u8 addr[16];
	__be16 port;
	__u16 pad;
	__u32 ifindex; /* NAT_SNAT_IN: primary of the container */
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 262144);
	__type(key, struct nat6_key);
	__type(value, struct nat6_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} netker_nat6 SEC(".maps");

/* Published ports on IPv6 host addresses; addr all-zero means every one. */
struct port6_key {
	__u8 addr[16];
	__be16 port;
	__u8 proto;
	__u8 pad;
};

struct port6_val {
	__u8 ctr_addr[16];
	__be16 ctr_port;
	__u16 pad;
	__u32 ifindex; /* primary of the container */
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, struct port6_key);
	__type(value, struct port6_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} netker_ports6 SEC(".maps");

static __always_inline struct port6_val *
lookup_port6(const __u8 *addr, __be16 port, __u8 proto, bool addr_is_local)
{
	struct port6_key key = { .port = port, .proto = proto };
	struct port6_val *v;

	__builtin_memcpy(key.addr, addr, 16);
	v = bpf_map_lookup_elem(&netker_ports6, &key);
	if (v || !addr_is_local)
		return v;
	__builtin_memset(key.addr, 0, 16);
	return bpf_map_lookup_elem(&netker_ports6, &key);
}
