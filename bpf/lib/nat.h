/* SPDX-License-Identifier: GPL-2.0 */
#pragma once

#include "maps.h"
#include "l4.h"

#define NAT_ALLOC_TRIES 32

static __always_inline void snat_keys(struct nat_key *out, struct nat_key *in,
				      __be32 ctr_addr, __be16 ctr_port,
				      __be32 remote, __be16 remote_port,
				      __be32 nat_addr, __be16 nat_port, __u8 proto, bool echo)
{
	*out = (struct nat_key){
		.saddr = ctr_addr, .daddr = remote,
		.sport = ctr_port, .dport = remote_port,
		.proto = proto, .dir = NAT_SNAT_OUT,
	};
	/* The reply as it arrives on the uplink. For ICMP echo the identifier
	 * sits in both "port" slots.
	 */
	*in = (struct nat_key){
		.saddr = remote, .daddr = nat_addr,
		.sport = echo ? nat_port : remote_port, .dport = nat_port,
		.proto = proto, .dir = NAT_SNAT_IN,
	};
}

/* snat_lookup_or_alloc returns the masquerade address/port for a container
 * flow, allocating a port for new flows. Returns NULL when no port is free.
 */
static __always_inline struct nat_val *
snat_lookup_or_alloc(const struct l4 *l, __be32 ctr_addr, __be32 remote, __be32 nat_addr,
		     __u32 ctr_ifindex)
{
	struct nat_key out, in;
	struct nat_val *v;

	snat_keys(&out, &in, ctr_addr, l->sport, remote, l->dport, nat_addr, 0, l->proto, l->is_echo);
	v = bpf_map_lookup_elem(&netker_nat, &out);
	if (v && v->addr == nat_addr)
		return v;

	struct config *cfg = get_config();
	if (!cfg || cfg->nat_port_max <= cfg->nat_port_min)
		return NULL;
	__u32 span = (__u32)cfg->nat_port_max - cfg->nat_port_min + 1;
	struct nat_val rev = { .addr = ctr_addr, .port = l->sport, .ifindex = ctr_ifindex };

	/* Probe random ports; the reverse entry doubles as the "port in use"
	 * marker for this remote address/port.
	 */
	for (int i = 0; i < NAT_ALLOC_TRIES; i++) {
		__u16 port = cfg->nat_port_min + bpf_get_prandom_u32() % span;
		__be16 nport = bpf_htons(port);

		snat_keys(&out, &in, ctr_addr, l->sport, remote, l->dport, nat_addr, nport,
			  l->proto, l->is_echo);
		if (bpf_map_update_elem(&netker_nat, &in, &rev, BPF_NOEXIST) != 0)
			continue;
		struct nat_val fwd = { .addr = nat_addr, .port = nport };
		if (bpf_map_update_elem(&netker_nat, &out, &fwd, BPF_ANY) != 0) {
			bpf_map_delete_elem(&netker_nat, &in);
			return NULL;
		}
		return bpf_map_lookup_elem(&netker_nat, &out);
	}
	return NULL;
}
