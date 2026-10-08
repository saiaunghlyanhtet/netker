/* SPDX-License-Identifier: GPL-2.0 */
#pragma once

#include <stdbool.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

/* Verdicts, identical to enum netkit_action and TCX. */
#define NETKIT_NEXT -1
#define NETKIT_PASS 0
#define NETKIT_DROP 2
#define NETKIT_REDIRECT 7
#define TCX_NEXT -1
#define TCX_PASS 0
#define TCX_DROP 2

#define IP_CSUM_OFF (ETH_HLEN + __builtin_offsetof(struct iphdr, check))
#define IP_TTL_OFF (ETH_HLEN + __builtin_offsetof(struct iphdr, ttl))
#define IP_SADDR_OFF (ETH_HLEN + __builtin_offsetof(struct iphdr, saddr))
#define IP_DADDR_OFF (ETH_HLEN + __builtin_offsetof(struct iphdr, daddr))

/* ICMP echo header; linux/icmp.h drags in libc headers. */
struct icmp_echo {
	__u8 type;
	__u8 code;
	__be16 checksum;
	__be16 id;
	__be16 seq;
};
#define ICMP_ECHOREPLY 0
#define ICMP_ECHO 8

enum reason {
	REASON_FORWARD_LOCAL = 1, /* redirected to a local container */
	REASON_PASS_STACK = 2,    /* handed to the host stack */
	REASON_PASS_ARP = 3,
	REASON_DELIVER = 4,       /* delivered into the container */
	REASON_SNAT = 5,          /* masqueraded and sent to an uplink */
	REASON_REV_SNAT = 6,      /* reply un-masqueraded into the container */
	REASON_DNAT = 7,          /* published port translated to the container */
	REASON_REV_DNAT = 8,      /* container reply to a published port */
	REASON_DROP_SPOOF = 10,   /* source IP isn't the container's */
	REASON_DROP_POLICY = 11,  /* destination on another network */
	REASON_DROP_NOT_OURS = 12,/* packet for another container's IP */
	REASON_DROP_PROTO = 13,   /* not IPv4 or ARP */
	REASON_DROP_MALFORMED = 14,
	REASON_DROP_NAT_EXHAUSTED = 15,
	REASON_DROP_MCAST = 16,   /* multicast/broadcast sent towards a container */
	REASON_DROP_ICC = 17,     /* container to container on an --icc=false network */
};

enum direction {
	DIR_EGRESS = 0,  /* from the container */
	DIR_INGRESS = 1, /* to the container */
};
