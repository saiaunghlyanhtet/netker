// SPDX-License-Identifier: GPL-2.0
/* Example netker hook: drop TCP packets to one destination port, IPv4 and
 * IPv6, and let everything else continue to netker's program.
 *
 *   clang -O2 -g -target bpf -I../../bpf/include -c drop_tcp_port.c -o drop_tcp_port.o
 *   sudo netker net hook add web egress drop_tcp_port.o
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "netker_hook.h"

#define BLOCKED_PORT 80

SEC("tc")
int drop_tcp_port(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	struct tcphdr *tcp;

	if ((void *)(eth + 1) > data_end)
		return NETKIT_NEXT;
	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = (void *)(eth + 1);
		if ((void *)(ip + 1) > data_end || ip->protocol != IPPROTO_TCP)
			return NETKIT_NEXT;
		tcp = (void *)ip + ip->ihl * 4;
	} else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = (void *)(eth + 1);
		if ((void *)(ip6 + 1) > data_end || ip6->nexthdr != IPPROTO_TCP)
			return NETKIT_NEXT;
		tcp = (void *)(ip6 + 1);
	} else {
		return NETKIT_NEXT;
	}
	if ((void *)(tcp + 1) > data_end)
		return NETKIT_NEXT;
	return tcp->dest == bpf_htons(BLOCKED_PORT) ? NETKIT_DROP : NETKIT_NEXT;
}

char __license[] SEC("license") = "GPL";
