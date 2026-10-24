/* SPDX-License-Identifier: GPL-2.0 */
/* For user hooks: BPF programs attached next to netker's on a container's
 * netkit device, with "netker net hook add" or "netker run --bpf-hook".
 *
 * A hook is a SCHED_CLS program (SEC("tc") or SEC("netkit/peer") etc.;
 * netker sets the attach type). It sees the packet from the Ethernet header
 * and returns one of the verdicts below. netkit runs the programs in order
 * and stops at the first verdict that isn't NETKIT_NEXT.
 *
 *   egress  hooks see what the container sends (netkit peer side),
 *   ingress hooks see what is delivered to it through its primary device.
 *   Packets that reach the container straight from an uplink
 *   (bpf_redirect_peer) don't pass through ingress hooks.
 *
 * Before netker's program (the default), return NETKIT_NEXT to hand the
 * packet on, or NETKIT_DROP. NETKIT_PASS or NETKIT_REDIRECT end the chain
 * there and skip netker's anti-spoofing, isolation and NAT.
 *
 * After netker's program (--after), a hook sees what netker lets through
 * to the host (netker returns NETKIT_NEXT for that); packets netker drops
 * or redirects don't get there.
 */
#pragma once

#define NETKIT_NEXT -1     /* continue with the next program; at the end: pass */
#define NETKIT_PASS 0      /* deliver now, skipping the rest of the chain */
#define NETKIT_DROP 2
#define NETKIT_REDIRECT 7  /* after bpf_redirect*() */
