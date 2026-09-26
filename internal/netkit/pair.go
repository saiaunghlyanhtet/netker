// Package netkit creates and manages netkit device pairs (drivers/net/netkit.c)
// that connect containers to the host.
package netkit

import (
	"errors"
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	vnetns "github.com/vishvananda/netns"

	"github.com/saiaunghlyanhtet/netker/internal/netns"
)

type Mode string

const (
	ModeL3 Mode = "l3"
	ModeL2 Mode = "l2"
)

func ParseMode(s string) (Mode, error) {
	switch Mode(s) {
	case "", ModeL3:
		return ModeL3, nil
	case ModeL2:
		return ModeL2, nil
	}
	return "", fmt.Errorf("unknown netkit mode %q (want l3 or l2)", s)
}

// OwnerAltName tags the primary device so netker can find the pairs it owns,
// e.g. during garbage collection after a crash.
func OwnerAltName(containerID string) string { return "netker-" + containerID }

// PairSpec describes one container attachment.
type PairSpec struct {
	ContainerID string
	HostName    string // primary device, stays in the host netns (<= 15 chars)
	PeerName    string // final interface name inside the container, e.g. eth0
	NetNSPath   string // container network namespace
	Mode        Mode
	MTU         int
	// FailClosed sets the peer's default policy to DROP, so container egress
	// is dropped until a BPF program is attached to BPF_NETKIT_PEER.
	FailClosed bool
	HostMAC    net.HardwareAddr // L2 only
	PeerMAC    net.HardwareAddr // L2 only
}

// CreatePair creates the netkit pair in the caller's (host) netns, moves the
// peer into spec.NetNSPath and renames it to spec.PeerName. Both ends are
// left down.
func CreatePair(spec PairSpec) (err error) {
	if len(spec.HostName) > 15 {
		return fmt.Errorf("host device name %q longer than 15 characters", spec.HostName)
	}
	mode := netlink.NETKIT_MODE_L3
	if spec.Mode == ModeL2 {
		mode = netlink.NETKIT_MODE_L2
	} else if spec.HostMAC != nil || spec.PeerMAC != nil {
		return errors.New("MAC addresses can only be set in netkit L2 mode")
	}
	peerPolicy := netlink.NETKIT_POLICY_FORWARD
	if spec.FailClosed {
		peerPolicy = netlink.NETKIT_POLICY_BLACKHOLE
	}

	// The peer is created in the host netns under a temporary name, since
	// the final name (eth0) may already exist on the host.
	tmpPeer := "p" + spec.HostName
	if len(tmpPeer) > 15 {
		tmpPeer = tmpPeer[:15]
	}
	nk := &netlink.Netkit{
		LinkAttrs: netlink.LinkAttrs{
			Name:         spec.HostName,
			MTU:          spec.MTU,
			HardwareAddr: spec.HostMAC,
		},
		Mode:       mode,
		Policy:     netlink.NETKIT_POLICY_FORWARD,
		PeerPolicy: peerPolicy,
		// Keep skb->mark on the host side; scrub what leaves the container
		// so it can't smuggle marks or priorities into the host.
		Scrub:     netlink.NETKIT_SCRUB_NONE,
		PeerScrub: netlink.NETKIT_SCRUB_DEFAULT,
	}
	nk.SetPeerAttrs(&netlink.LinkAttrs{Name: tmpPeer, MTU: spec.MTU, HardwareAddr: spec.PeerMAC})
	if err := netlink.LinkAdd(nk); err != nil {
		return fmt.Errorf("create netkit pair %s: %w", spec.HostName, err)
	}
	defer func() {
		if err != nil {
			_ = netlink.LinkDel(nk)
		}
	}()

	host, err := netlink.LinkByName(spec.HostName)
	if err != nil {
		return err
	}
	if err := netlink.LinkAddAltName(host, OwnerAltName(spec.ContainerID)); err != nil {
		return fmt.Errorf("tag %s: %w", spec.HostName, err)
	}

	peer, err := netlink.LinkByName(tmpPeer)
	if err != nil {
		return err
	}
	target, err := vnetns.GetFromPath(spec.NetNSPath)
	if err != nil {
		return err
	}
	defer target.Close()
	if err := netlink.LinkSetNsFd(peer, int(target)); err != nil {
		return fmt.Errorf("move %s into container netns: %w", tmpPeer, err)
	}
	return netns.DoHandle(target, func() error {
		l, err := netlink.LinkByName(tmpPeer)
		if err != nil {
			return err
		}
		if err := netlink.LinkSetName(l, spec.PeerName); err != nil {
			return fmt.Errorf("rename peer to %s: %w", spec.PeerName, err)
		}
		return nil
	})
}

// Delete removes a pair by its host-side name. The kernel removes the peer
// with it. A missing device is not an error.
func Delete(hostName string) error {
	l, err := netlink.LinkByName(hostName)
	if err != nil {
		var nf netlink.LinkNotFoundError
		if errors.As(err, &nf) {
			return nil
		}
		return err
	}
	return netlink.LinkDel(l)
}

// Owned lists the host-side netkit devices tagged with OwnerAltName, keyed by
// container ID.
func Owned() (map[string]netlink.Link, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	out := map[string]netlink.Link{}
	for _, l := range links {
		if l.Type() != "netkit" {
			continue
		}
		for _, alt := range l.Attrs().AltNames {
			const p = "netker-"
			if len(alt) > len(p) && alt[:len(p)] == p {
				out[alt[len(p):]] = l
			}
		}
	}
	return out, nil
}
