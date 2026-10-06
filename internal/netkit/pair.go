// Package netkit creates and manages netkit device pairs (drivers/net/netkit.c)
// that connect containers to the host.
package netkit

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

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

// OwnerAltName tags a container's primary device for attachment idx so
// netker can find the pairs it owns, e.g. during garbage collection after a
// crash. Altnames are unique per netns, hence one per attachment.
func OwnerAltName(containerID string, idx int) string {
	return fmt.Sprintf("netker-%s-%d", containerID, idx)
}

// ownerOf returns the container ID in an altname written by OwnerAltName,
// or by netker versions that tagged only one device as "netker-<id>".
func ownerOf(alt string) (string, bool) {
	rest, ok := strings.CutPrefix(alt, "netker-")
	if !ok || rest == "" {
		return "", false
	}
	if i := strings.LastIndexByte(rest, '-'); i > 0 {
		if _, err := strconv.Atoi(rest[i+1:]); err == nil {
			return rest[:i], true
		}
	}
	return rest, true
}

// PairSpec describes one container attachment.
type PairSpec struct {
	ContainerID string
	Index       int    // attachment number: eth<Index> in the container
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
	if err := netlink.LinkAddAltName(host, OwnerAltName(spec.ContainerID, spec.Index)); err != nil {
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

// Owned lists the host-side netkit devices tagged by OwnerAltName, keyed by
// container ID.
func Owned() (map[string][]netlink.Link, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	out := map[string][]netlink.Link{}
	for _, l := range links {
		if l.Type() != "netkit" {
			continue
		}
		for _, alt := range l.Attrs().AltNames {
			if id, ok := ownerOf(alt); ok {
				out[id] = append(out[id], l)
			}
		}
	}
	return out, nil
}

// DeviceInfo is a netkit device's configuration as the kernel reports it.
// Older iproute2 (before netkit support) only shows the link kind.
type DeviceInfo struct {
	Name       string `json:"name"`
	Mode       Mode   `json:"mode"`
	Primary    bool   `json:"primary"`
	Policy     string `json:"policy"`      // pass or drop, when no program is attached
	PeerPolicy string `json:"peer_policy"` // same, for the peer
	Scrub      string `json:"scrub,omitempty"`
	PeerScrub  string `json:"peer_scrub,omitempty"`
}

func policyName(p netlink.NetkitPolicy) string {
	switch p {
	case netlink.NETKIT_POLICY_FORWARD:
		return "pass"
	case netlink.NETKIT_POLICY_BLACKHOLE:
		return "drop"
	}
	return fmt.Sprintf("unknown(%d)", p)
}

func scrubName(s netlink.NetkitScrub) string {
	if s == netlink.NETKIT_SCRUB_NONE {
		return "none"
	}
	return "default"
}

// Describe reads a netkit device's attributes over netlink.
func Describe(name string) (*DeviceInfo, error) {
	l, err := netlink.LinkByName(name)
	if err != nil {
		return nil, err
	}
	nk, ok := l.(*netlink.Netkit)
	if !ok {
		return nil, fmt.Errorf("%s is a %s device, not netkit", name, l.Type())
	}
	info := &DeviceInfo{
		Name:       name,
		Mode:       ModeL3,
		Primary:    nk.IsPrimary(),
		Policy:     policyName(nk.Policy),
		PeerPolicy: policyName(nk.PeerPolicy),
	}
	if nk.Mode == netlink.NETKIT_MODE_L2 {
		info.Mode = ModeL2
	}
	if nk.SupportsScrub() {
		info.Scrub, info.PeerScrub = scrubName(nk.Scrub), scrubName(nk.PeerScrub)
	}
	return info, nil
}
