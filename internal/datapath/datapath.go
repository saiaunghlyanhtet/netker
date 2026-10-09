// Package datapath loads netker's eBPF programs and attaches them to netkit
// devices through pinned BPF links, so the datapath keeps working after the
// CLI exits.
package datapath

import (
	"errors"
	"fmt"
	"hash/crc32"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Endpoint is what the datapath needs to know about one container interface.
type Endpoint struct {
	IP          netip.Addr
	HostIf      string
	HostIfIndex int
	PeerIfIndex int // ifindex inside the container netns
	NetID       uint32
	Internal    bool // network without external connectivity
	NoICC       bool // no traffic between containers of the network
	L2          bool // netkit L2 mode: enforce the container's MAC
	HostMAC     net.HardwareAddr
	PeerMAC     net.HardwareAddr
}

// Endpoint flags, EP_F_* in bpf/lib/maps.h.
const (
	flagInternal = 0x1
	flagNoICC    = 0x2
	flagL2       = 0x4
)

// NetID derives a network's numeric ID from its name.
func NetID(network string) uint32 { return crc32.ChecksumIEEE([]byte(network)) }

type Datapath struct {
	root string
	objs *netkerObjects
}

func New(root string) *Datapath { return &Datapath{root: root} }

func (d *Datapath) mapsDir() string  { return filepath.Join(d.root, "maps") }
func (d *Datapath) linksDir() string { return filepath.Join(d.root, "links") }

func (d *Datapath) linkPin(containerID, hostIf, side string) string {
	return filepath.Join(d.linksDir(), containerID, hostIf+"-"+side)
}

// Load loads the programs and opens (or creates) the pinned maps. It fails
// without CAP_BPF/CAP_NET_ADMIN in the initial user namespace.
func (d *Datapath) Load() error {
	if d.objs != nil {
		return nil
	}
	if err := os.MkdirAll(d.mapsDir(), 0o700); err != nil {
		return fmt.Errorf("bpffs: %w", err)
	}
	var objs netkerObjects
	err := loadNetkerObjects(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: d.mapsDir()},
	})
	if err != nil {
		return fmt.Errorf("load eBPF datapath: %w", err)
	}
	d.objs = &objs
	return nil
}

func (d *Datapath) Close() error {
	if d.objs == nil {
		return nil
	}
	err := d.objs.Close()
	d.objs = nil
	return err
}

// Attach publishes the endpoint in the map and attaches both programs.
func (d *Datapath) Attach(containerID string, ep Endpoint) (err error) {
	if err := d.Load(); err != nil {
		return err
	}
	val := netkerEndpoint{
		Ifindex:     uint32(ep.HostIfIndex),
		PeerIfindex: uint32(ep.PeerIfIndex),
		Netid:       ep.NetID,
	}
	if ep.Internal {
		val.Flags |= flagInternal
	}
	if ep.NoICC {
		val.Flags |= flagNoICC
	}
	if ep.L2 {
		val.Flags |= flagL2
	}
	copy(val.Mac[:], ep.HostMAC)
	copy(val.PeerMac[:], ep.PeerMAC)
	key := ep.IP.As4()
	if err := d.objs.NetkerEndpoints.Put(key, val); err != nil {
		return fmt.Errorf("endpoint map: %w", err)
	}
	defer func() {
		if err != nil {
			d.Detach(containerID, ep.HostIf, ep.IP)
		}
	}()
	if err := os.MkdirAll(filepath.Join(d.linksDir(), containerID), 0o700); err != nil {
		return err
	}
	for _, a := range []struct {
		side string
		prog *ebpf.Program
		typ  ebpf.AttachType
	}{
		{"peer", d.objs.NkFromContainer, ebpf.AttachNetkitPeer},
		{"primary", d.objs.NkToContainer, ebpf.AttachNetkitPrimary},
	} {
		l, err := link.AttachNetkit(link.NetkitOptions{Interface: ep.HostIfIndex, Program: a.prog, Attach: a.typ})
		if err != nil {
			return fmt.Errorf("attach %s program to %s: %w", a.side, ep.HostIf, err)
		}
		err = l.Pin(d.linkPin(containerID, ep.HostIf, a.side))
		l.Close()
		if err != nil {
			return fmt.Errorf("pin %s link: %w", a.side, err)
		}
	}
	return d.EnsureHost()
}

// Detach removes the endpoint and releases its links. Missing pieces are
// not an error.
func (d *Datapath) Detach(containerID, hostIf string, ip netip.Addr) error {
	var errs []error
	if err := d.Load(); err != nil {
		return err
	}
	if err := d.objs.NetkerEndpoints.Delete(ip.As4()); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		errs = append(errs, err)
	}
	for _, side := range []string{"peer", "primary"} {
		p := d.linkPin(containerID, hostIf, side)
		l, err := link.LoadPinnedLink(p, nil)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			// A defunct link (device already gone) may not load; drop the pin.
			os.Remove(p)
			continue
		}
		if err := l.Unpin(); err != nil {
			errs = append(errs, err)
		}
		l.Close()
	}
	os.Remove(filepath.Join(d.linksDir(), containerID))
	return errors.Join(errs...)
}

// GC removes pinned links of containers that keep reports as gone, and
// endpoint entries whose primary device no longer exists.
func (d *Datapath) GC(keep func(containerID string) bool) (links, entries int, err error) {
	if err := d.Load(); err != nil {
		return 0, 0, err
	}
	cids, _ := os.ReadDir(d.linksDir())
	for _, c := range cids {
		if keep(c.Name()) {
			continue
		}
		dir := filepath.Join(d.linksDir(), c.Name())
		pins, _ := os.ReadDir(dir)
		for _, p := range pins {
			path := filepath.Join(dir, p.Name())
			if l, err := link.LoadPinnedLink(path, nil); err == nil {
				l.Unpin()
				l.Close()
			} else {
				os.Remove(path)
			}
			links++
		}
		os.Remove(dir)
	}
	var key [4]byte
	var val netkerEndpoint
	var stale [][4]byte
	it := d.objs.NetkerEndpoints.Iterate()
	for it.Next(&key, &val) {
		if _, err := net.InterfaceByIndex(int(val.Ifindex)); err != nil {
			stale = append(stale, key)
		}
	}
	for _, k := range stale {
		if d.objs.NetkerEndpoints.Delete(k) == nil {
			entries++
		}
	}
	if err := it.Err(); err != nil {
		return links, entries, err
	}
	// Published ports whose container is gone.
	var pk netkerPortKey
	var pv netkerPortVal
	var stalePorts []netkerPortKey
	pit := d.objs.NetkerPorts.Iterate()
	for pit.Next(&pk, &pv) {
		var ep netkerEndpoint
		addr := addrFromBE32(pv.CtrAddr).As4()
		if d.objs.NetkerEndpoints.Lookup(addr, &ep) != nil {
			stalePorts = append(stalePorts, pk)
		}
	}
	for _, k := range stalePorts {
		if d.objs.NetkerPorts.Delete(k) == nil {
			entries++
		}
	}
	// Uplink links of interfaces that disappeared.
	hls, _ := d.HostLinks()
	for _, hl := range hls {
		if hl.Defunct {
			os.Remove(hl.Pin)
			links++
		}
	}
	return links, entries, pit.Err()
}

// EndpointEntry is one row of the endpoint map.
type EndpointEntry struct {
	IP          netip.Addr `json:"ip"`
	Ifindex     uint32     `json:"ifindex"`
	PeerIfindex uint32     `json:"peer_ifindex"`
	NetID       uint32     `json:"netid"`
}

func (d *Datapath) Endpoints() ([]EndpointEntry, error) {
	if err := d.Load(); err != nil {
		return nil, err
	}
	var out []EndpointEntry
	var key [4]byte
	var val netkerEndpoint
	it := d.objs.NetkerEndpoints.Iterate()
	for it.Next(&key, &val) {
		out = append(out, EndpointEntry{netip.AddrFrom4(key), val.Ifindex, val.PeerIfindex, val.Netid})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP.Less(out[j].IP) })
	return out, it.Err()
}

// LinkInfo describes one pinned link.
type LinkInfo struct {
	Container string `json:"container"`
	Pin       string `json:"pin"`
	Side      string `json:"side"`
	ProgramID uint32 `json:"program_id"`
	Ifindex   uint32 `json:"ifindex"`
	Defunct   bool   `json:"defunct"`
}

// Links lists all pinned links.
func (d *Datapath) Links() ([]LinkInfo, error) {
	var out []LinkInfo
	cids, err := os.ReadDir(d.linksDir())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	for _, c := range cids {
		pins, _ := os.ReadDir(filepath.Join(d.linksDir(), c.Name()))
		for _, p := range pins {
			path := filepath.Join(d.linksDir(), c.Name(), p.Name())
			li := LinkInfo{Container: c.Name(), Pin: path, Side: sideOf(p.Name())}
			l, err := link.LoadPinnedLink(path, nil)
			if err != nil {
				li.Defunct = true
				out = append(out, li)
				continue
			}
			if info, err := l.Info(); err == nil {
				li.ProgramID = uint32(info.Program)
				if nk := info.Netkit(); nk != nil {
					li.Ifindex = nk.Ifindex
					li.Defunct = nk.Ifindex == 0
				}
			}
			l.Close()
			out = append(out, li)
		}
	}
	return out, nil
}

func sideOf(pin string) string {
	for _, s := range []string{"peer", "primary"} {
		if len(pin) > len(s) && pin[len(pin)-len(s):] == s {
			return s
		}
	}
	return ""
}

// Upgrade loads the current programs and atomically swaps them into every
// pinned link (netkit_link_update, BPF_F_REPLACE). Returns the number of
// links updated.
func (d *Datapath) Upgrade() (int, error) {
	if err := d.Load(); err != nil {
		return 0, err
	}
	links, err := d.Links()
	if err != nil {
		return 0, err
	}
	hostLinks, err := d.HostLinks()
	if err != nil {
		return 0, err
	}
	type target struct {
		pin  string
		prog *ebpf.Program
	}
	var targets []target
	for _, li := range links {
		if li.Defunct {
			continue
		}
		prog := d.objs.NkFromContainer
		if li.Side == "primary" {
			prog = d.objs.NkToContainer
		}
		targets = append(targets, target{li.Pin, prog})
	}
	for _, hl := range hostLinks {
		if hl.Defunct {
			continue
		}
		prog := d.objs.NkFromWorld
		switch hl.Kind {
		case "connect4":
			prog = d.objs.NkSockConnect4
		case "loopback":
			prog = d.objs.NkFromLo
		}
		targets = append(targets, target{hl.Pin, prog})
	}
	n := 0
	var errs []error
	for _, t := range targets {
		l, err := link.LoadPinnedLink(t.pin, nil)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := l.Update(t.prog); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", t.pin, err))
		} else {
			n++
		}
		l.Close()
	}
	return n, errors.Join(errs...)
}

// Reasons names the datapath's metric reasons (enum reason in bpf/netker.c).
var Reasons = map[uint8]string{
	1: "forward-local", 2: "pass-stack", 3: "pass-arp", 4: "deliver",
	5: "snat", 6: "rev-snat", 7: "dnat", 8: "rev-dnat",
	10: "drop-spoof", 11: "drop-policy", 12: "drop-not-ours", 13: "drop-proto", 14: "drop-malformed",
	15: "drop-nat-exhausted", 16: "drop-mcast", 17: "drop-icc", 18: "drop-spoof-mac",
}

type Metric struct {
	Ifindex   uint32 `json:"ifindex"`
	Direction string `json:"direction"`
	Reason    string `json:"reason"`
	Packets   uint64 `json:"packets"`
	Bytes     uint64 `json:"bytes"`
}

// Metrics sums the per-CPU counters.
func (d *Datapath) Metrics() ([]Metric, error) {
	if err := d.Load(); err != nil {
		return nil, err
	}
	var out []Metric
	var key netkerMetricsKey
	var vals []netkerMetricsVal
	it := d.objs.NetkerMetrics.Iterate()
	for it.Next(&key, &vals) {
		m := Metric{Ifindex: key.Ifindex, Direction: "egress", Reason: Reasons[key.Reason]}
		if key.Dir == 1 {
			m.Direction = "ingress"
		}
		for _, v := range vals {
			m.Packets += v.Packets
			m.Bytes += v.Bytes
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Ifindex != out[j].Ifindex {
			return out[i].Ifindex < out[j].Ifindex
		}
		return out[i].Reason < out[j].Reason
	})
	return out, it.Err()
}

// ForgetMetrics deletes the counters of a removed endpoint.
func (d *Datapath) ForgetMetrics(ifindex int) {
	if d.Load() != nil {
		return
	}
	var key netkerMetricsKey
	var vals []netkerMetricsVal
	var stale []netkerMetricsKey
	it := d.objs.NetkerMetrics.Iterate()
	for it.Next(&key, &vals) {
		if key.Ifindex == uint32(ifindex) {
			stale = append(stale, key)
		}
	}
	for _, k := range stale {
		d.objs.NetkerMetrics.Delete(k)
	}
}
