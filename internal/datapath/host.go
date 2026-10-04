package datapath

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/saiaunghlyanhtet/netker/internal/config"
)

// NAT source ports. The default Linux ephemeral range is 32768-60999, so
// masqueraded flows never collide with the host's own connections.
const (
	NATPortMin = 61000
	NATPortMax = 65535
)

func (d *Datapath) hostDir() string { return filepath.Join(d.root, "host") }

func (d *Datapath) uplinkPin(ifname string) string {
	return filepath.Join(d.hostDir(), "uplink-"+ifname)
}

func (d *Datapath) connectPin() string  { return filepath.Join(d.hostDir(), "connect4") }
func (d *Datapath) loopbackPin() string { return filepath.Join(d.hostDir(), "loopback") }

// be32 returns addr as the uint32 whose in-memory bytes are in network order,
// which is how the BPF side's __be32 fields read it.
func be32(a netip.Addr) uint32 {
	b := a.As4()
	return binary.NativeEndian.Uint32(b[:])
}

func be16(p uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], p)
	return binary.NativeEndian.Uint16(b[:])
}

func addrFromBE32(v uint32) netip.Addr {
	var b [4]byte
	binary.NativeEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}

func portFromBE16(v uint16) uint16 {
	var b [2]byte
	binary.NativeEndian.PutUint16(b[:], v)
	return binary.BigEndian.Uint16(b[:])
}

// cgroupRoot is where the connect4 hook is attached: every process on the
// host (and in containers, which the hook ignores via the netns cookie).
func cgroupRoot() string {
	if v := os.Getenv("NETKER_CGROUP_ROOT"); v != "" {
		return v
	}
	return "/sys/fs/cgroup"
}

// EnsureHost installs the host-wide parts of the datapath if they're
// missing: config, tcx ingress on lo and on every uplink, and the connect4
// cgroup hook. It's idempotent and runs on every attach.
func (d *Datapath) EnsureHost() error {
	if err := d.Load(); err != nil {
		return err
	}
	if err := os.MkdirAll(d.hostDir(), 0o700); err != nil {
		return err
	}
	if err := d.writeConfig(); err != nil {
		return err
	}
	if err := d.acceptLocalOnLo(); err != nil {
		return err
	}
	if err := d.attachLoopback(); err != nil {
		return err
	}
	uplinks, err := Uplinks()
	if err != nil {
		return err
	}
	for _, l := range uplinks {
		if err := d.attachUplink(l); err != nil {
			return err
		}
	}
	return d.attachConnect4()
}

func (d *Datapath) writeConfig() error {
	cookie, err := netnsCookie()
	if err != nil {
		return err
	}
	cfg := netkerConfig{HostNetnsCookie: cookie, NatPortMin: NATPortMin, NatPortMax: NATPortMax}
	return d.objs.NetkerConfig.Put(uint32(0), cfg)
}

// netnsCookie returns the cookie of the calling thread's network namespace.
func netnsCookie() (uint64, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	c, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_NETNS_COOKIE)
	if err != nil {
		return 0, fmt.Errorf("SO_NETNS_COOKIE: %w", err)
	}
	return c, nil
}

// Uplinks returns the Ethernet devices that routes in the main table point
// at, excluding netkit devices. NETKER_UPLINKS (comma separated) overrides.
func Uplinks() ([]netlink.Link, error) {
	if v := os.Getenv("NETKER_UPLINKS"); v != "" {
		var out []netlink.Link
		for _, name := range strings.Split(v, ",") {
			l, err := netlink.LinkByName(strings.TrimSpace(name))
			if err != nil {
				return nil, fmt.Errorf("uplink %s: %w", name, err)
			}
			out = append(out, l)
		}
		return out, nil
	}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4,
		&netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, err
	}
	seen := map[int]bool{}
	var out []netlink.Link
	add := func(idx int) {
		if idx == 0 || seen[idx] {
			return
		}
		seen[idx] = true
		l, err := netlink.LinkByIndex(idx)
		if err != nil {
			return
		}
		a := l.Attrs()
		if l.Type() == "netkit" || a.EncapType != "ether" || a.Flags&unix.IFF_LOOPBACK != 0 {
			return
		}
		out = append(out, l)
	}
	for _, r := range routes {
		add(r.LinkIndex)
		for _, nh := range r.MultiPath {
			add(nh.LinkIndex)
		}
	}
	return out, nil
}

func (d *Datapath) attachUplink(l netlink.Link) error {
	return d.attachTCX(l, d.uplinkPin(l.Attrs().Name), d.objs.NkFromWorld)
}

const loAcceptLocal = "/proc/sys/net/ipv4/conf/lo/accept_local"

// bpffs can't hold regular files, so the saved value lives in netker's run dir.
func loAcceptLocalSaved() string {
	return filepath.Join(config.DefaultPaths().Run, "lo-accept-local.orig")
}

// acceptLocalOnLo lets replies to the host's own-address connections back in
// through lo. nk_from_container injects them there without a route attached,
// so the input route lookup runs, and fib_validate_source() drops a local
// source address unless accept_local is set (with it, lo passes even strict
// rp_filter). Only locally injected packets ever arrive on lo. The previous
// value is saved so ResetHost can restore it.
func (d *Datapath) acceptLocalOnLo() error {
	cur, err := os.ReadFile(loAcceptLocal)
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(cur)) == "1" {
		return nil
	}
	saved := loAcceptLocalSaved()
	if err := os.MkdirAll(filepath.Dir(saved), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(saved, cur, 0o600); err != nil {
		return err
	}
	return os.WriteFile(loAcceptLocal, []byte("1"), 0o644)
}

// attachLoopback hooks lo ingress, which carries the host's connections to
// its own addresses.
func (d *Datapath) attachLoopback() error {
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return err
	}
	return d.attachTCX(lo, d.loopbackPin(), d.objs.NkFromLo)
}

func (d *Datapath) attachTCX(l netlink.Link, pin string, prog *ebpf.Program) error {
	if existing, err := link.LoadPinnedLink(pin, nil); err == nil {
		info, ierr := existing.Info()
		ok := ierr == nil && info.TCX() != nil && int(info.TCX().Ifindex) == l.Attrs().Index
		existing.Close()
		if ok {
			return nil
		}
		// The interface was recreated: the old link is defunct.
		os.Remove(pin)
	}
	tl, err := link.AttachTCX(link.TCXOptions{
		Interface: l.Attrs().Index,
		Program:   prog,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		return fmt.Errorf("attach tcx ingress to %s: %w", l.Attrs().Name, err)
	}
	defer tl.Close()
	return tl.Pin(pin)
}

func (d *Datapath) attachConnect4() error {
	if l, err := link.LoadPinnedLink(d.connectPin(), nil); err == nil {
		l.Close()
		return nil
	}
	cl, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupRoot(),
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: d.objs.NkSockConnect4,
	})
	if err != nil {
		return fmt.Errorf("attach connect4 hook to %s: %w", cgroupRoot(), err)
	}
	defer cl.Close()
	return cl.Pin(d.connectPin())
}

// HostLink describes a pinned host-wide link.
type HostLink struct {
	Pin       string `json:"pin"`
	Kind      string `json:"kind"` // uplink, loopback or connect4
	Device    string `json:"device,omitempty"`
	ProgramID uint32 `json:"program_id"`
	Defunct   bool   `json:"defunct"`
}

func (d *Datapath) HostLinks() ([]HostLink, error) {
	entries, err := os.ReadDir(d.hostDir())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []HostLink
	for _, e := range entries {
		hl := HostLink{Pin: filepath.Join(d.hostDir(), e.Name()), Kind: e.Name()}
		if dev, ok := strings.CutPrefix(e.Name(), "uplink-"); ok {
			hl.Kind, hl.Device = "uplink", dev
		} else if e.Name() == "loopback" {
			hl.Device = "lo"
		}
		l, err := link.LoadPinnedLink(hl.Pin, nil)
		if err != nil {
			hl.Defunct = true
			out = append(out, hl)
			continue
		}
		if info, err := l.Info(); err == nil {
			hl.ProgramID = uint32(info.Program)
			if t := info.TCX(); t != nil && t.Ifindex == 0 {
				hl.Defunct = true
			}
		}
		l.Close()
		out = append(out, hl)
	}
	return out, nil
}

// ResetHost detaches the host-wide hooks.
func (d *Datapath) ResetHost() error {
	hls, err := d.HostLinks()
	if err != nil {
		return err
	}
	var errs []error
	saved := loAcceptLocalSaved()
	if orig, err := os.ReadFile(saved); err == nil {
		errs = append(errs, os.WriteFile(loAcceptLocal, orig, 0o644), os.Remove(saved))
	}
	for _, hl := range hls {
		if l, err := link.LoadPinnedLink(hl.Pin, nil); err == nil {
			errs = append(errs, l.Unpin())
			l.Close()
		} else if !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, os.Remove(hl.Pin))
		}
	}
	return errors.Join(errs...)
}
