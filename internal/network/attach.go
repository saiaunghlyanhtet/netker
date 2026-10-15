package network

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/saiaunghlyanhtet/netker/internal/config"
	"github.com/saiaunghlyanhtet/netker/internal/datapath"
	"github.com/saiaunghlyanhtet/netker/internal/ipam"
	"github.com/saiaunghlyanhtet/netker/internal/netkit"
	"github.com/saiaunghlyanhtet/netker/internal/netns"
)

// Endpoint is one container interface on one network.
type Endpoint struct {
	Network string     `json:"network"`
	IfName  string     `json:"ifname"`  // inside the container, e.g. eth0
	HostIf  string     `json:"host_if"` // netkit primary in the host netns
	IP      netip.Addr `json:"ip"`
	Gateway netip.Addr `json:"gateway"`
	// IP6 and Gateway6 are set on networks with an IPv6 subnet.
	IP6      netip.Addr  `json:"ip6,omitzero"`
	Gateway6 netip.Addr  `json:"gateway6,omitzero"`
	Mode     netkit.Mode `json:"netkit_mode"`
	// Default is set on the attachment that carries the default route.
	Default bool `json:"default_route,omitempty"`
	// Datapath is "ebpf" or "legacy", fixed when the endpoint is created.
	Datapath    string `json:"datapath"`
	HostIfIndex int    `json:"host_ifindex"`
}

const (
	DatapathEBPF   = "ebpf"
	DatapathLegacy = "legacy"
)

// HostIfName is the primary device name for attachment index idx of a
// container: "nk" + 11 ID characters + index, at most 15 characters.
func HostIfName(containerID string, idx int) string {
	id := containerID
	if len(id) > 11 {
		id = id[:11]
	}
	return fmt.Sprintf("nk%s%d", id, idx)
}

// Attach connects the container whose network namespace is at nsPath to
// network n as interface eth<idx>. want optionally requests a fixed IP.
// defaultRoute makes this attachment carry the container's default route;
// otherwise it gets a route to its own subnet.
func (s *Store) Attach(n *Network, containerID, nsPath string, idx int, want netip.Addr, defaultRoute bool) (ep *Endpoint, err error) {
	if idx > 9 {
		return nil, fmt.Errorf("at most 10 networks per container")
	}
	pool, err := s.pool(n)
	if err != nil {
		return nil, err
	}
	mode, err := s.datapathMode()
	if err != nil {
		return nil, err
	}
	ip, err := pool.Allocate(containerID, want)
	if err != nil {
		return nil, err
	}
	var ip6 netip.Addr
	var pool6 *ipam.Pool
	if n.HasIPv6() {
		if pool6, err = s.pool6(n); err != nil {
			pool.Release(ip)
			return nil, err
		}
		if ip6, err = pool6.Allocate(containerID, netip.Addr{}); err != nil {
			pool.Release(ip)
			return nil, err
		}
	}
	hostIf := HostIfName(containerID, idx)
	ep = &Endpoint{
		Network:  n.Name,
		IfName:   fmt.Sprintf("eth%d", idx),
		HostIf:   hostIf,
		IP:       ip,
		Gateway:  n.Gateway,
		IP6:      ip6,
		Gateway6: n.Gateway6,
		Mode:     n.Mode,
		Datapath: mode,
		Default:  defaultRoute,
	}
	defer func() {
		// Not ep: "return nil, err" has already cleared it.
		if err != nil {
			_ = netkit.Delete(hostIf)
			if mode == DatapathEBPF {
				_ = s.dp.Detach(containerID, hostIf, ip, ip6)
			}
			_ = pool.Release(ip)
			if pool6 != nil {
				_ = pool6.Release(ip6)
			}
		}
	}()

	spec := netkit.PairSpec{
		ContainerID: containerID,
		Index:       idx,
		HostName:    ep.HostIf,
		PeerName:    ep.IfName,
		NetNSPath:   nsPath,
		Mode:        n.Mode,
		MTU:         n.MTU,
		// With the eBPF datapath the container's egress is dropped until
		// nk_from_container is attached, and whenever it gets detached.
		// The legacy datapath has no program, so it must forward.
		FailClosed: mode == DatapathEBPF,
	}
	if n.Mode == netkit.ModeL2 {
		// Explicit MACs stop systemd's MACAddressPolicy from rewriting them
		// after creation (same workaround as Cilium).
		spec.HostMAC = deterministicMAC(containerID, idx, 0)
		spec.PeerMAC = deterministicMAC(containerID, idx, 1)
	}
	if err := netkit.CreatePair(spec); err != nil {
		return nil, err
	}
	if err := setupHostSide(ep); err != nil {
		return nil, err
	}
	err = netns.Do(nsPath, func() error { return setupContainerSide(ep, n.Subnet, n.Subnet6, defaultRoute) })
	if err != nil {
		return nil, err
	}
	dep, err := datapathEndpoint(n, ep, nsPath)
	if err != nil {
		return nil, err
	}
	ep.HostIfIndex = dep.HostIfIndex
	if mode == DatapathEBPF {
		if err := s.dp.Attach(containerID, dep); err != nil {
			return nil, err
		}
	}
	if err := ensureNetworkRules(n); err != nil {
		return nil, err
	}
	return ep, nil
}

// datapathEndpoint describes ep for the BPF maps, from the live devices:
// the primary in the host netns and the peer in the container's.
func datapathEndpoint(n *Network, ep *Endpoint, nsPath string) (datapath.Endpoint, error) {
	host, err := netlink.LinkByName(ep.HostIf)
	if err != nil {
		return datapath.Endpoint{}, err
	}
	var peer netlink.Link
	err = netns.Do(nsPath, func() error {
		var err error
		peer, err = netlink.LinkByName(ep.IfName)
		return err
	})
	if err != nil {
		return datapath.Endpoint{}, fmt.Errorf("%s in the container: %w", ep.IfName, err)
	}
	return datapath.Endpoint{
		IP:          ep.IP,
		IP6:         ep.IP6,
		HostIf:      ep.HostIf,
		HostIfIndex: host.Attrs().Index,
		PeerIfIndex: peer.Attrs().Index,
		NetID:       datapath.NetID(n.Name),
		Internal:    n.Internal,
		NoICC:       n.NoICC,
		L2:          n.Mode == netkit.ModeL2,
		HostMAC:     host.Attrs().HardwareAddr,
		PeerMAC:     peer.Attrs().HardwareAddr,
	}, nil
}

// datapathMode resolves NETKER_DATAPATH: "auto" picks eBPF when the programs
// load (root with bpffs) and legacy otherwise.
func (s *Store) datapathMode() (string, error) {
	switch m := config.DatapathMode(); m {
	case DatapathLegacy:
		return DatapathLegacy, nil
	case DatapathEBPF:
		if err := s.dp.Load(); err != nil {
			return "", err
		}
		return DatapathEBPF, nil
	case "auto":
		err := s.dp.Load()
		if err == nil {
			return DatapathEBPF, nil
		}
		// Maps from another netker version: new containers would end up
		// on a different datapath than the running ones. Stop instead.
		if errors.Is(err, datapath.ErrIncompatibleMaps) {
			return "", err
		}
		// Unprivileged (or root in a user namespace) the fallback is
		// expected. As real root it hides a real problem, such as the
		// verifier rejecting a program, so say so.
		if os.Geteuid() == 0 && !s.warnedFallback && inInitUserNS() {
			fmt.Fprintf(os.Stderr, "warning: eBPF datapath unavailable, using the legacy datapath: %v\n", err)
			s.warnedFallback = true
		}
		return DatapathLegacy, nil
	default:
		return "", fmt.Errorf("unknown NETKER_DATAPATH %q (want ebpf, legacy or auto)", m)
	}
}

// Detach removes the pair and frees the address. It tolerates a pair that
// is already gone (e.g. the kernel removed it with the netns).
func (s *Store) Detach(ep *Endpoint, containerID string) error {
	var errs []error
	if err := netkit.Delete(ep.HostIf); err != nil {
		errs = append(errs, err)
	}
	if ep.Datapath == DatapathEBPF {
		if err := s.dp.Detach(containerID, ep.HostIf, ep.IP, ep.IP6); err != nil {
			errs = append(errs, err)
		}
		s.dp.ForgetMetrics(ep.HostIfIndex)
	}
	n, err := s.Get(ep.Network)
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			errs = append(errs, err)
		}
		return errors.Join(errs...)
	}
	pool, err := s.pool(n)
	if err == nil {
		err = pool.ReleaseOwner(containerID)
	}
	errs = append(errs, err)
	if n.HasIPv6() {
		pool6, err := s.pool6(n)
		if err == nil {
			err = pool6.ReleaseOwner(containerID)
		}
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func setupHostSide(ep *Endpoint) error {
	host, err := netlink.LinkByName(ep.HostIf)
	if err != nil {
		return err
	}
	// The gateway address lives on every primary of the network. Linux
	// allows the same /32 on several devices; it gives containers a
	// reachable gateway and the host a source address towards them.
	gw := &netlink.Addr{IPNet: hostNet(ep.Gateway), Flags: unix.IFA_F_NOPREFIXROUTE}
	if err := netlink.AddrAdd(host, gw); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("add gateway address: %w", err)
	}
	if err := writeSysctl(fmt.Sprintf("net/ipv4/conf/%s/rp_filter", ep.HostIf), "0"); err != nil {
		return err
	}
	if err := writeSysctl("net/ipv4/ip_forward", "1"); err != nil {
		return err
	}
	if err := netlink.LinkSetUp(host); err != nil {
		return err
	}
	route := &netlink.Route{
		LinkIndex: host.Attrs().Index,
		Dst:       hostNet(ep.IP),
		Scope:     netlink.SCOPE_LINK,
		Src:       net.IP(ep.Gateway.AsSlice()),
	}
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("route to %s: %w", ep.IP, err)
	}
	if ep.IP6.IsValid() {
		return setupHostSide6(host, ep)
	}
	return nil
}

// setupHostSide6 mirrors the IPv4 setup: the IPv6 gateway on the primary
// (without duplicate address detection, it's on every primary of the
// network), a host route to the container, and IPv6 forwarding.
func setupHostSide6(host netlink.Link, ep *Endpoint) error {
	dev := ep.HostIf
	for key, val := range map[string]string{"disable_ipv6": "0", "accept_ra": "0", "autoconf": "0"} {
		if err := writeSysctl(fmt.Sprintf("net/ipv6/conf/%s/%s", dev, key), val); err != nil {
			return err
		}
	}
	gw := &netlink.Addr{IPNet: hostNet(ep.Gateway6), Flags: unix.IFA_F_NOPREFIXROUTE | unix.IFA_F_NODAD}
	if err := netlink.AddrAdd(host, gw); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("add IPv6 gateway address: %w", err)
	}
	if err := enableIPv6Forwarding(); err != nil {
		return err
	}
	route := &netlink.Route{
		LinkIndex: host.Attrs().Index,
		Dst:       hostNet(ep.IP6),
		Scope:     netlink.SCOPE_LINK,
		Src:       net.IP(ep.Gateway6.AsSlice()),
	}
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("route to %s: %w", ep.IP6, err)
	}
	return nil
}

// enableIPv6Forwarding turns on IPv6 forwarding. A forwarding host ignores
// router advertisements on interfaces with accept_ra=1, which would drop
// its own SLAAC addresses and default route, so those interfaces are moved
// to accept_ra=2 (accept RAs even when forwarding) first.
func enableIPv6Forwarding() error {
	cur, err := os.ReadFile("/proc/sys/net/ipv6/conf/all/forwarding")
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(cur)) == "1" {
		return nil
	}
	ifaces, err := os.ReadDir("/proc/sys/net/ipv6/conf")
	if err != nil {
		return err
	}
	for _, e := range ifaces {
		name := e.Name()
		if name == "all" || name == "default" || name == "lo" {
			continue
		}
		p := filepath.Join("net/ipv6/conf", name, "accept_ra")
		if v, err := os.ReadFile(filepath.Join("/proc/sys", p)); err == nil && strings.TrimSpace(string(v)) == "1" {
			if err := writeSysctl(p, "2"); err != nil {
				return err
			}
		}
	}
	return writeSysctl("net/ipv6/conf/all/forwarding", "1")
}

// setupContainerSide configures the container's end. The first attachment
// carries the default route; later ones get a route to their own subnet, so
// traffic to that network leaves through its interface (and BPF sees it on
// the right endpoint).
func setupContainerSide(ep *Endpoint, subnet, subnet6 netip.Prefix, defaultRoute bool) error {
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return err
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		return err
	}
	l, err := netlink.LinkByName(ep.IfName)
	if err != nil {
		return err
	}
	if err := netlink.AddrAdd(l, &netlink.Addr{IPNet: hostNet(ep.IP)}); err != nil {
		return fmt.Errorf("address %s: %w", ep.IP, err)
	}
	// IPv6 only on IPv6 networks; otherwise the container would still send
	// router solicitations and MLD reports (Docker disables it too). With
	// IPv6, addresses come from netker only: no SLAAC, RAs or DAD.
	v6 := map[string]string{"disable_ipv6": "1"}
	if ep.IP6.IsValid() {
		v6 = map[string]string{"disable_ipv6": "0", "accept_ra": "0", "autoconf": "0", "accept_dad": "0"}
	}
	for key, val := range v6 {
		if err := writeSysctl(fmt.Sprintf("net/ipv6/conf/%s/%s", ep.IfName, key), val); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := netlink.LinkSetUp(l); err != nil {
		return err
	}
	if err := netlink.RouteAdd(&netlink.Route{
		LinkIndex: l.Attrs().Index,
		Dst:       hostNet(ep.Gateway),
		Scope:     netlink.SCOPE_LINK,
	}); err != nil {
		return fmt.Errorf("route to gateway: %w", err)
	}
	route := &netlink.Route{
		LinkIndex: l.Attrs().Index,
		Gw:        net.IP(ep.Gateway.AsSlice()),
	}
	if !defaultRoute {
		route.Dst = &net.IPNet{IP: net.IP(subnet.Masked().Addr().AsSlice()), Mask: net.CIDRMask(subnet.Bits(), 32)}
	}
	if err := netlink.RouteAdd(route); err != nil {
		return fmt.Errorf("route via %s: %w", ep.Gateway, err)
	}
	if ep.IP6.IsValid() {
		return setupContainerSide6(l, ep, subnet6, defaultRoute)
	}
	return nil
}

func setupContainerSide6(l netlink.Link, ep *Endpoint, subnet6 netip.Prefix, defaultRoute bool) error {
	if err := netlink.AddrAdd(l, &netlink.Addr{IPNet: hostNet(ep.IP6), Flags: unix.IFA_F_NODAD}); err != nil {
		return fmt.Errorf("address %s: %w", ep.IP6, err)
	}
	if err := netlink.RouteAdd(&netlink.Route{
		LinkIndex: l.Attrs().Index,
		Dst:       hostNet(ep.Gateway6),
		Scope:     netlink.SCOPE_LINK,
	}); err != nil {
		return fmt.Errorf("route to IPv6 gateway: %w", err)
	}
	route := &netlink.Route{
		LinkIndex: l.Attrs().Index,
		Gw:        net.IP(ep.Gateway6.AsSlice()),
	}
	if defaultRoute {
		route.Dst = &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}
	} else {
		route.Dst = &net.IPNet{IP: net.IP(subnet6.Masked().Addr().AsSlice()), Mask: net.CIDRMask(subnet6.Bits(), 128)}
	}
	if err := netlink.RouteAdd(route); err != nil {
		return fmt.Errorf("route via %s: %w", ep.Gateway6, err)
	}
	return nil
}

func hostNet(a netip.Addr) *net.IPNet {
	return &net.IPNet{IP: net.IP(a.AsSlice()), Mask: net.CIDRMask(a.BitLen(), a.BitLen())}
}

// deterministicMAC returns a locally administered unicast MAC derived from
// the container ID, attachment index and side (0 host, 1 container).
func deterministicMAC(containerID string, idx, side int) net.HardwareAddr {
	var b [6]byte
	b[0] = 0x02
	for i := 0; i < 3 && 2*i+1 < len(containerID); i++ {
		var v byte
		fmt.Sscanf(containerID[2*i:2*i+2], "%02x", &v)
		b[1+i] = v
	}
	b[4] = byte(idx)
	b[5] = byte(side)
	return net.HardwareAddr(b[:])
}

func writeSysctl(key, value string) error {
	p := filepath.Join("/proc/sys", key)
	cur, err := os.ReadFile(p)
	if err == nil && string(cur) == value+"\n" {
		return nil
	}
	if err := os.WriteFile(p, []byte(value), 0o644); err != nil {
		return fmt.Errorf("sysctl %s=%s: %w", key, value, err)
	}
	return nil
}

// SetDefaultRoute moves the container's default route to ep, e.g. after the
// attachment that carried it was disconnected.
func (s *Store) SetDefaultRoute(nsPath string, ep *Endpoint) error {
	err := netns.Do(nsPath, func() error {
		l, err := netlink.LinkByName(ep.IfName)
		if err != nil {
			return err
		}
		if err := netlink.RouteReplace(&netlink.Route{
			LinkIndex: l.Attrs().Index,
			Gw:        net.IP(ep.Gateway.AsSlice()),
		}); err != nil {
			return err
		}
		if !ep.IP6.IsValid() {
			return nil
		}
		return netlink.RouteReplace(&netlink.Route{
			LinkIndex: l.Attrs().Index,
			Dst:       &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
			Gw:        net.IP(ep.Gateway6.AsSlice()),
		})
	})
	if err != nil {
		return fmt.Errorf("default route via %s: %w", ep.IfName, err)
	}
	ep.Default = true
	return nil
}

// inInitUserNS reports whether netker runs in the initial user namespace,
// where root can load BPF.
func inInitUserNS() bool {
	b, err := os.ReadFile("/proc/self/uid_map")
	if err != nil {
		return false
	}
	f := strings.Fields(string(b))
	return len(f) == 3 && f[0] == "0" && f[1] == "0" && f[2] == "4294967295"
}
