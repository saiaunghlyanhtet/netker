package network

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/saiaunghlyanhtet/netker/internal/config"
	"github.com/saiaunghlyanhtet/netker/internal/netkit"
	"github.com/saiaunghlyanhtet/netker/internal/netns"
)

// These tests create real netkit devices. Run them unprivileged with:
//
//	unshare -rnm go test ./internal/network/
func requireNetAdmin(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs CAP_NET_ADMIN; run under `unshare -rnm`")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed")
	}
}

func testStore(t *testing.T) (*Store, config.Paths) {
	dir := t.TempDir()
	p := config.Paths{Root: filepath.Join(dir, "root"), Run: filepath.Join(dir, "run")}
	return NewStore(p), p
}

func newNS(t *testing.T, p config.Paths, name string) string {
	t.Helper()
	path := filepath.Join(p.NetNS(), name)
	if err := netns.Create(path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { netns.Delete(path) })
	return path
}

// listenIn opens a TCP listener inside the namespace at nsPath. The socket
// stays bound to that namespace after the goroutine switches back.
func listenIn(t *testing.T, nsPath, addr string) net.Listener {
	t.Helper()
	var ln net.Listener
	listen := func() error {
		var err error
		ln, err = net.Listen("tcp4", addr)
		return err
	}
	var err error
	if nsPath == "" {
		err = listen()
	} else {
		err = netns.Do(nsPath, listen)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			fmt.Fprint(c, "hello from netker")
			c.Close()
		}
	}()
	return ln
}

func dialIn(nsPath, addr string) (string, error) {
	var got []byte
	fn := func() error {
		c, err := net.DialTimeout("tcp4", addr, 2*time.Second)
		if err != nil {
			return err
		}
		defer c.Close()
		got, err = io.ReadAll(c)
		return err
	}
	var err error
	if nsPath == "" {
		err = fn()
	} else {
		err = netns.Do(nsPath, fn)
	}
	return string(got), err
}

func TestAttachL3(t *testing.T) {
	requireNetAdmin(t)
	s, p := testStore(t)
	n, err := s.Get(DefaultName)
	if err != nil {
		t.Fatal(err)
	}
	id := "0123456789abcdef"
	ns := newNS(t, p, id)
	ep, err := s.Attach(n, id, ns, 0, netip.Addr{}, true)
	if err != nil {
		t.Fatal(err)
	}
	if ep.IP != netip.MustParseAddr("10.87.0.2") || ep.IfName != "eth0" || ep.HostIf != "nk0123456789a0" {
		t.Fatalf("unexpected endpoint %+v", ep)
	}

	host, err := netlink.LinkByName(ep.HostIf)
	if err != nil {
		t.Fatal(err)
	}
	nk, ok := host.(*netlink.Netkit)
	if !ok || !nk.IsPrimary() || nk.Mode != netlink.NETKIT_MODE_L3 {
		t.Fatalf("host device is not an L3 netkit primary: %#v", host)
	}
	if owned, _ := netkit.Owned(); len(owned[id]) != 1 {
		t.Fatalf("host device not tagged with owner altname")
	}

	err = netns.Do(ns, func() error {
		l, err := netlink.LinkByName("eth0")
		if err != nil {
			return err
		}
		if nk, ok := l.(*netlink.Netkit); !ok || nk.IsPrimary() {
			return fmt.Errorf("eth0 is not a netkit peer: %#v", l)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// host -> container
	listenIn(t, ns, ep.IP.String()+":8080")
	if got, err := dialIn("", ep.IP.String()+":8080"); err != nil || got != "hello from netker" {
		t.Fatalf("host->container: %q, %v", got, err)
	}
	// container -> gateway (the host)
	listenIn(t, "", ep.Gateway.String()+":8081")
	if got, err := dialIn(ns, ep.Gateway.String()+":8081"); err != nil || got != "hello from netker" {
		t.Fatalf("container->gateway: %q, %v", got, err)
	}

	if err := s.Detach(ep, id); err != nil {
		t.Fatal(err)
	}
	if _, err := netlink.LinkByName(ep.HostIf); err == nil {
		t.Fatal("host device still exists after detach")
	}
}

func TestContainerToContainer(t *testing.T) {
	requireNetAdmin(t)
	s, p := testStore(t)
	n, err := s.Get(DefaultName)
	if err != nil {
		t.Fatal(err)
	}
	a, b := "aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb"
	nsA, nsB := newNS(t, p, a), newNS(t, p, b)
	epA, err := s.Attach(n, a, nsA, 0, netip.Addr{}, true)
	if err != nil {
		t.Fatal(err)
	}
	epB, err := s.Attach(n, b, nsB, 0, netip.Addr{}, true)
	if err != nil {
		t.Fatal(err)
	}
	listenIn(t, nsB, epB.IP.String()+":9000")
	if got, err := dialIn(nsA, epB.IP.String()+":9000"); err != nil || got != "hello from netker" {
		t.Fatalf("A->B: %q, %v", got, err)
	}
	s.Detach(epA, a)
	s.Detach(epB, b)
}

func TestAttachL2(t *testing.T) {
	requireNetAdmin(t)
	s, p := testStore(t)
	n := &Network{Name: "l2net", Subnet: netip.MustParsePrefix("10.99.0.0/24"), Mode: netkit.ModeL2}
	if err := s.Create(n); err != nil {
		t.Fatal(err)
	}
	id := "cccccccccccccccc"
	ns := newNS(t, p, id)
	ep, err := s.Attach(n, id, ns, 0, netip.Addr{}, true)
	if err != nil {
		t.Fatal(err)
	}
	host, _ := netlink.LinkByName(ep.HostIf)
	if nk, ok := host.(*netlink.Netkit); !ok || nk.Mode != netlink.NETKIT_MODE_L2 {
		t.Fatalf("host device is not L2 netkit: %#v", host)
	}
	if host.Attrs().HardwareAddr.String() != deterministicMAC(id, 0, 0).String() {
		t.Fatalf("host MAC %s", host.Attrs().HardwareAddr)
	}
	listenIn(t, ns, ep.IP.String()+":8080")
	if got, err := dialIn("", ep.IP.String()+":8080"); err != nil || got != "hello from netker" {
		t.Fatalf("host->container over L2: %q, %v", got, err)
	}
	s.Detach(ep, id)
}

func TestPublishPorts(t *testing.T) {
	requireNetAdmin(t)
	s, p := testStore(t)
	n, _ := s.Get(DefaultName)
	id := "dddddddddddddddd"
	ns := newNS(t, p, id)
	ep, err := s.Attach(n, id, ns, 0, netip.Addr{}, true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Detach(ep, id)

	// A "public" host address to publish on.
	dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "pub0"}}
	if err := netlink.LinkAdd(dummy); err != nil {
		t.Fatal(err)
	}
	defer netlink.LinkDel(dummy)
	netlink.AddrAdd(dummy, &netlink.Addr{IPNet: hostNet(netip.MustParseAddr("192.0.2.10"))})
	netlink.LinkSetUp(dummy)

	listenIn(t, ns, ep.IP.String()+":80")
	if err := PublishPorts(id, ep.IP.String(), []PortMapping{{HostPort: 8080, ContainerPort: 80, Protocol: "tcp"}}); err != nil {
		t.Fatal(err)
	}
	if got, err := dialIn("", "192.0.2.10:8080"); err != nil || got != "hello from netker" {
		t.Fatalf("published port: %q, %v", got, err)
	}
	if err := UnpublishPorts(id); err != nil {
		t.Fatal(err)
	}
	if _, err := dialIn("", "192.0.2.10:8080"); err == nil {
		t.Fatal("port still published after UnpublishPorts")
	}
}

func TestMultipleNetworks(t *testing.T) {
	requireNetAdmin(t)
	s, p := testStore(t)
	n1, err := s.Get(DefaultName)
	if err != nil {
		t.Fatal(err)
	}
	n2 := &Network{Name: "second", Subnet: netip.MustParsePrefix("10.95.0.0/24")}
	if err := s.Create(n2); err != nil {
		t.Fatal(err)
	}
	a, b := "eeeeeeeeeeeeeeee", "ffffffffffffffff"
	nsA, nsB := newNS(t, p, a), newNS(t, p, b)
	epA0, err := s.Attach(n1, a, nsA, 0, netip.Addr{}, true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Detach(epA0, a)
	epA1, err := s.Attach(n2, a, nsA, 1, netip.Addr{}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Detach(epA1, a)
	epB, err := s.Attach(n2, b, nsB, 0, netip.Addr{}, true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Detach(epB, b)

	if epA1.IfName != "eth1" || !n2.Subnet.Contains(epA1.IP) {
		t.Fatalf("second attachment: %+v", epA1)
	}
	// Traffic to the second network must leave through eth1; the default
	// route stays on eth0.
	err = netns.Do(nsA, func() error {
		for dst, want := range map[string]string{epB.IP.String(): "eth1", "1.1.1.1": "eth0"} {
			routes, err := netlink.RouteGet(net.ParseIP(dst))
			if err != nil {
				return err
			}
			l, err := netlink.LinkByIndex(routes[0].LinkIndex)
			if err != nil {
				return err
			}
			if l.Attrs().Name != want {
				return fmt.Errorf("route to %s via %s, want %s", dst, l.Attrs().Name, want)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	listenIn(t, nsB, epB.IP.String()+":9000")
	if got, err := dialIn(nsA, epB.IP.String()+":9000"); err != nil || got != "hello from netker" {
		t.Fatalf("A->B over the second network: %q, %v", got, err)
	}
	if epA1.Datapath == DatapathEBPF && metric(t, s, epA1.HostIfIndex, "forward-local") == 0 {
		t.Fatal("traffic on eth1 was not forwarded in BPF on the eth1 endpoint")
	}
}

// TestHotplugAndDefaultRouteMove is what "network connect/disconnect" do:
// attach to a namespace that already has an interface, detach the one with
// the default route, and move the default route to what's left.
func TestHotplugAndDefaultRouteMove(t *testing.T) {
	requireNetAdmin(t)
	s, p := testStore(t)
	n1, _ := s.Get(DefaultName)
	n2 := &Network{Name: "hot", Subnet: netip.MustParsePrefix("10.93.0.0/24")}
	if err := s.Create(n2); err != nil {
		t.Fatal(err)
	}
	id := "1212121212121212"
	ns := newNS(t, p, id)
	ep0, err := s.Attach(n1, id, ns, 0, netip.Addr{}, true)
	if err != nil {
		t.Fatal(err)
	}
	ep1, err := s.Attach(n2, id, ns, 1, netip.Addr{}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Detach(ep1, id)
	if ep1.Default || !ep0.Default {
		t.Fatalf("default flags: eth0 %v, eth1 %v", ep0.Default, ep1.Default)
	}

	defaultVia := func() (string, error) {
		var dev string
		err := netns.Do(ns, func() error {
			routes, err := netlink.RouteGet(net.ParseIP("1.1.1.1"))
			if err != nil {
				return err
			}
			l, err := netlink.LinkByIndex(routes[0].LinkIndex)
			if err == nil {
				dev = l.Attrs().Name
			}
			return err
		})
		return dev, err
	}
	if dev, err := defaultVia(); err != nil || dev != "eth0" {
		t.Fatalf("default route via %q, %v; want eth0", dev, err)
	}

	if err := s.Detach(ep0, id); err != nil {
		t.Fatal(err)
	}
	err = netns.Do(ns, func() error {
		if _, err := netlink.LinkByName("eth0"); err == nil {
			return fmt.Errorf("eth0 still exists after detach")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := defaultVia(); err == nil {
		t.Fatal("default route survived its interface")
	}
	if err := s.SetDefaultRoute(ns, ep1); err != nil {
		t.Fatal(err)
	}
	if dev, err := defaultVia(); err != nil || dev != "eth1" || !ep1.Default {
		t.Fatalf("default route via %q, %v; want eth1", dev, err)
	}
	// eth1 still reaches the host after the move.
	listenIn(t, "", ep1.Gateway.String()+":8085")
	if got, err := dialIn(ns, ep1.Gateway.String()+":8085"); err != nil || got != "hello from netker" {
		t.Fatalf("eth1 -> gateway: %q, %v", got, err)
	}
}

// TestNoICC runs on whichever datapath is available: nftables when
// unprivileged, BPF as root.
func TestNoICC(t *testing.T) {
	requireNetAdmin(t)
	s, p := testStore(t)
	n := &Network{Name: "noicc", Subnet: netip.MustParsePrefix("10.92.0.0/24"), NoICC: true}
	if err := s.Create(n); err != nil {
		t.Fatal(err)
	}
	a, b := "1313131313131313", "1414141414141414"
	nsA, nsB := newNS(t, p, a), newNS(t, p, b)
	epA, err := s.Attach(n, a, nsA, 0, netip.Addr{}, true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Detach(epA, a)
	epB, err := s.Attach(n, b, nsB, 0, netip.Addr{}, true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Detach(epB, b)

	listenIn(t, nsB, epB.IP.String()+":9000")
	if _, err := dialIn(nsA, epB.IP.String()+":9000"); err == nil {
		t.Fatal("containers on an --icc=false network reached each other")
	}
	listenIn(t, "", epA.Gateway.String()+":8086")
	if got, err := dialIn(nsA, epA.Gateway.String()+":8086"); err != nil || got != "hello from netker" {
		t.Fatalf("container -> gateway on an --icc=false network: %q, %v", got, err)
	}
	if epA.Datapath == DatapathEBPF && metric(t, s, epA.HostIfIndex, "drop-icc") == 0 {
		t.Fatal("blocked traffic not counted as drop-icc")
	}
}

func TestCreateIPv6Validation(t *testing.T) {
	s, _ := testStore(t)
	ok := &Network{Name: "v6", Subnet: netip.MustParsePrefix("10.89.0.0/24"), Subnet6: netip.MustParsePrefix("fd00:89::/64")}
	if err := s.Create(ok); err != nil {
		t.Fatal(err)
	}
	if ok.Gateway6 != netip.MustParseAddr("fd00:89::1") {
		t.Fatalf("default IPv6 gateway %s", ok.Gateway6)
	}
	bad := map[string]*Network{
		"L2 with IPv6":     {Name: "b1", Subnet: netip.MustParsePrefix("10.88.1.0/24"), Subnet6: netip.MustParsePrefix("fd00:1::/64"), Mode: netkit.ModeL2},
		"overlapping v6":   {Name: "b2", Subnet: netip.MustParsePrefix("10.88.2.0/24"), Subnet6: netip.MustParsePrefix("fd00:89::/80")},
		"v4 as v6":         {Name: "b3", Subnet: netip.MustParsePrefix("10.88.3.0/24"), Subnet6: netip.MustParsePrefix("10.88.4.0/24")},
		"too large":        {Name: "b4", Subnet: netip.MustParsePrefix("10.88.5.0/24"), Subnet6: netip.MustParsePrefix("fd00::/32")},
		"gateway6 outside": {Name: "b5", Subnet: netip.MustParsePrefix("10.88.6.0/24"), Subnet6: netip.MustParsePrefix("fd00:6::/64"), Gateway6: netip.MustParseAddr("fd00:7::1")},
		"gateway6 alone":   {Name: "b6", Subnet: netip.MustParsePrefix("10.88.7.0/24"), Gateway6: netip.MustParseAddr("fd00:7::1")},
	}
	for name, n := range bad {
		if err := s.Create(n); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func readSysctl(t *testing.T, key string) string {
	t.Helper()
	b, err := os.ReadFile("/proc/sys/" + key)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

func TestIPv6Legacy(t *testing.T) {
	requireNetAdmin(t)
	t.Setenv("NETKER_DATAPATH", "legacy")
	s, p := testStore(t)
	// An uplink that learns its address from router advertisements.
	ra := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "ra0"}}
	if err := netlink.LinkAdd(ra); err != nil {
		t.Fatal(err)
	}
	defer netlink.LinkDel(ra)
	os.WriteFile("/proc/sys/net/ipv6/conf/ra0/accept_ra", []byte("1"), 0o644)
	os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte("0"), 0o644)

	n := &Network{Name: "v6", Subnet: netip.MustParsePrefix("10.89.0.0/24"), Subnet6: netip.MustParsePrefix("fd00:89::/64")}
	if err := s.Create(n); err != nil {
		t.Fatal(err)
	}
	a, b := "6a6a6a6a6a6a6a6a", "6b6b6b6b6b6b6b6b"
	nsA, nsB := newNS(t, p, a), newNS(t, p, b)
	epA, err := s.Attach(n, a, nsA, 0, netip.Addr{}, true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Detach(epA, a)
	epB, err := s.Attach(n, b, nsB, 0, netip.Addr{}, true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Detach(epB, b)
	if !n.Subnet6.Contains(epA.IP6) || epA.Gateway6 != n.Gateway6 || epA.IP6 == epB.IP6 {
		t.Fatalf("IPv6 addresses: A %s, B %s, gateway %s", epA.IP6, epB.IP6, epA.Gateway6)
	}

	if got := readSysctl(t, "net/ipv6/conf/all/forwarding"); got != "1" {
		t.Fatalf("IPv6 forwarding %s", got)
	}
	if got := readSysctl(t, "net/ipv6/conf/ra0/accept_ra"); got != "2" {
		t.Fatalf("accept_ra on an RA-configured interface is %s after enabling forwarding, want 2", got)
	}

	err = netns.Do(nsA, func() error {
		routes, err := netlink.RouteGet(net.ParseIP("2001:db8::1"))
		if err != nil {
			return fmt.Errorf("no IPv6 default route: %w", err)
		}
		if gw := routes[0].Gw.String(); gw != epA.Gateway6.String() {
			return fmt.Errorf("IPv6 default route via %s, want %s", gw, epA.Gateway6)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	listenIn6 := func(ns, addr string) {
		var ln net.Listener
		listen := func() error {
			var err error
			ln, err = net.Listen("tcp6", addr)
			return err
		}
		if ns == "" {
			err = listen()
		} else {
			err = netns.Do(ns, listen)
		}
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				fmt.Fprint(c, "hello over v6")
				c.Close()
			}
		}()
	}
	dial6 := func(ns, addr string) (string, error) {
		var got []byte
		err := netns.Do(ns, func() error {
			c, err := net.DialTimeout("tcp6", addr, 2*time.Second)
			if err != nil {
				return err
			}
			defer c.Close()
			got, err = io.ReadAll(c)
			return err
		})
		return string(got), err
	}
	listenIn6(nsB, netip.AddrPortFrom(epB.IP6, 9000).String())
	if got, err := dial6(nsA, netip.AddrPortFrom(epB.IP6, 9000).String()); err != nil || got != "hello over v6" {
		t.Fatalf("A->B over IPv6: %q, %v", got, err)
	}
	listenIn6("", netip.AddrPortFrom(epA.Gateway6, 8087).String())
	if got, err := dial6(nsA, netip.AddrPortFrom(epA.Gateway6, 8087).String()); err != nil || got != "hello over v6" {
		t.Fatalf("A->IPv6 gateway: %q, %v", got, err)
	}

	out, err := exec.Command("nft", "list", "table", "ip6", "netker").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "ip6 saddr fd00:89::/64 ip6 daddr != fd00:89::/64 masquerade") {
		t.Fatalf("no IPv6 masquerade rule: %v\n%s", err, out)
	}
	if err := s.Remove("v6", false); err != nil {
		t.Fatal(err)
	}
	out, _ = exec.Command("nft", "list", "table", "ip6", "netker").CombinedOutput()
	if strings.Contains(string(out), "netker:net:v6") {
		t.Fatalf("IPv6 rules left after network rm:\n%s", out)
	}
}
