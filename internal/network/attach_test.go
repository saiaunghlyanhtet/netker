package network

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
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
	ep, err := s.Attach(n, id, ns, 0, netip.Addr{})
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
	epA, err := s.Attach(n, a, nsA, 0, netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	epB, err := s.Attach(n, b, nsB, 0, netip.Addr{})
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
	ep, err := s.Attach(n, id, ns, 0, netip.Addr{})
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
	ep, err := s.Attach(n, id, ns, 0, netip.Addr{})
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
	epA0, err := s.Attach(n1, a, nsA, 0, netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Detach(epA0, a)
	epA1, err := s.Attach(n2, a, nsA, 1, netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Detach(epA1, a)
	epB, err := s.Attach(n2, b, nsB, 0, netip.Addr{})
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
