package network

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/saiaunghlyanhtet/netker/internal/datapath"
	"github.com/saiaunghlyanhtet/netker/internal/netkit"
	"github.com/saiaunghlyanhtet/netker/internal/netns"
)

// These tests need real root (BPF can't be loaded from a user namespace).
// Run them in a private network namespace, e.g. `make test-ebpf`.
func ebpfStore(t *testing.T) (*Store, string) {
	t.Helper()
	requireNetAdmin(t)
	// The test netns plays the host, and a host's own addresses are only
	// reachable over lo. A fresh "unshare --net" (as in CI) has lo down.
	if err := netns.LoopbackUp(); err != nil {
		t.Fatal(err)
	}
	bpffs := filepath.Join("/sys/fs/bpf", fmt.Sprintf("netker-test-%d", time.Now().UnixNano()))
	t.Setenv("NETKER_BPFFS", bpffs)
	t.Setenv("NETKER_DATAPATH", "ebpf")
	s, _ := testStore(t)
	if err := s.dp.Load(); err != nil {
		t.Skipf("eBPF datapath not loadable here: %v", err)
	}
	t.Cleanup(func() {
		s.dp.ResetHost()
		s.dp.Close()
		os.RemoveAll(bpffs)
	})
	return s, bpffs
}

func attachT(t *testing.T, s *Store, n *Network, id string) (*Endpoint, string) {
	t.Helper()
	ns := newNS(t, s.paths, id)
	ep, err := s.Attach(n, id, ns, 0, netip.Addr{}, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Detach(ep, id) })
	return ep, ns
}

func metric(t *testing.T, s *Store, ifindex int, reason string) uint64 {
	t.Helper()
	ms, err := s.dp.Metrics()
	if err != nil {
		t.Fatal(err)
	}
	var n uint64
	for _, m := range ms {
		if int(m.Ifindex) == ifindex && m.Reason == reason {
			n += m.Packets
		}
	}
	return n
}

// dumpMetrics logs every datapath counter; call it when a test fails.
func dumpMetrics(t *testing.T, s *Store) {
	t.Helper()
	ms, _ := s.dp.Metrics()
	for _, m := range ms {
		t.Logf("  ifindex %d %s %s: %d packets", m.Ifindex, m.Direction, m.Reason, m.Packets)
	}
}

func TestEBPFAttachIsFailClosed(t *testing.T) {
	s, bpffs := ebpfStore(t)
	n, _ := s.Get(DefaultName)
	id := "e1e1e1e1e1e1e1e1"
	ep, ns := attachT(t, s, n, id)
	if ep.Datapath != DatapathEBPF {
		t.Fatalf("datapath %q", ep.Datapath)
	}
	host, _ := netlink.LinkByName(ep.HostIf)
	if nk := host.(*netlink.Netkit); nk.PeerPolicy != netlink.NETKIT_POLICY_BLACKHOLE {
		t.Fatalf("peer policy %v, want blackhole", nk.PeerPolicy)
	}
	for _, side := range []string{"peer", "primary"} {
		if _, err := os.Stat(filepath.Join(bpffs, "links", id, ep.HostIf+"-"+side)); err != nil {
			t.Fatalf("%s link not pinned: %v", side, err)
		}
	}

	listenIn(t, ns, ep.IP.String()+":8080")
	if got, err := dialIn("", ep.IP.String()+":8080"); err != nil || got != "hello from netker" {
		t.Fatalf("host->container: %q, %v", got, err)
	}
	if metric(t, s, ep.HostIfIndex, "deliver") == 0 {
		t.Fatal("nk_to_container did not count the delivery")
	}

	// Detaching the programs must cut the container off (peer policy DROP).
	if err := s.dp.Detach(id, ep.HostIf, ep.IP); err != nil {
		t.Fatal(err)
	}
	listenIn(t, "", ep.Gateway.String()+":8081")
	if _, err := dialIn(ns, ep.Gateway.String()+":8081"); err == nil {
		t.Fatal("container egress still works without its BPF program")
	}
}

func TestEBPFContainerToContainerRedirect(t *testing.T) {
	s, _ := ebpfStore(t)
	n, _ := s.Get(DefaultName)
	epA, nsA := attachT(t, s, n, "a1a1a1a1a1a1a1a1")
	epB, nsB := attachT(t, s, n, "b1b1b1b1b1b1b1b1")

	listenIn(t, nsB, epB.IP.String()+":9000")
	if got, err := dialIn(nsA, epB.IP.String()+":9000"); err != nil || got != "hello from netker" {
		t.Fatalf("A->B: %q, %v", got, err)
	}
	if metric(t, s, epA.HostIfIndex, "forward-local") == 0 {
		t.Fatal("A->B was not redirected by nk_from_container")
	}
	if metric(t, s, epB.HostIfIndex, "forward-local") == 0 {
		t.Fatal("B->A replies were not redirected by nk_from_container")
	}
	// Redirected packets still pass B's nk_to_container.
	if metric(t, s, epB.HostIfIndex, "deliver") == 0 {
		t.Fatal("redirected packets skipped nk_to_container")
	}
}

func TestEBPFNetworksAreIsolated(t *testing.T) {
	s, _ := ebpfStore(t)
	n1, _ := s.Get(DefaultName)
	n2 := &Network{Name: "other", Subnet: netip.MustParsePrefix("10.98.0.0/24")}
	if err := s.Create(n2); err != nil {
		t.Fatal(err)
	}
	epA, nsA := attachT(t, s, n1, "a2a2a2a2a2a2a2a2")
	epB, nsB := attachT(t, s, n2, "b2b2b2b2b2b2b2b2")
	listenIn(t, nsB, epB.IP.String()+":9000")
	if _, err := dialIn(nsA, epB.IP.String()+":9000"); err == nil {
		t.Fatal("container reached a container on another network")
	}
	if metric(t, s, epA.HostIfIndex, "drop-policy") == 0 {
		t.Fatal("cross-network traffic not counted as drop-policy")
	}
}

func TestEBPFAntiSpoofing(t *testing.T) {
	s, _ := ebpfStore(t)
	n, _ := s.Get(DefaultName)
	epA, nsA := attachT(t, s, n, "a3a3a3a3a3a3a3a3")
	epB, nsB := attachT(t, s, n, "b3b3b3b3b3b3b3b3")
	listenIn(t, nsB, epB.IP.String()+":9000")

	// Container A adds an address it doesn't own and uses it as source.
	spoofed := netip.MustParseAddr("10.87.200.200")
	err := netns.Do(nsA, func() error {
		l, err := netlink.LinkByName("eth0")
		if err != nil {
			return err
		}
		return netlink.AddrAdd(l, &netlink.Addr{IPNet: hostNet(spoofed)})
	})
	if err != nil {
		t.Fatal(err)
	}
	err = netns.Do(nsA, func() error {
		d := net.Dialer{Timeout: time.Second, LocalAddr: &net.TCPAddr{IP: net.IP(spoofed.AsSlice())}}
		c, err := d.Dial("tcp4", epB.IP.String()+":9000")
		if err == nil {
			c.Close()
			return fmt.Errorf("spoofed connection succeeded")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if metric(t, s, epA.HostIfIndex, "drop-spoof") == 0 {
		t.Fatal("spoofed packets not counted as drop-spoof")
	}
}

func TestEBPFL2Redirect(t *testing.T) {
	s, _ := ebpfStore(t)
	n := &Network{Name: "l2", Subnet: netip.MustParsePrefix("10.97.0.0/24"), Mode: netkit.ModeL2}
	if err := s.Create(n); err != nil {
		t.Fatal(err)
	}
	epA, nsA := attachT(t, s, n, "a4a4a4a4a4a4a4a4")
	epB, nsB := attachT(t, s, n, "b4b4b4b4b4b4b4b4")
	listenIn(t, nsB, epB.IP.String()+":9000")
	if got, err := dialIn(nsA, epB.IP.String()+":9000"); err != nil || got != "hello from netker" {
		t.Fatalf("L2 A->B: %q, %v", got, err)
	}
	if metric(t, s, epA.HostIfIndex, "forward-local") == 0 {
		t.Fatal("L2 traffic was not redirected")
	}
}

func TestEBPFUpgradeKeepsTraffic(t *testing.T) {
	s, _ := ebpfStore(t)
	n, _ := s.Get(DefaultName)
	_, nsA := attachT(t, s, n, "a5a5a5a5a5a5a5a5")
	epB, nsB := attachT(t, s, n, "b5b5b5b5b5b5b5b5")
	before, _ := s.dp.Links()

	// A fresh loader, as a newer netker binary would be.
	dp2 := datapath.New(os.Getenv("NETKER_BPFFS"))
	defer dp2.Close()
	updated, err := dp2.Upgrade()
	if err != nil {
		t.Fatal(err)
	}
	hostLinks, _ := s.dp.HostLinks()
	if want := len(before) + len(hostLinks); updated != want || len(before) != 4 {
		t.Fatalf("updated %d links, want %d (4 container links + %d host hooks)", updated, want, len(hostLinks))
	}
	after, _ := s.dp.Links()
	for i := range before {
		if before[i].ProgramID == after[i].ProgramID {
			t.Fatalf("link %s still runs program %d", after[i].Pin, after[i].ProgramID)
		}
	}
	listenIn(t, nsB, epB.IP.String()+":9000")
	if got, err := dialIn(nsA, epB.IP.String()+":9000"); err != nil || got != "hello from netker" {
		t.Fatalf("A->B after upgrade: %q, %v", got, err)
	}
}

// world builds a fake uplink: uplink0 (198.51.100.2) in the test netns,
// which plays the host, and its peer in a separate "internet" netns
// (198.51.100.1). The netker nft table is deleted so that anything that
// works can only have been translated in BPF.
type world struct {
	ns     string
	hostIP netip.Addr
	peerIP netip.Addr
}

func setupWorld(t *testing.T, s *Store) *world {
	t.Helper()
	t.Setenv("NETKER_UPLINKS", "uplink0")
	w := &world{
		ns:     newNS(t, s.paths, "world"),
		hostIP: netip.MustParseAddr("198.51.100.2"),
		peerIP: netip.MustParseAddr("198.51.100.1"),
	}
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "uplink0"}, PeerName: "wld0"}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { netlink.LinkDel(veth) })
	up, _ := netlink.LinkByName("uplink0")
	netlink.AddrAdd(up, &netlink.Addr{IPNet: &net.IPNet{IP: net.IP(w.hostIP.AsSlice()), Mask: net.CIDRMask(24, 32)}})
	netlink.LinkSetUp(up)
	peer, _ := netlink.LinkByName("wld0")
	ns, err := os.Open(w.ns)
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	if err := netlink.LinkSetNsFd(peer, int(ns.Fd())); err != nil {
		t.Fatal(err)
	}
	err = netns.Do(w.ns, func() error {
		l, err := netlink.LinkByName("wld0")
		if err != nil {
			return err
		}
		netlink.AddrAdd(l, &netlink.Addr{IPNet: &net.IPNet{IP: net.IP(w.peerIP.AsSlice()), Mask: net.CIDRMask(24, 32)}})
		netlink.LinkSetUp(l)
		return netns.LoopbackUp()
	})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func dropNFT(t *testing.T) {
	t.Helper()
	exec.Command("nft", "delete", "table", "ip", "netker").Run()
}

// listenRemoteIn replies with the address the connection came from.
func listenRemoteIn(t *testing.T, nsPath, addr string) {
	t.Helper()
	var ln net.Listener
	err := netns.Do(nsPath, func() error {
		var err error
		ln, err = net.Listen("tcp4", addr)
		return err
	})
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
			fmt.Fprint(c, c.RemoteAddr().String())
			c.Close()
		}
	}()
}

func TestEBPFMasquerade(t *testing.T) {
	s, _ := ebpfStore(t)
	w := setupWorld(t, s)
	n, _ := s.Get(DefaultName)
	ep, ns := attachT(t, s, n, "a6a6a6a6a6a6a6a6")
	dropNFT(t)

	listenRemoteIn(t, w.ns, w.peerIP.String()+":7000")
	got, err := dialIn(ns, w.peerIP.String()+":7000")
	if err != nil {
		t.Fatalf("container->world: %v", err)
	}
	src, err := netip.ParseAddrPort(got)
	if err != nil {
		t.Fatalf("server saw %q", got)
	}
	if src.Addr() != w.hostIP || src.Port() < 61000 {
		t.Fatalf("server saw %s, want %s with a NAT port >= 61000", src, w.hostIP)
	}
	if metric(t, s, ep.HostIfIndex, "snat") == 0 || metric(t, s, ep.HostIfIndex, "rev-snat") == 0 {
		t.Fatal("masquerading was not done in BPF")
	}
}

func TestEBPFPublishedPorts(t *testing.T) {
	s, _ := ebpfStore(t)
	w := setupWorld(t, s)
	n, _ := s.Get(DefaultName)
	epA, nsA := attachT(t, s, n, "a7a7a7a7a7a7a7a7")
	epB, nsB := attachT(t, s, n, "b7b7b7b7b7b7b7b7")
	listenIn(t, nsB, epB.IP.String()+":80")
	ports := []PortMapping{{HostPort: 8080, ContainerPort: 80, Protocol: "tcp"}}
	if err := s.Publish("b7b7b7b7b7b7b7b7", epB, ports); err != nil {
		t.Fatal(err)
	}
	dropNFT(t)
	hostPort := w.hostIP.String() + ":8080"

	t.Run("from the world", func(t *testing.T) {
		if got, err := dialIn(w.ns, hostPort); err != nil || got != "hello from netker" {
			t.Fatalf("%q, %v", got, err)
		}
		if metric(t, s, epB.HostIfIndex, "dnat") == 0 || metric(t, s, epB.HostIfIndex, "rev-dnat") == 0 {
			t.Fatal("published port not translated in BPF")
		}
	})
	t.Run("from the host via localhost", func(t *testing.T) {
		if got, err := dialIn("", "127.0.0.1:8080"); err != nil || got != "hello from netker" {
			t.Fatalf("%q, %v", got, err)
		}
	})
	t.Run("from the host via its own address", func(t *testing.T) {
		if got, err := dialIn("", hostPort); err != nil || got != "hello from netker" {
			dumpMetrics(t, s)
			t.Fatalf("%q, %v", got, err)
		}
	})
	t.Run("from the host via an address added after publishing", func(t *testing.T) {
		d := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "late0"}}
		if err := netlink.LinkAdd(d); err != nil {
			t.Fatal(err)
		}
		defer netlink.LinkDel(d)
		netlink.AddrAdd(d, &netlink.Addr{IPNet: hostNet(netip.MustParseAddr("203.0.113.7"))})
		netlink.LinkSetUp(d)
		if got, err := dialIn("", "203.0.113.7:8080"); err != nil || got != "hello from netker" {
			t.Fatalf("%q, %v", got, err)
		}
	})
	t.Run("hairpin from another container", func(t *testing.T) {
		if got, err := dialIn(nsA, hostPort); err != nil || got != "hello from netker" {
			t.Fatalf("%q, %v", got, err)
		}
		if metric(t, s, epA.HostIfIndex, "dnat") == 0 {
			t.Fatal("hairpin not translated in BPF")
		}
	})
	t.Run("container's own localhost is untouched", func(t *testing.T) {
		if _, err := dialIn(nsA, "127.0.0.1:8080"); err == nil {
			t.Fatal("127.0.0.1 inside a container was redirected")
		}
	})
	t.Run("port already allocated", func(t *testing.T) {
		if err := s.Publish("a7a7a7a7a7a7a7a7", epA, ports); err == nil {
			t.Fatal("publishing a taken port succeeded")
		}
	})
	t.Run("unpublish", func(t *testing.T) {
		if err := s.Unpublish("b7b7b7b7b7b7b7b7", []*Endpoint{epB}, ports); err != nil {
			t.Fatal(err)
		}
		if _, err := dialIn(w.ns, hostPort); err == nil {
			t.Fatal("port still reachable after unpublish")
		}
	})
}

func TestEBPFPingThroughNAT(t *testing.T) {
	s, _ := ebpfStore(t)
	w := setupWorld(t, s)
	n, _ := s.Get(DefaultName)
	ep, ns := attachT(t, s, n, "a8a8a8a8a8a8a8a8")
	dropNFT(t)

	err := netns.Do(ns, func() error {
		c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
		if err != nil {
			return err
		}
		defer c.Close()
		msg := icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: 4242, Seq: 1, Data: []byte("netker")}}
		b, _ := msg.Marshal(nil)
		if _, err := c.WriteTo(b, &net.IPAddr{IP: net.IP(w.peerIP.AsSlice())}); err != nil {
			return err
		}
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 1500)
		for {
			n, from, err := c.ReadFrom(buf)
			if err != nil {
				return fmt.Errorf("no echo reply: %w", err)
			}
			m, err := icmp.ParseMessage(1, buf[:n])
			if err != nil || m.Type != ipv4.ICMPTypeEchoReply {
				continue
			}
			if e := m.Body.(*icmp.Echo); e.ID != 4242 {
				return fmt.Errorf("reply id %d, want the original 4242", e.ID)
			}
			if from.String() != w.peerIP.String() {
				return fmt.Errorf("reply from %s", from)
			}
			return nil
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if metric(t, s, ep.HostIfIndex, "rev-snat") == 0 {
		t.Fatal("echo reply was not un-masqueraded in BPF")
	}
}

func TestEBPFInternalNetwork(t *testing.T) {
	s, _ := ebpfStore(t)
	w := setupWorld(t, s)
	n := &Network{Name: "sealed", Subnet: netip.MustParsePrefix("10.96.0.0/24"), Internal: true}
	if err := s.Create(n); err != nil {
		t.Fatal(err)
	}
	epA, nsA := attachT(t, s, n, "a9a9a9a9a9a9a9a9")
	epB, nsB := attachT(t, s, n, "b9b9b9b9b9b9b9b9")
	dropNFT(t)
	listenRemoteIn(t, w.ns, w.peerIP.String()+":7000")
	if _, err := dialIn(nsA, w.peerIP.String()+":7000"); err == nil {
		t.Fatal("container on an internal network reached the outside world")
	}
	if metric(t, s, epA.HostIfIndex, "drop-policy") == 0 {
		t.Fatal("internal egress not dropped by policy")
	}
	listenIn(t, nsB, epB.IP.String()+":9000")
	if got, err := dialIn(nsA, epB.IP.String()+":9000"); err != nil || got != "hello from netker" {
		t.Fatalf("containers on the same internal network: %q, %v", got, err)
	}
	listenIn(t, nsB, epB.IP.String()+":80")
	if err := s.Publish("b9b9b9b9b9b9b9b9", epB, []PortMapping{{HostPort: 8081, ContainerPort: 80, Protocol: "tcp"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := dialIn(w.ns, w.hostIP.String()+":8081"); err == nil {
		t.Fatal("internal container reachable from the world through a published port")
	}
}
