package network

import (
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"

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
	if !inInitUserNS() {
		t.Skip("loading BPF needs root in the initial user namespace")
	}
	// As real root a load failure is a bug (e.g. the verifier rejecting a
	// program), not a reason to skip.
	if err := s.dp.Load(); err != nil {
		t.Fatalf("load eBPF datapath: %v", err)
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
	if err := s.dp.Detach(id, ep.HostIf, ep.IP, ep.IP6); err != nil {
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
	ns               string
	hostIP, peerIP   netip.Addr
	hostIP6, peerIP6 netip.Addr
}

func setupWorld(t *testing.T, s *Store) *world {
	t.Helper()
	t.Setenv("NETKER_UPLINKS", "uplink0")
	w := &world{
		ns:      newNS(t, s.paths, "world"),
		hostIP:  netip.MustParseAddr("198.51.100.2"),
		peerIP:  netip.MustParseAddr("198.51.100.1"),
		hostIP6: netip.MustParseAddr("2001:db8:100::2"),
		peerIP6: netip.MustParseAddr("2001:db8:100::1"),
	}
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "uplink0"}, PeerName: "wld0"}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { netlink.LinkDel(veth) })
	up, _ := netlink.LinkByName("uplink0")
	netlink.AddrAdd(up, &netlink.Addr{IPNet: &net.IPNet{IP: net.IP(w.hostIP.AsSlice()), Mask: net.CIDRMask(24, 32)}})
	netlink.AddrAdd(up, &netlink.Addr{IPNet: &net.IPNet{IP: net.IP(w.hostIP6.AsSlice()), Mask: net.CIDRMask(64, 128)}, Flags: unix.IFA_F_NODAD})
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
		netlink.AddrAdd(l, &netlink.Addr{IPNet: &net.IPNet{IP: net.IP(w.peerIP6.AsSlice()), Mask: net.CIDRMask(64, 128)}, Flags: unix.IFA_F_NODAD})
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

// dropNFT6 is dropNFT for the IPv6 table.
func dropNFT6(t *testing.T) {
	t.Helper()
	exec.Command("nft", "delete", "table", "ip6", "netker").Run()
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

func TestEBPFNoICCKeepsPublishedPorts(t *testing.T) {
	s, _ := ebpfStore(t)
	w := setupWorld(t, s)
	n := &Network{Name: "noicc", Subnet: netip.MustParsePrefix("10.92.0.0/24"), NoICC: true}
	if err := s.Create(n); err != nil {
		t.Fatal(err)
	}
	epA, nsA := attachT(t, s, n, "a0a0a0a0a0a0a0a0")
	epB, nsB := attachT(t, s, n, "b0b0b0b0b0b0b0b0")
	listenIn(t, nsB, epB.IP.String()+":80")
	if err := s.Publish("b0b0b0b0b0b0b0b0", epB, []PortMapping{{HostPort: 8082, ContainerPort: 80, Protocol: "tcp"}}); err != nil {
		t.Fatal(err)
	}
	dropNFT(t)
	if _, err := dialIn(nsA, epB.IP.String()+":80"); err == nil {
		t.Fatal("direct container-to-container traffic allowed with --icc=false")
	}
	if metric(t, s, epA.HostIfIndex, "drop-icc") == 0 {
		t.Fatal("not counted as drop-icc")
	}
	if got, err := dialIn(nsA, w.hostIP.String()+":8082"); err != nil || got != "hello from netker" {
		t.Fatalf("hairpin to a published port with --icc=false: %q, %v", got, err)
	}
	listenRemoteIn(t, w.ns, w.peerIP.String()+":7000")
	if _, err := dialIn(nsA, w.peerIP.String()+":7000"); err != nil {
		t.Fatalf("container -> world with --icc=false: %v", err)
	}
}

// sendARP sends one ARP reply out of eth0 in the namespace at ns, with the
// given Ethernet source and ARP sender fields, to the host's primary.
func sendARP(t *testing.T, ns string, ethSrc, sha net.HardwareAddr, sip netip.Addr, hostMAC net.HardwareAddr, tip netip.Addr) {
	t.Helper()
	err := netns.Do(ns, func() error {
		l, err := netlink.LinkByName("eth0")
		if err != nil {
			return err
		}
		proto := uint16(unix.ETH_P_ARP<<8&0xff00 | unix.ETH_P_ARP>>8)
		fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(proto))
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		frame := make([]byte, 0, 42)
		frame = append(frame, hostMAC...)
		frame = append(frame, ethSrc...)
		frame = append(frame, 0x08, 0x06)                   // ETH_P_ARP
		frame = append(frame, 0, 1, 0x08, 0x00, 6, 4, 0, 2) // Ethernet/IPv4, reply
		frame = append(frame, sha...)
		frame = append(frame, sip.AsSlice()...)
		frame = append(frame, hostMAC...)
		frame = append(frame, tip.AsSlice()...)
		sa := &unix.SockaddrLinklayer{Ifindex: l.Attrs().Index, Protocol: proto, Halen: 6}
		copy(sa.Addr[:], hostMAC)
		err = unix.Sendto(fd, frame, 0, sa)
		// A frame the BPF program drops comes back as NET_XMIT_DROP from
		// netkit_xmit, which packet sockets report as ENOBUFS.
		if errors.Is(err, unix.ENOBUFS) {
			return nil
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestEBPFL2AntiSpoofing(t *testing.T) {
	s, _ := ebpfStore(t)
	n := &Network{Name: "l2guard", Subnet: netip.MustParsePrefix("10.90.0.0/24"), Mode: netkit.ModeL2}
	if err := s.Create(n); err != nil {
		t.Fatal(err)
	}
	a, b := "c1c1c1c1c1c1c1c1", "d1d1d1d1d1d1d1d1"
	epA, nsA := attachT(t, s, n, a)
	epB, nsB := attachT(t, s, n, b)
	listenIn(t, nsB, epB.IP.String()+":9000")
	realMAC := deterministicMAC(a, 0, 1)
	hostMAC := deterministicMAC(a, 0, 0)
	fake, _ := net.ParseMAC("02:de:ad:be:ef:01")

	if got, err := dialIn(nsA, epB.IP.String()+":9000"); err != nil || got != "hello from netker" {
		t.Fatalf("baseline A->B on L2: %q, %v", got, err)
	}

	setMAC := func(mac net.HardwareAddr) {
		t.Helper()
		err := netns.Do(nsA, func() error {
			l, err := netlink.LinkByName("eth0")
			if err != nil {
				return err
			}
			return netlink.LinkSetHardwareAddr(l, mac)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Run("changed MAC is dropped", func(t *testing.T) {
		setMAC(fake)
		dialIn(nsA, epB.IP.String()+":9000")
		if metric(t, s, epA.HostIfIndex, "drop-spoof-mac") == 0 {
			dumpMetrics(t, s)
			t.Fatal("frames from a changed MAC were not dropped as drop-spoof-mac")
		}
		setMAC(realMAC)
		if got, err := dialIn(nsA, epB.IP.String()+":9000"); err != nil || got != "hello from netker" {
			t.Fatalf("after restoring the MAC: %q, %v", got, err)
		}
	})
	t.Run("ARP for another container's IP is dropped", func(t *testing.T) {
		before := metric(t, s, epA.HostIfIndex, "drop-spoof")
		sendARP(t, nsA, realMAC, realMAC, epB.IP, hostMAC, epA.Gateway)
		time.Sleep(100 * time.Millisecond)
		if metric(t, s, epA.HostIfIndex, "drop-spoof") == before {
			t.Fatal("ARP claiming B's IP was not dropped")
		}
		neighs, err := netlink.NeighList(epA.HostIfIndex, netlink.FAMILY_V4)
		if err != nil {
			t.Fatal(err)
		}
		for _, nb := range neighs {
			if nb.IP.Equal(net.IP(epB.IP.AsSlice())) {
				t.Fatalf("host learned B's IP on A's device: %v", nb)
			}
		}
	})
	t.Run("ARP with a fake sender MAC is dropped", func(t *testing.T) {
		before := metric(t, s, epA.HostIfIndex, "drop-spoof-mac")
		sendARP(t, nsA, realMAC, fake, epA.IP, hostMAC, epA.Gateway)
		time.Sleep(100 * time.Millisecond)
		if metric(t, s, epA.HostIfIndex, "drop-spoof-mac") == before {
			t.Fatal("ARP with a fake sender MAC was not dropped")
		}
	})
}

// listenRemoteIn6 replies with the address the IPv6 connection came from.
func listenRemoteIn6(t *testing.T, nsPath, addr string) {
	t.Helper()
	var ln net.Listener
	err := netns.Do(nsPath, func() error {
		var err error
		ln, err = net.Listen("tcp6", addr)
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

// addAddr6 adds an extra address to eth0 in ns until the test ends.
// Removing it matters: IPv6 source selection may prefer it for later
// connections.
func addAddr6(t *testing.T, ns string, a netip.Addr) {
	t.Helper()
	addr := &netlink.Addr{IPNet: hostNet(a), Flags: unix.IFA_F_NODAD}
	onEth0 := func(fn func(netlink.Link) error) error {
		return netns.Do(ns, func() error {
			l, err := netlink.LinkByName("eth0")
			if err != nil {
				return err
			}
			return fn(l)
		})
	}
	if err := onEth0(func(l netlink.Link) error { return netlink.AddrAdd(l, addr) }); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { onEth0(func(l netlink.Link) error { return netlink.AddrDel(l, addr) }) })
}

func TestEBPFIPv6(t *testing.T) {
	s, _ := ebpfStore(t)
	w := setupWorld(t, s)
	mk := func(name, v4, v6 string, mod func(*Network)) *Network {
		n := &Network{Name: name, Subnet: netip.MustParsePrefix(v4), Subnet6: netip.MustParsePrefix(v6)}
		if mod != nil {
			mod(n)
		}
		if err := s.Create(n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	v6 := mk("v6", "10.89.0.0/24", "fd00:89::/64", nil)
	other := mk("v6other", "10.88.0.0/24", "fd00:88::/64", nil)
	noicc := mk("v6noicc", "10.86.0.0/24", "fd00:86::/64", func(n *Network) { n.NoICC = true })
	internal := mk("v6int", "10.85.0.0/24", "fd00:85::/64", func(n *Network) { n.Internal = true })

	epA, nsA := attachT(t, s, v6, "a61a61a61a61a61a")
	epB, nsB := attachT(t, s, v6, "b61b61b61b61b61b")
	epC, nsC := attachT(t, s, other, "c61c61c61c61c61c")
	if epA.Datapath != DatapathEBPF || !epA.IP6.IsValid() {
		t.Fatalf("endpoint %+v", epA)
	}
	port := func(a netip.Addr, p uint16) string { return netip.AddrPortFrom(a, p).String() }

	t.Run("container to container, redirected in BPF", func(t *testing.T) {
		listenIn6(t, nsB, port(epB.IP6, 9000))
		if got, err := dialIn6(nsA, port(epB.IP6, 9000)); err != nil || got != "hello over v6" {
			dumpMetrics(t, s)
			t.Fatalf("A->B over IPv6: %q, %v", got, err)
		}
		if metric(t, s, epA.HostIfIndex, "forward-local") == 0 || metric(t, s, epB.HostIfIndex, "forward-local") == 0 {
			t.Fatal("IPv6 traffic between containers wasn't redirected in BPF both ways")
		}
	})
	t.Run("other network is isolated", func(t *testing.T) {
		listenIn6(t, nsC, port(epC.IP6, 9000))
		before := metric(t, s, epA.HostIfIndex, "drop-policy")
		if _, err := dialIn6(nsA, port(epC.IP6, 9000)); err == nil {
			t.Fatal("reached a container on another network over IPv6")
		}
		if metric(t, s, epA.HostIfIndex, "drop-policy") == before {
			t.Fatal("not counted as drop-policy")
		}
	})
	t.Run("spoofed source is dropped", func(t *testing.T) {
		spoof := netip.MustParseAddr("fd00:89::dead")
		addAddr6(t, nsA, spoof)
		before := metric(t, s, epA.HostIfIndex, "drop-spoof")
		if _, err := dialIn6(nsA, port(epB.IP6, 9000), spoof); err == nil {
			t.Fatal("connection from a spoofed IPv6 source succeeded")
		}
		if metric(t, s, epA.HostIfIndex, "drop-spoof") == before {
			t.Fatal("not counted as drop-spoof")
		}
	})
	t.Run("gateway and host stack", func(t *testing.T) {
		listenIn6(t, "", port(epA.Gateway6, 8088))
		if got, err := dialIn6(nsA, port(epA.Gateway6, 8088)); err != nil || got != "hello over v6" {
			t.Fatalf("A->IPv6 gateway: %q, %v", got, err)
		}
	})
	t.Run("outside world, masqueraded in BPF", func(t *testing.T) {
		dropNFT6(t)
		listenRemoteIn6(t, w.ns, port(w.peerIP6, 7000))
		got, err := dialIn6(nsA, port(w.peerIP6, 7000))
		if err != nil {
			dumpMetrics(t, s)
			t.Fatalf("A->world over IPv6: %v", err)
		}
		if src, err := netip.ParseAddrPort(got); err != nil || src.Addr() != w.hostIP6 || src.Port() < 61000 {
			t.Fatalf("world saw %q, want the host's address %s with a NAT port >= 61000", got, w.hostIP6)
		}
		if metric(t, s, epA.HostIfIndex, "snat") == 0 || metric(t, s, epA.HostIfIndex, "rev-snat") == 0 {
			t.Fatal("IPv6 to the world wasn't masqueraded in BPF")
		}
	})
	t.Run("--icc=false", func(t *testing.T) {
		epD, nsD := attachT(t, s, noicc, "d61d61d61d61d61d")
		epE, nsE := attachT(t, s, noicc, "e61e61e61e61e61e")
		listenIn6(t, nsE, port(epE.IP6, 9000))
		if _, err := dialIn6(nsD, port(epE.IP6, 9000)); err == nil {
			t.Fatal("--icc=false containers reached each other over IPv6")
		}
		if metric(t, s, epD.HostIfIndex, "drop-icc") == 0 {
			t.Fatal("not counted as drop-icc")
		}
	})
	t.Run("--internal", func(t *testing.T) {
		epF, nsF := attachT(t, s, internal, "f61f61f61f61f61f")
		before := metric(t, s, epF.HostIfIndex, "drop-policy")
		if _, err := dialIn6(nsF, port(w.peerIP6, 7000)); err == nil {
			t.Fatal("internal container reached the outside world over IPv6")
		}
		if metric(t, s, epF.HostIfIndex, "drop-policy") == before {
			t.Fatal("not counted as drop-policy")
		}
	})
	t.Run("detach removes the IPv6 entry", func(t *testing.T) {
		if err := s.Detach(epB, "b61b61b61b61b61b"); err != nil {
			t.Fatal(err)
		}
		eps, err := s.dp.Endpoints()
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range eps {
			if e.IP == epB.IP6 {
				t.Fatal("IPv6 endpoint entry left after detach")
			}
		}
	})
}

func TestEBPFIPv6PublishedPorts(t *testing.T) {
	s, _ := ebpfStore(t)
	w := setupWorld(t, s)
	n := &Network{Name: "v6p", Subnet: netip.MustParsePrefix("10.84.0.0/24"), Subnet6: netip.MustParsePrefix("fd00:84::/64")}
	if err := s.Create(n); err != nil {
		t.Fatal(err)
	}
	epA, nsA := attachT(t, s, n, "a62a62a62a62a62a")
	epB, nsB := attachT(t, s, n, "b62b62b62b62b62b")
	listenIn6(t, nsB, netip.AddrPortFrom(epB.IP6, 80).String())
	listenIn(t, nsB, epB.IP.String()+":80")
	ports := []PortMapping{{HostPort: 8080, ContainerPort: 80, Protocol: "tcp"}}
	if err := s.Publish("b62b62b62b62b62b", epB, ports); err != nil {
		t.Fatal(err)
	}
	dropNFT(t)
	dropNFT6(t)
	hostPort6 := netip.AddrPortFrom(w.hostIP6, 8080).String()

	t.Run("published on both families", func(t *testing.T) {
		entries, err := s.dp.Ports()
		if err != nil {
			t.Fatal(err)
		}
		var hosts []string
		for _, e := range entries {
			hosts = append(hosts, e.HostIP)
		}
		if len(entries) != 2 || !slices.Contains(hosts, "0.0.0.0") || !slices.Contains(hosts, "::") {
			t.Fatalf("published entries %+v", entries)
		}
	})
	t.Run("from the world over IPv6", func(t *testing.T) {
		if got, err := dialIn6(w.ns, hostPort6); err != nil || got != "hello over v6" {
			dumpMetrics(t, s)
			t.Fatalf("%q, %v", got, err)
		}
		if metric(t, s, epB.HostIfIndex, "dnat") == 0 || metric(t, s, epB.HostIfIndex, "rev-dnat") == 0 {
			t.Fatal("IPv6 published port not translated in BPF")
		}
	})
	t.Run("from the world over IPv4 still works", func(t *testing.T) {
		if got, err := dialIn(w.ns, w.hostIP.String()+":8080"); err != nil || got != "hello from netker" {
			t.Fatalf("%q, %v", got, err)
		}
	})
	t.Run("from the host via [::1]", func(t *testing.T) {
		var got []byte
		c, err := net.DialTimeout("tcp6", "[::1]:8080", 2*time.Second)
		if err == nil {
			got, err = io.ReadAll(c)
			c.Close()
		}
		if err != nil || string(got) != "hello over v6" {
			t.Fatalf("%q, %v", got, err)
		}
	})
	t.Run("from the host via its own IPv6 address", func(t *testing.T) {
		var got []byte
		c, err := net.DialTimeout("tcp6", hostPort6, 2*time.Second)
		if err == nil {
			got, err = io.ReadAll(c)
			c.Close()
		}
		if err != nil || string(got) != "hello over v6" {
			dumpMetrics(t, s)
			t.Fatalf("%q, %v", got, err)
		}
	})
	t.Run("hairpin from another container", func(t *testing.T) {
		before := metric(t, s, epA.HostIfIndex, "dnat")
		if got, err := dialIn6(nsA, hostPort6); err != nil || got != "hello over v6" {
			t.Fatalf("%q, %v", got, err)
		}
		if metric(t, s, epA.HostIfIndex, "dnat") == before {
			t.Fatal("IPv6 hairpin not translated in BPF")
		}
	})
	t.Run("container's own [::1] is untouched", func(t *testing.T) {
		if _, err := dialIn6(nsA, "[::1]:8080"); err == nil {
			t.Fatal("[::1] inside a container was redirected")
		}
	})
	t.Run("unpublish removes both families", func(t *testing.T) {
		if err := s.Unpublish("b62b62b62b62b62b", []*Endpoint{epB}, ports); err != nil {
			t.Fatal(err)
		}
		if entries, _ := s.dp.Ports(); len(entries) != 0 {
			t.Fatalf("entries left: %+v", entries)
		}
		if _, err := dialIn6(w.ns, hostPort6); err == nil {
			t.Fatal("IPv6 port still reachable after unpublish")
		}
	})
}

func TestEBPFPing6ThroughNAT(t *testing.T) {
	s, _ := ebpfStore(t)
	w := setupWorld(t, s)
	n := &Network{Name: "v6ping", Subnet: netip.MustParsePrefix("10.83.0.0/24"), Subnet6: netip.MustParsePrefix("fd00:83::/64")}
	if err := s.Create(n); err != nil {
		t.Fatal(err)
	}
	ep, ns := attachT(t, s, n, "a63a63a63a63a63a")
	dropNFT6(t)
	err := netns.Do(ns, func() error {
		c, err := icmp.ListenPacket("ip6:ipv6-icmp", "::")
		if err != nil {
			return err
		}
		defer c.Close()
		msg := icmp.Message{Type: ipv6.ICMPTypeEchoRequest, Body: &icmp.Echo{ID: 4343, Seq: 1, Data: []byte("netker")}}
		b, _ := msg.Marshal(nil) // the kernel fills in the ICMPv6 checksum
		if _, err := c.WriteTo(b, &net.IPAddr{IP: net.IP(w.peerIP6.AsSlice())}); err != nil {
			return err
		}
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 1500)
		for {
			n, from, err := c.ReadFrom(buf)
			if err != nil {
				return fmt.Errorf("no echo reply: %w", err)
			}
			m, err := icmp.ParseMessage(58, buf[:n])
			if err != nil || m.Type != ipv6.ICMPTypeEchoReply {
				continue
			}
			if e := m.Body.(*icmp.Echo); e.ID != 4343 {
				return fmt.Errorf("reply id %d, want the original 4343", e.ID)
			}
			if from.String() != w.peerIP6.String() {
				return fmt.Errorf("reply from %s", from)
			}
			return nil
		}
	})
	if err != nil {
		dumpMetrics(t, s)
		t.Fatal(err)
	}
	if metric(t, s, ep.HostIfIndex, "rev-snat") == 0 {
		t.Fatal("ICMPv6 echo reply was not un-masqueraded in BPF")
	}
}

// pinIncompatible replaces the pinned map name with one of another layout,
// as a different netker version would have left it. Programs already
// attached keep the map they were loaded with.
func pinIncompatible(t *testing.T, bpffs, name string, typ ebpf.MapType, keySize uint32) {
	t.Helper()
	p := filepath.Join(bpffs, "maps", name)
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: typ, KeySize: keySize, ValueSize: 8, MaxEntries: 16})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err := m.Pin(p); err != nil {
		t.Fatal(err)
	}
}

func TestEBPFMapLayoutChange(t *testing.T) {
	s, bpffs := ebpfStore(t)
	n, _ := s.Get(DefaultName)
	epA, nsA := attachT(t, s, n, "a71a71a71a71a71a")
	epB, nsB := attachT(t, s, n, "b71b71b71b71b71b")
	ports := []PortMapping{{HostPort: 8090, ContainerPort: 80, Protocol: "tcp"}}
	if err := s.Publish("b71b71b71b71b71b", epB, ports); err != nil {
		t.Fatal(err)
	}
	listenIn(t, nsB, epB.IP.String()+":9000")
	before, _ := s.dp.Links()

	// An older netker left maps with another layout behind.
	pinIncompatible(t, bpffs, "netker_endpoints", ebpf.Hash, 4)
	pinIncompatible(t, bpffs, "netker_nat", ebpf.LRUHash, 16)
	if got, err := dialIn(nsA, epB.IP.String()+":9000"); err != nil || got != "hello from netker" {
		t.Fatalf("running containers stopped working when the pins changed: %q, %v", got, err)
	}

	s2 := NewStore(s.paths)
	defer s2.dp.Close()
	err := s2.dp.Load()
	if !errors.Is(err, datapath.ErrIncompatibleMaps) {
		t.Fatalf("load with stale maps: %v", err)
	}
	for _, want := range []string{"netker_endpoints", "netker_nat", "ValueSize", "netker system datapath upgrade"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q doesn't mention %q", err, want)
		}
	}

	t.Run("auto mode refuses instead of falling back to legacy", func(t *testing.T) {
		t.Setenv("NETKER_DATAPATH", "auto")
		id := "c71c71c71c71c71c"
		ns := newNS(t, s.paths, id)
		if _, err := s2.Attach(n, id, ns, 0, netip.Addr{}, true); !errors.Is(err, datapath.ErrIncompatibleMaps) {
			t.Fatalf("attach with stale maps: %v", err)
		}
		if _, err := netlink.LinkByName(HostIfName(id, 0)); err == nil {
			t.Fatal("netkit pair left behind")
		}
	})

	t.Run("a failed rebuild leaves bpffs untouched", func(t *testing.T) {
		broken := []RestoreItem{
			{ContainerID: "a71a71a71a71a71a", NetNSPath: nsA, Endpoints: []*Endpoint{epA}},
			{ContainerID: "b71b71b71b71b71b", NetNSPath: "/nonexistent/netns", Endpoints: []*Endpoint{epB}},
		}
		if _, err := s2.RebuildDatapath(broken); err == nil {
			t.Fatal("rebuild with an unreachable container succeeded")
		}
		s2.dp.Close()
		bad, err := s2.dp.CheckMaps()
		if err != nil || len(bad) != 2 {
			t.Fatalf("pins changed by a failed rebuild: %+v, %v", bad, err)
		}
		if after, _ := s2.dp.Links(); after[0].ProgramID != before[0].ProgramID {
			t.Fatal("a failed rebuild swapped programs")
		}
		if got, err := dialIn(nsA, epB.IP.String()+":9000"); err != nil || got != "hello from netker" {
			t.Fatalf("running containers broken by a failed rebuild: %q, %v", got, err)
		}
	})

	report, err := s2.RebuildDatapath([]RestoreItem{
		{ContainerID: "a71a71a71a71a71a", NetNSPath: nsA, Endpoints: []*Endpoint{epA}},
		{ContainerID: "b71b71b71b71b71b", NetNSPath: nsB, Endpoints: []*Endpoint{epB}, Ports: ports},
	})
	if err != nil {
		t.Fatal(err)
	}
	var rebuilt []string
	for _, m := range report.Rebuilt {
		rebuilt = append(rebuilt, m.Name)
	}
	if !slices.Equal(rebuilt, []string{"netker_endpoints", "netker_nat"}) || report.Endpoints != 2 || report.Links < len(before) {
		t.Fatalf("report %+v", report)
	}

	s3 := NewStore(s.paths)
	defer s3.dp.Close()
	if err := s3.dp.Load(); err != nil {
		t.Fatalf("load after the rebuild: %v", err)
	}
	eps, _ := s3.dp.Endpoints()
	var ips []netip.Addr
	for _, e := range eps {
		ips = append(ips, e.IP)
	}
	if !slices.Contains(ips, epA.IP) || !slices.Contains(ips, epB.IP) {
		t.Fatalf("endpoints not restored: %v", ips)
	}
	if pe, _ := s3.dp.Ports(); len(pe) != 1 || pe[0].HostPort != 8090 {
		t.Fatalf("published port not restored: %+v", pe)
	}
	after, _ := s3.dp.Links()
	for i := range before {
		if before[i].ProgramID == after[i].ProgramID {
			t.Fatalf("link %s still runs the old program", after[i].Pin)
		}
	}
	// The new programs use the rebuilt maps.
	fwd := metric(t, s, epA.HostIfIndex, "forward-local")
	if got, err := dialIn(nsA, epB.IP.String()+":9000"); err != nil || got != "hello from netker" {
		t.Fatalf("A->B after the rebuild: %q, %v", got, err)
	}
	if metric(t, s, epA.HostIfIndex, "forward-local") == fwd {
		t.Fatal("traffic after the rebuild wasn't forwarded by the new programs")
	}
	// Running it again (e.g. after a failure halfway) changes nothing.
	again, err := s3.RebuildDatapath([]RestoreItem{
		{ContainerID: "a71a71a71a71a71a", NetNSPath: nsA, Endpoints: []*Endpoint{epA}},
		{ContainerID: "b71b71b71b71b71b", NetNSPath: nsB, Endpoints: []*Endpoint{epB}, Ports: ports},
	})
	if err != nil || len(again.Rebuilt) != 0 {
		t.Fatalf("second rebuild: %+v, %v", again, err)
	}
	if got, err := dialIn(nsA, epB.IP.String()+":9000"); err != nil || got != "hello from netker" {
		t.Fatalf("A->B after a second rebuild: %q, %v", got, err)
	}
}
