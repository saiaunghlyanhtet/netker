package network

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/saiaunghlyanhtet/netker/internal/datapath"
	"github.com/saiaunghlyanhtet/netker/internal/netkit"
	"github.com/saiaunghlyanhtet/netker/internal/netns"
)

// These tests need real root (BPF can't be loaded from a user namespace).
// Run them in a private network namespace, e.g. `make test-ebpf`.
func ebpfStore(t *testing.T) (*Store, string) {
	t.Helper()
	requireNetAdmin(t)
	bpffs := filepath.Join("/sys/fs/bpf", fmt.Sprintf("netker-test-%d", time.Now().UnixNano()))
	t.Setenv("NETKER_BPFFS", bpffs)
	t.Setenv("NETKER_DATAPATH", "ebpf")
	s, _ := testStore(t)
	if err := s.dp.Load(); err != nil {
		t.Skipf("eBPF datapath not loadable here: %v", err)
	}
	t.Cleanup(func() {
		s.dp.Close()
		os.RemoveAll(bpffs)
	})
	return s, bpffs
}

func attachT(t *testing.T, s *Store, n *Network, id string) (*Endpoint, string) {
	t.Helper()
	ns := newNS(t, s.paths, id)
	ep, err := s.Attach(n, id, ns, 0, netip.Addr{})
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
	if updated != 4 {
		t.Fatalf("updated %d links, want 4", updated)
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
