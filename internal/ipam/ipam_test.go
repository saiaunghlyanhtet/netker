package ipam

import (
	"errors"
	"net/netip"
	"sync"
	"testing"
)

func newPool(t *testing.T, cidr, gw string) *Pool {
	t.Helper()
	p, err := New(t.TempDir(), "test", netip.MustParsePrefix(cidr), netip.MustParseAddr(gw))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAllocateSkipsReserved(t *testing.T) {
	p := newPool(t, "10.0.0.0/29", "10.0.0.1")
	var got []string
	for {
		a, err := p.Allocate("c", netip.Addr{})
		if errors.Is(err, ErrExhausted) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, a.String())
	}
	want := []string{"10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestReleaseAndReuseAfterWrap(t *testing.T) {
	p := newPool(t, "10.0.0.0/29", "10.0.0.1")
	var addrs []netip.Addr
	for i := 0; i < 5; i++ {
		a, err := p.Allocate("c", netip.Addr{})
		if err != nil {
			t.Fatal(err)
		}
		addrs = append(addrs, a)
	}
	if err := p.Release(addrs[1]); err != nil {
		t.Fatal(err)
	}
	a, err := p.Allocate("d", netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	if a != addrs[1] {
		t.Fatalf("got %s, want freed %s", a, addrs[1])
	}
}

func TestExplicitAddress(t *testing.T) {
	p := newPool(t, "10.0.0.0/24", "10.0.0.1")
	if _, err := p.Allocate("a", netip.MustParseAddr("10.0.0.50")); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Allocate("b", netip.MustParseAddr("10.0.0.50")); err == nil {
		t.Fatal("expected conflict")
	}
	for _, bad := range []string{"10.0.0.0", "10.0.0.1", "10.0.0.255", "10.0.1.5"} {
		if _, err := p.Allocate("b", netip.MustParseAddr(bad)); err == nil {
			t.Fatalf("expected %s to be rejected", bad)
		}
	}
}

func TestReleaseOwner(t *testing.T) {
	p := newPool(t, "10.0.0.0/24", "10.0.0.1")
	a1, _ := p.Allocate("a", netip.Addr{})
	p.Allocate("b", netip.Addr{})
	if err := p.ReleaseOwner("a"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Allocate("c", a1); err != nil {
		t.Fatalf("address of released owner not free: %v", err)
	}
}

func TestConcurrentAllocationsAreUnique(t *testing.T) {
	p := newPool(t, "10.0.0.0/24", "10.0.0.1")
	var mu sync.Mutex
	seen := map[netip.Addr]bool{}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, err := p.Allocate("c", netip.Addr{})
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if seen[a] {
				t.Errorf("duplicate %s", a)
			}
			seen[a] = true
		}()
	}
	wg.Wait()
}
