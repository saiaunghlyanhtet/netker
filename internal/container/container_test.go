package container

import (
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/saiaunghlyanhtet/netker/internal/config"
	"github.com/saiaunghlyanhtet/netker/internal/network"
)

func TestValidateNetworks(t *testing.T) {
	cases := []struct {
		in      []string
		want    []string
		wantErr bool
	}{
		{nil, []string{"netker"}, false},
		{[]string{"a", "b"}, []string{"a", "b"}, false},
		{[]string{"host"}, []string{"host"}, false},
		{[]string{"none"}, []string{"none"}, false},
		{[]string{"host", "a"}, nil, true},
		{[]string{"a", "none"}, nil, true},
		{[]string{"a", "a"}, nil, true},
		{[]string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11"}, nil, true},
	}
	for _, c := range cases {
		got, err := validateNetworks(c.in)
		if (err != nil) != c.wantErr || (!c.wantErr && !reflect.DeepEqual(got, c.want)) {
			t.Errorf("validateNetworks(%v) = %v, %v; want %v, err=%v", c.in, got, err, c.want, c.wantErr)
		}
	}
}

func TestFreeIndex(t *testing.T) {
	eps := func(names ...string) []*network.Endpoint {
		var out []*network.Endpoint
		for _, n := range names {
			out = append(out, &network.Endpoint{IfName: n})
		}
		return out
	}
	cases := []struct {
		in   []*network.Endpoint
		want int
	}{
		{nil, 0},
		{eps("eth0"), 1},
		{eps("eth0", "eth1"), 2},
		{eps("eth1"), 0}, // eth0 was disconnected
		{eps("eth0", "eth2"), 1},
	}
	for _, c := range cases {
		if got := freeIndex(c.in); got != c.want {
			t.Errorf("freeIndex(%d endpoints) = %d, want %d", len(c.in), got, c.want)
		}
	}
}

func TestLoadBackfillsDefaultRoute(t *testing.T) {
	m := NewManager(config.Paths{Root: t.TempDir(), Run: t.TempDir()})
	id := "0123456789abcdef"
	if err := os.MkdirAll(m.dir(id), 0o755); err != nil {
		t.Fatal(err)
	}
	// A record from before endpoints stored default_route.
	old := `{"id":"` + id + `","name":"old","network":"a","endpoints":[{"network":"a","ifname":"eth0"},{"network":"b","ifname":"eth1"}]}`
	if err := os.WriteFile(m.recordPath(id), []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := m.load(id)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Endpoints[0].Default || c.Endpoints[1].Default {
		t.Fatalf("default route not backfilled onto eth0: %+v %+v", c.Endpoints[0], c.Endpoints[1])
	}
	if !reflect.DeepEqual(c.Networks, []string{"a"}) {
		t.Fatalf("networks %v", c.Networks)
	}
}

func TestHostsFile(t *testing.T) {
	ep := func(net, ip, ifname string) *network.Endpoint {
		return &network.Endpoint{Network: net, IP: netip.MustParseAddr(ip), IfName: ifname}
	}
	web := &Container{ID: "aaaaaaaaaaaa1111", Name: "web", Hostname: "aaaaaaaaaaaa",
		Endpoints: []*network.Endpoint{ep("front", "10.1.0.2", "eth0"), ep("back", "10.2.0.2", "eth1")}}
	db := &Container{ID: "bbbbbbbbbbbb2222", Name: "db", Hostname: "dbhost",
		Endpoints: []*network.Endpoint{ep("back", "10.2.0.3", "eth0")}}
	lb := &Container{ID: "cccccccccccc3333", Name: "lb", Hostname: "cccccccccccc",
		Endpoints: []*network.Endpoint{ep("front", "10.1.0.4", "eth0")}}
	other := &Container{ID: "dddddddddddd4444", Name: "other", Hostname: "dddddddddddd",
		Endpoints: []*network.Endpoint{ep("elsewhere", "10.9.0.2", "eth0")}}
	all := []*Container{web, db, lb, other}

	got := string(hostsFile(web, all))
	want := "127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n" +
		"10.1.0.2\tweb aaaaaaaaaaaa\n" +
		"10.2.0.2\tweb aaaaaaaaaaaa\n" +
		"10.2.0.3\tdb dbhost bbbbbbbbbbbb\n" +
		"10.1.0.4\tlb cccccccccccc\n"
	if got != want {
		t.Fatalf("web's hosts:\n%s\nwant:\n%s", got, want)
	}
	// db only shares "back" with web, so it sees web's back address only.
	if got := string(hostsFile(db, all)); !strings.Contains(got, "10.2.0.2\tweb") || strings.Contains(got, "10.1.0.2") || strings.Contains(got, "lb") {
		t.Fatalf("db's hosts:\n%s", got)
	}
	if got := string(hostsFile(other, all)); strings.Contains(got, "web") || strings.Contains(got, "db") {
		t.Fatalf("a container on another network was listed:\n%s", got)
	}
}
