package container

import (
	"os"
	"reflect"
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
