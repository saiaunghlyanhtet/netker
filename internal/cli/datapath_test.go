package cli

import (
	"slices"
	"testing"

	"github.com/saiaunghlyanhtet/netker/internal/datapath"
)

func TestGCLines(t *testing.T) {
	got := gcLines(datapath.GCReport{Links: 2, Hooks: 1, Endpoints: 1, Ports: 3})
	want := []string{
		"removed 2 orphaned container links and 1 hook link",
		"removed 0 uplink hooks of devices that are gone",
		"removed 1 stale endpoint entry and 3 published-port entries",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}
