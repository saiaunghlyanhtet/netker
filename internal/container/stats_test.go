package container

import (
	"testing"

	"github.com/saiaunghlyanhtet/netker/internal/network"
)

func TestDroppedTotal(t *testing.T) {
	ebpf := NetStats{Datapath: network.DatapathEBPF, Drops: map[string]uint64{"drop-icc": 3, "drop-spoof": 2}}
	ebpf.TxDropped = 99 // not used on eBPF: the datapath's counters are more precise
	if got := ebpf.DroppedTotal(); got != 5 {
		t.Fatalf("eBPF drops %d, want 5", got)
	}
	legacy := NetStats{Datapath: network.DatapathLegacy}
	legacy.TxDropped = 7
	if got := legacy.DroppedTotal(); got != 7 {
		t.Fatalf("legacy drops %d, want 7", got)
	}
}
