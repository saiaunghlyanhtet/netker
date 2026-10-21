package network

import (
	"fmt"

	"github.com/vishvananda/netlink"

	"github.com/saiaunghlyanhtet/netker/internal/netns"
)

// IfStats are an interface's counters as the container sees them.
type IfStats struct {
	RxBytes   uint64 `json:"rx_bytes"`
	RxPackets uint64 `json:"rx_packets"`
	TxBytes   uint64 `json:"tx_bytes"`
	TxPackets uint64 `json:"tx_packets"`
	// TxDropped counts packets the container sent that its netkit device
	// dropped (a DROP verdict from the datapath, or no peer).
	TxDropped uint64 `json:"tx_dropped"`
}

// InterfaceStats reads the counters of the container's end of a netkit pair.
// That end sees everything: netkit counts a packet as sent there whether
// it's passed to the host or redirected in BPF, and as received whether it
// came through the primary or straight from an uplink (bpf_redirect_peer).
// The host-side primary misses traffic redirected in BPF.
func InterfaceStats(nsPath, ifname string) (IfStats, error) {
	var st IfStats
	err := netns.Do(nsPath, func() error {
		l, err := netlink.LinkByName(ifname)
		if err != nil {
			return err
		}
		s := l.Attrs().Statistics
		if s == nil {
			return fmt.Errorf("%s: no statistics", ifname)
		}
		st = IfStats{
			RxBytes: s.RxBytes, RxPackets: s.RxPackets,
			TxBytes: s.TxBytes, TxPackets: s.TxPackets,
			TxDropped: s.TxDropped,
		}
		return nil
	})
	return st, err
}
