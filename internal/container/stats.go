package container

import (
	"sort"

	"github.com/saiaunghlyanhtet/netker/internal/datapath"
	"github.com/saiaunghlyanhtet/netker/internal/network"
)

// NetStats are one container interface's counters.
type NetStats struct {
	Network  string `json:"network"`
	IfName   string `json:"ifname"`
	Datapath string `json:"datapath"`
	network.IfStats
	// Drops counts packets the eBPF datapath dropped, by reason, in both
	// directions. On the legacy datapath it's empty.
	Drops map[string]uint64 `json:"drops,omitempty"`
}

// DroppedTotal is the number shown in "netker stats": the datapath's drop
// counters on eBPF, the device's dropped transmissions on legacy.
func (n NetStats) DroppedTotal() uint64 {
	if n.Datapath != network.DatapathEBPF {
		return n.TxDropped
	}
	var t uint64
	for _, v := range n.Drops {
		t += v
	}
	return t
}

// NetStats reads the counters of each of c's network interfaces. metrics
// are the eBPF datapath's counters (nil when it isn't loaded); pass them
// in so that a refresh over many containers reads the map once.
func (m *Manager) NetStats(c *Container, metrics []datapath.Metric) ([]NetStats, error) {
	var out []NetStats
	for _, ep := range c.Endpoints {
		st, err := network.InterfaceStats(c.NetNSPath, ep.IfName)
		if err != nil {
			return nil, err
		}
		ns := NetStats{Network: ep.Network, IfName: ep.IfName, Datapath: ep.Datapath, IfStats: st}
		if ep.Datapath == network.DatapathEBPF {
			for _, mt := range metrics {
				if int(mt.Ifindex) == ep.HostIfIndex && mt.Drop {
					if ns.Drops == nil {
						ns.Drops = map[string]uint64{}
					}
					ns.Drops[mt.Reason] += mt.Packets
				}
			}
		}
		out = append(out, ns)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IfName < out[j].IfName })
	return out, nil
}
