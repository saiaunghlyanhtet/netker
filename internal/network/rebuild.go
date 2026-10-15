package network

import (
	"errors"
	"fmt"

	"github.com/saiaunghlyanhtet/netker/internal/datapath"
)

// RestoreItem is one container's datapath state, taken from its record.
type RestoreItem struct {
	ContainerID string
	NetNSPath   string
	Endpoints   []*Endpoint
	Ports       []PortMapping
}

// RebuildReport says what RebuildDatapath did.
type RebuildReport struct {
	Rebuilt   []datapath.IncompatibleMap `json:"rebuilt_maps"`
	Endpoints int                        `json:"endpoints"`
	Links     int                        `json:"links_updated"`
}

// RebuildDatapath brings the eBPF datapath in line with this binary: maps
// whose layout changed are recreated, every eBPF endpoint and published
// port is written again from the container records, and every program is
// swapped for this binary's. Maps that didn't change keep their contents;
// recreated NAT maps lose their flows, so connections through NAT reset.
func (s *Store) RebuildDatapath(items []RestoreItem) (*RebuildReport, error) {
	rebuilt, err := s.dp.RebuildMaps()
	if err != nil {
		return nil, err
	}
	report := &RebuildReport{Rebuilt: rebuilt}
	var errs []error
	for _, it := range items {
		for i, ep := range it.Endpoints {
			if ep.Datapath != DatapathEBPF {
				continue
			}
			n, err := s.Get(ep.Network)
			if err != nil {
				errs = append(errs, fmt.Errorf("container %s: %w", it.ContainerID, err))
				continue
			}
			dep, err := datapathEndpoint(n, ep, it.NetNSPath)
			if err == nil {
				err = s.dp.RestoreEndpoint(dep)
			}
			if err == nil && i == 0 && len(it.Ports) > 0 {
				err = s.dp.RestorePorts(ep.IP, ep.IP6, dep.HostIfIndex, bpfPorts(it.Ports))
			}
			if err != nil {
				errs = append(errs, fmt.Errorf("container %s, %s: %w", it.ContainerID, ep.IfName, err))
				continue
			}
			report.Endpoints++
		}
	}
	if err := s.dp.EnsureHost(); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		// Don't swap programs onto maps that are missing entries.
		return report, errors.Join(errs...)
	}
	report.Links, err = s.dp.FinishRebuild()
	return report, err
}
