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
	// Relinked lists the interfaces whose missing links were attached
	// again. Their user hooks were detached; the caller re-attaches them.
	Relinked []Relinked `json:"relinked,omitempty"`
	// Hooks counts the user hooks the caller attached again.
	Hooks int `json:"hooks_reattached,omitempty"`
}

// Relinked is an interface whose netker links were missing.
type Relinked struct {
	ContainerID string `json:"container_id"`
	IfName      string `json:"ifname"`
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
	type restored struct {
		containerID string
		ep          *Endpoint
		dep         datapath.Endpoint
	}
	var eps []restored
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
			eps = append(eps, restored{it.ContainerID, ep, dep})
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
	if err != nil {
		return report, err
	}
	// Only now: the new links use this binary's maps, which are pinned.
	for _, r := range eps {
		relinked, err := s.dp.Relink(r.containerID, r.dep)
		if err != nil {
			errs = append(errs, fmt.Errorf("container %s, %s: %w", r.containerID, r.ep.IfName, err))
		} else if relinked {
			report.Relinked = append(report.Relinked, Relinked{r.containerID, r.ep.IfName})
		}
	}
	return report, errors.Join(errs...)
}

// AttachHook attaches a user BPF program to ep's netkit device, next to
// netker's own program. Only eBPF endpoints have one to attach to.
func (s *Store) AttachHook(containerID string, ep *Endpoint, h datapath.Hook) error {
	if ep.Datapath != DatapathEBPF {
		return fmt.Errorf("%s uses the %s datapath: hooks need the eBPF datapath", ep.IfName, ep.Datapath)
	}
	return s.dp.AttachHook(containerID, ep.HostIf, ep.HostIfIndex, h)
}

// DetachHook removes a user BPF program from ep's netkit device.
func (s *Store) DetachHook(containerID string, ep *Endpoint, direction, name string) error {
	return s.dp.DetachHook(containerID, ep.HostIf, direction, name)
}
