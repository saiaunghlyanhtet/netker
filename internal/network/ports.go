package network

import (
	"errors"
	"net/netip"

	"github.com/saiaunghlyanhtet/netker/internal/datapath"
)

// Publish makes ports reachable from the host and the outside world: in BPF
// (uplink ingress, connect4 and hairpin) for eBPF endpoints, with nftables
// DNAT otherwise.
func (s *Store) Publish(containerID string, ep *Endpoint, ports []PortMapping) error {
	if len(ports) == 0 {
		return nil
	}
	if ep.Datapath != DatapathEBPF {
		return PublishPorts(containerID, ep.IP.String(), ports)
	}
	return s.dp.Publish(ep.IP, ep.HostIfIndex, bpfPorts(ports))
}

// Unpublish removes what Publish installed.
func (s *Store) Unpublish(containerID string, eps []*Endpoint, ports []PortMapping) error {
	if len(ports) == 0 {
		return nil
	}
	var errs []error
	for _, ep := range eps {
		if ep.Datapath == DatapathEBPF {
			errs = append(errs, s.dp.Unpublish(ep.IP, bpfPorts(ports)))
		}
	}
	errs = append(errs, UnpublishPorts(containerID))
	return errors.Join(errs...)
}

func bpfPorts(ports []PortMapping) []datapath.Port {
	out := make([]datapath.Port, 0, len(ports))
	for _, p := range ports {
		dp := datapath.Port{HostPort: p.HostPort, ContainerPort: p.ContainerPort, Protocol: p.Protocol}
		if p.HostIP != "" {
			dp.HostIP, _ = netip.ParseAddr(p.HostIP)
		}
		out = append(out, dp)
	}
	return out
}
