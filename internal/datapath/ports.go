package datapath

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// Port is one published port (docker -p) handled in BPF.
type Port struct {
	HostIP        netip.Addr // invalid = every host address
	HostPort      uint16
	ContainerPort uint16
	Protocol      string // tcp or udp
}

func protoNum(p string) (uint8, error) {
	switch p {
	case "tcp":
		return unix.IPPROTO_TCP, nil
	case "udp":
		return unix.IPPROTO_UDP, nil
	}
	return 0, fmt.Errorf("unsupported protocol %q", p)
}

// portKeys returns the map keys a published port needs. Like Docker, a
// port without a host IP is published on IPv4 and, if the container has
// IPv6, on IPv6; 0.0.0.0 and [::] pick one family.
func portKeys(p Port, hasIPv6 bool) (k4 *netkerPortKey, k6 *netkerPort6Key, err error) {
	proto, err := protoNum(p.Protocol)
	if err != nil {
		return nil, nil, err
	}
	v4 := !p.HostIP.IsValid() || p.HostIP.Is4()
	v6 := (!p.HostIP.IsValid() && hasIPv6) || (p.HostIP.IsValid() && p.HostIP.Is6())
	if p.HostIP.IsValid() && p.HostIP.Is6() && !hasIPv6 {
		return nil, nil, fmt.Errorf("host IP %s: the container has no IPv6 address", p.HostIP)
	}
	if v4 {
		k4 = &netkerPortKey{Port: be16(p.HostPort), Proto: proto}
		if p.HostIP.IsValid() && !p.HostIP.IsUnspecified() {
			k4.Addr = be32(p.HostIP)
		}
	}
	if v6 {
		k6 = &netkerPort6Key{Port: be16(p.HostPort), Proto: proto}
		if p.HostIP.IsValid() && !p.HostIP.IsUnspecified() {
			k6.Addr = p.HostIP.As16()
		}
	}
	return k4, k6, nil
}

// Publish maps each host port to the container (ctrIP6 may be the zero
// Addr). A port that's already published fails, like Docker's "port is
// already allocated".
func (d *Datapath) Publish(ctrIP, ctrIP6 netip.Addr, ifindex int, ports []Port) error {
	return d.publish(ctrIP, ctrIP6, ifindex, ports, ebpf.UpdateNoExist)
}

// RestorePorts rewrites a container's published ports, e.g. after the
// maps were rebuilt. Existing entries are overwritten.
func (d *Datapath) RestorePorts(ctrIP, ctrIP6 netip.Addr, ifindex int, ports []Port) error {
	return d.publish(ctrIP, ctrIP6, ifindex, ports, ebpf.UpdateAny)
}

func (d *Datapath) publish(ctrIP, ctrIP6 netip.Addr, ifindex int, ports []Port, flags ebpf.MapUpdateFlags) (err error) {
	if err := d.EnsureHost(); err != nil {
		return err
	}
	var done []Port
	defer func() {
		if err != nil {
			d.Unpublish(ctrIP, ctrIP6, done)
		}
	}()
	taken := func(p Port, err error) error {
		if errors.Is(err, ebpf.ErrKeyExist) {
			return fmt.Errorf("port %d/%s is already allocated", p.HostPort, p.Protocol)
		}
		return err
	}
	for _, p := range ports {
		k4, k6, err := portKeys(p, ctrIP6.IsValid())
		if err != nil {
			return err
		}
		if k4 != nil {
			v := netkerPortVal{CtrAddr: be32(ctrIP), CtrPort: be16(p.ContainerPort), Ifindex: uint32(ifindex)}
			if err := d.objs.NetkerPorts.Update(k4, v, flags); err != nil {
				return taken(p, err)
			}
		}
		if k6 != nil {
			v := netkerPort6Val{CtrAddr: ctrIP6.As16(), CtrPort: be16(p.ContainerPort), Ifindex: uint32(ifindex)}
			if err := d.objs.NetkerPorts6.Update(k6, v, flags); err != nil {
				// The IPv4 half is in place; roll it back with this port.
				done = append(done, p)
				return taken(p, err)
			}
		}
		done = append(done, p)
	}
	return nil
}

// Unpublish removes the container's entries; entries owned by another
// container are left alone.
func (d *Datapath) Unpublish(ctrIP, ctrIP6 netip.Addr, ports []Port) error {
	if err := d.Load(); err != nil {
		return err
	}
	var errs []error
	for _, p := range ports {
		k4, k6, err := portKeys(p, ctrIP6.IsValid())
		if err != nil {
			continue
		}
		var v4 netkerPortVal
		if k4 != nil && d.objs.NetkerPorts.Lookup(k4, &v4) == nil && v4.CtrAddr == be32(ctrIP) {
			if err := d.objs.NetkerPorts.Delete(k4); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				errs = append(errs, err)
			}
		}
		var v6 netkerPort6Val
		if k6 != nil && d.objs.NetkerPorts6.Lookup(k6, &v6) == nil && v6.CtrAddr == ctrIP6.As16() {
			if err := d.objs.NetkerPorts6.Delete(k6); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// PortEntry is one row of the published-ports map.
type PortEntry struct {
	HostIP        string     `json:"host_ip"`
	HostPort      uint16     `json:"host_port"`
	Protocol      string     `json:"protocol"`
	ContainerIP   netip.Addr `json:"container_ip"`
	ContainerPort uint16     `json:"container_port"`
}

func (d *Datapath) Ports() ([]PortEntry, error) {
	if err := d.Load(); err != nil {
		return nil, err
	}
	var out []PortEntry
	var k netkerPortKey
	var v netkerPortVal
	it := d.objs.NetkerPorts.Iterate()
	for it.Next(&k, &v) {
		e := PortEntry{
			HostIP:        "0.0.0.0",
			HostPort:      portFromBE16(k.Port),
			Protocol:      map[uint8]string{unix.IPPROTO_TCP: "tcp", unix.IPPROTO_UDP: "udp"}[k.Proto],
			ContainerIP:   addrFromBE32(v.CtrAddr),
			ContainerPort: portFromBE16(v.CtrPort),
		}
		if k.Addr != 0 {
			e.HostIP = addrFromBE32(k.Addr).String()
		}
		out = append(out, e)
	}
	if err := it.Err(); err != nil {
		return nil, err
	}
	var k6 netkerPort6Key
	var v6 netkerPort6Val
	it6 := d.objs.NetkerPorts6.Iterate()
	for it6.Next(&k6, &v6) {
		out = append(out, PortEntry{
			HostIP:        netip.AddrFrom16(k6.Addr).String(),
			HostPort:      portFromBE16(k6.Port),
			Protocol:      map[uint8]string{unix.IPPROTO_TCP: "tcp", unix.IPPROTO_UDP: "udp"}[k6.Proto],
			ContainerIP:   netip.AddrFrom16(v6.CtrAddr),
			ContainerPort: portFromBE16(v6.CtrPort),
		})
	}
	return out, it6.Err()
}

// NATEntries counts the connection-tracking entries.
func (d *Datapath) NATEntries() (int, error) {
	if err := d.Load(); err != nil {
		return 0, err
	}
	n := 0
	var k netkerNatKey
	var v netkerNatVal
	it := d.objs.NetkerNat.Iterate()
	for it.Next(&k, &v) {
		n++
	}
	if err := it.Err(); err != nil {
		return n, err
	}
	var k6 netkerNat6Key
	var v6 netkerNat6Val
	it6 := d.objs.NetkerNat6.Iterate()
	for it6.Next(&k6, &v6) {
		n++
	}
	return n, it6.Err()
}
