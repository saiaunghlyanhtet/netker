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

func portKey(p Port) (netkerPortKey, error) {
	proto, err := protoNum(p.Protocol)
	if err != nil {
		return netkerPortKey{}, err
	}
	k := netkerPortKey{Port: be16(p.HostPort), Proto: proto}
	if p.HostIP.IsValid() && !p.HostIP.IsUnspecified() {
		if !p.HostIP.Is4() {
			return k, fmt.Errorf("host IP %s: only IPv4 is supported", p.HostIP)
		}
		k.Addr = be32(p.HostIP)
	}
	return k, nil
}

// Publish maps each host port to the container. A port that's already
// published fails, like Docker's "port is already allocated".
func (d *Datapath) Publish(ctrIP netip.Addr, ifindex int, ports []Port) (err error) {
	if err := d.EnsureHost(); err != nil {
		return err
	}
	var done []Port
	defer func() {
		if err != nil {
			d.Unpublish(ctrIP, done)
		}
	}()
	for _, p := range ports {
		k, err := portKey(p)
		if err != nil {
			return err
		}
		v := netkerPortVal{CtrAddr: be32(ctrIP), CtrPort: be16(p.ContainerPort), Ifindex: uint32(ifindex)}
		if err := d.objs.NetkerPorts.Update(k, v, ebpf.UpdateNoExist); err != nil {
			if errors.Is(err, ebpf.ErrKeyExist) {
				return fmt.Errorf("port %d/%s is already allocated", p.HostPort, p.Protocol)
			}
			return err
		}
		done = append(done, p)
	}
	return nil
}

// Unpublish removes the container's entries; entries owned by another
// container are left alone.
func (d *Datapath) Unpublish(ctrIP netip.Addr, ports []Port) error {
	if err := d.Load(); err != nil {
		return err
	}
	var errs []error
	for _, p := range ports {
		k, err := portKey(p)
		if err != nil {
			continue
		}
		var v netkerPortVal
		if err := d.objs.NetkerPorts.Lookup(k, &v); err != nil {
			continue
		}
		if v.CtrAddr != be32(ctrIP) {
			continue
		}
		if err := d.objs.NetkerPorts.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, err)
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
	return out, it.Err()
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
	return n, it.Err()
}
