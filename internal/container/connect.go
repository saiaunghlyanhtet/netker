package container

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/saiaunghlyanhtet/netker/internal/network"
)

// Connect attaches a container to one more network, as the lowest free
// eth<N>. It works whether or not the container is running: the network
// namespace lives as long as the container.
func (m *Manager) Connect(c *Container, name string, ip netip.Addr) error {
	unlock, err := m.lock()
	if err != nil {
		return err
	}
	defer unlock()
	if c, err = m.load(c.ID); err != nil {
		return err
	}
	if c.NetNSPath == "" || slices.Contains(c.Networks, network.ModeNone) {
		return fmt.Errorf("container %s uses --network %s and can't join other networks", c.Name, c.Network)
	}
	if slices.Contains(c.Networks, name) {
		return fmt.Errorf("container %s is already connected to network %s", c.Name, name)
	}
	if len(c.Endpoints) >= 10 {
		return fmt.Errorf("at most 10 networks per container")
	}
	n, err := m.Networks.Get(name)
	if err != nil {
		return err
	}
	ep, err := m.Networks.Attach(n, c.ID, c.NetNSPath, freeIndex(c.Endpoints), ip, defaultEndpoint(c) == nil)
	if err != nil {
		return err
	}
	c.Endpoints = append(c.Endpoints, ep)
	c.Networks = append(c.Networks, name)
	c.Network = c.Networks[0]
	if err := m.save(c); err != nil {
		return err
	}
	if len(c.Endpoints) == 1 {
		// Its only network again: published ports come back with it.
		if err := m.Networks.Publish(c.ID, ep, c.Ports); err != nil {
			return err
		}
	}
	return m.writeEtcFiles(c)
}

// Disconnect removes a container from a network. If that attachment carried
// the default route, the next remaining one takes it over; if it carried
// the published ports, they move to the next remaining one.
func (m *Manager) Disconnect(c *Container, name string) error {
	unlock, err := m.lock()
	if err != nil {
		return err
	}
	defer unlock()
	if c, err = m.load(c.ID); err != nil {
		return err
	}
	i := slices.IndexFunc(c.Endpoints, func(ep *network.Endpoint) bool { return ep.Network == name })
	if i < 0 {
		return fmt.Errorf("container %s is not connected to network %s", c.Name, name)
	}
	ep := c.Endpoints[i]
	var errs []error
	if i == 0 {
		errs = append(errs, m.Networks.Unpublish(c.ID, []*network.Endpoint{ep}, c.Ports))
	}
	if err := m.Networks.Detach(ep, c.ID); err != nil {
		return errors.Join(append(errs, err)...)
	}
	c.Endpoints = slices.Delete(c.Endpoints, i, i+1)
	c.Networks = slices.DeleteFunc(c.Networks, func(n string) bool { return n == name })
	c.Network = ""
	if len(c.Networks) > 0 {
		c.Network = c.Networks[0]
	}
	if len(c.Endpoints) > 0 {
		if ep.Default {
			errs = append(errs, m.Networks.SetDefaultRoute(c.NetNSPath, c.Endpoints[0]))
		}
		if i == 0 {
			errs = append(errs, m.Networks.Publish(c.ID, c.Endpoints[0], c.Ports))
		}
	}
	errs = append(errs, m.save(c), m.writeEtcFiles(c))
	return errors.Join(errs...)
}

// freeIndex returns the lowest N with no eth<N> in use.
func freeIndex(eps []*network.Endpoint) int {
	for idx := 0; ; idx++ {
		name := fmt.Sprintf("eth%d", idx)
		if !slices.ContainsFunc(eps, func(ep *network.Endpoint) bool { return ep.IfName == name }) {
			return idx
		}
	}
}

func defaultEndpoint(c *Container) *network.Endpoint {
	for _, ep := range c.Endpoints {
		if ep.Default {
			return ep
		}
	}
	return nil
}
