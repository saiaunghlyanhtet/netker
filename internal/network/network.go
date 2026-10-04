// Package network manages netker networks and connects containers to them
// with netkit pairs.
//
// The device setup is the same for both datapaths. With the eBPF datapath
// (internal/datapath) BPF programs on the devices forward and NAT; with the
// legacy one the host stack forwards and nftables does NAT.
package network

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"

	"github.com/saiaunghlyanhtet/netker/internal/config"
	"github.com/saiaunghlyanhtet/netker/internal/datapath"
	"github.com/saiaunghlyanhtet/netker/internal/idutil"
	"github.com/saiaunghlyanhtet/netker/internal/ipam"
	"github.com/saiaunghlyanhtet/netker/internal/netkit"
)

const (
	DefaultName   = "netker"
	defaultSubnet = "10.87.0.0/16"
	DefaultMTU    = 1500
)

// Special --network values that don't create a netkit pair.
const (
	ModeHost = "host"
	ModeNone = "none"
)

var ErrNotFound = errors.New("network not found")

type Network struct {
	Name     string       `json:"name"`
	Subnet   netip.Prefix `json:"subnet"`
	Gateway  netip.Addr   `json:"gateway"`
	Mode     netkit.Mode  `json:"netkit_mode"`
	MTU      int          `json:"mtu"`
	Internal bool         `json:"internal"`
}

type Store struct {
	paths config.Paths
	dp    *datapath.Datapath
}

func NewStore(p config.Paths) *Store {
	return &Store{paths: p, dp: datapath.New(config.BPFFS())}
}

// Datapath gives access to the eBPF datapath (for status and upgrades).
func (s *Store) Datapath() *datapath.Datapath { return s.dp }

func (s *Store) file(name string) string { return filepath.Join(s.paths.Networks(), name+".json") }

// Get loads a network, creating the default network on first use.
func (s *Store) Get(name string) (*Network, error) {
	data, err := os.ReadFile(s.file(name))
	if os.IsNotExist(err) {
		if name == DefaultName {
			return s.createDefault()
		}
		return nil, fmt.Errorf("%s: %w", name, ErrNotFound)
	}
	if err != nil {
		return nil, err
	}
	var n Network
	if err := json.Unmarshal(data, &n); err != nil {
		return nil, fmt.Errorf("network %s: %w", name, err)
	}
	return &n, nil
}

func (s *Store) createDefault() (*Network, error) {
	n := &Network{
		Name:    DefaultName,
		Subnet:  netip.MustParsePrefix(defaultSubnet),
		Gateway: netip.MustParseAddr("10.87.0.1"),
		Mode:    netkit.ModeL3,
		MTU:     DefaultMTU,
	}
	if err := s.save(n, false); err != nil && !os.IsExist(err) {
		return nil, err
	}
	return n, nil
}

// Create adds a user-defined network. The gateway defaults to the first
// address of the subnet.
func (s *Store) Create(n *Network) error {
	if err := idutil.ValidateName(n.Name); err != nil {
		return err
	}
	if n.Name == ModeHost || n.Name == ModeNone {
		return fmt.Errorf("%q is a reserved network name", n.Name)
	}
	if !n.Subnet.IsValid() || !n.Subnet.Addr().Is4() {
		return fmt.Errorf("an IPv4 --subnet is required")
	}
	n.Subnet = n.Subnet.Masked()
	if !n.Gateway.IsValid() {
		n.Gateway = n.Subnet.Addr().Next()
	}
	if !n.Subnet.Contains(n.Gateway) {
		return fmt.Errorf("gateway %s not in subnet %s", n.Gateway, n.Subnet)
	}
	if n.Mode == "" {
		n.Mode = netkit.ModeL3
	}
	if n.MTU == 0 {
		n.MTU = DefaultMTU
	}
	all, err := s.List()
	if err != nil {
		return err
	}
	for _, o := range all {
		if o.Subnet.Overlaps(n.Subnet) {
			return fmt.Errorf("subnet %s overlaps network %s (%s)", n.Subnet, o.Name, o.Subnet)
		}
	}
	return s.save(n, false)
}

func (s *Store) save(n *Network, overwrite bool) error {
	if err := os.MkdirAll(s.paths.Networks(), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(n, "", "  ")
	if err != nil {
		return err
	}
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	if overwrite {
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	}
	f, err := os.OpenFile(s.file(n.Name), flags, 0o644)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("network %s already exists: %w", n.Name, err)
		}
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}

// List returns all networks, including the default one.
func (s *Store) List() ([]*Network, error) {
	if _, err := s.Get(DefaultName); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(s.paths.Networks())
	if err != nil {
		return nil, err
	}
	var out []*Network
	for _, e := range entries {
		name := e.Name()
		if filepath.Ext(name) != ".json" {
			continue
		}
		n, err := s.Get(name[:len(name)-len(".json")])
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Remove deletes a user-defined network. inUse reports whether any
// container is still attached.
func (s *Store) Remove(name string, inUse bool) error {
	if name == DefaultName {
		return fmt.Errorf("the default network cannot be removed")
	}
	if _, err := s.Get(name); err != nil {
		return err
	}
	if inUse {
		return fmt.Errorf("network %s has attached containers", name)
	}
	if err := removeNetworkRules(name); err != nil {
		return err
	}
	os.Remove(filepath.Join(s.paths.IPAM(), name+".json"))
	os.Remove(filepath.Join(s.paths.IPAM(), name+".json.lock"))
	return os.Remove(s.file(name))
}

func (s *Store) pool(n *Network) (*ipam.Pool, error) {
	return ipam.New(s.paths.IPAM(), n.Name, n.Subnet, n.Gateway)
}
