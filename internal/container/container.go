// Package container implements the container lifecycle: rootfs, network
// namespace, netkit attachment and the OCI runtime.
package container

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/saiaunghlyanhtet/netker/internal/config"
	"github.com/saiaunghlyanhtet/netker/internal/image"
	"github.com/saiaunghlyanhtet/netker/internal/network"
	"github.com/saiaunghlyanhtet/netker/internal/oci"
)

var ErrNotFound = errors.New("no such container")

// Container is the persisted record of a container.
type Container struct {
	ID          string                `json:"id"`
	Name        string                `json:"name"`
	Image       string                `json:"image"`
	ImageDigest string                `json:"image_digest"`
	Created     time.Time             `json:"created"`
	Args        []string              `json:"args"`
	Env         []string              `json:"env"`
	Cwd         string                `json:"cwd"`
	User        string                `json:"user,omitempty"`
	Tty         bool                  `json:"tty"`
	Hostname    string                `json:"hostname"`
	Network     string                `json:"network"` // first network, "host" or "none"
	Networks    []string              `json:"networks,omitempty"`
	NetNSPath   string                `json:"netns,omitempty"`
	Endpoints   []*network.Endpoint   `json:"endpoints,omitempty"`
	Ports       []network.PortMapping `json:"ports,omitempty"`
	AutoRemove  bool                  `json:"auto_remove"`
}

// Status is the runtime status plus netker's own states.
func (m *Manager) Status(c *Container) string {
	st, err := m.rt.State(c.ID)
	if err != nil {
		return "created"
	}
	switch st.Status {
	case "stopped":
		return "exited"
	default:
		return st.Status
	}
}

type Manager struct {
	Paths    config.Paths
	Images   *image.Store
	Networks *network.Store
	rt       *oci.Runtime
}

func NewManager(p config.Paths) *Manager {
	return &Manager{
		Paths:    p,
		Images:   image.NewStore(p),
		Networks: network.NewStore(p),
		rt:       &oci.Runtime{Bin: config.Runtime(), Root: p.RuntimeRoot(), CgroupManager: config.CgroupManager()},
	}
}

func (m *Manager) dir(id string) string        { return m.Paths.Container(id) }
func (m *Manager) bundle(id string) string     { return filepath.Join(m.dir(id), "bundle") }
func (m *Manager) rootfs(id string) string     { return filepath.Join(m.bundle(id), "rootfs") }
func (m *Manager) LogPath(id string) string    { return filepath.Join(m.dir(id), "container.log") }
func (m *Manager) recordPath(id string) string { return filepath.Join(m.dir(id), "container.json") }

func (m *Manager) save(c *Container) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := m.recordPath(c.ID) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, m.recordPath(c.ID))
}

func (m *Manager) load(id string) (*Container, error) {
	data, err := os.ReadFile(m.recordPath(id))
	if err != nil {
		return nil, err
	}
	var c Container
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	if len(c.Networks) == 0 && c.Network != "" {
		c.Networks = []string{c.Network}
	}
	return &c, nil
}

// List returns all containers, newest first.
func (m *Manager) List() ([]*Container, error) {
	entries, err := os.ReadDir(m.Paths.Containers())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []*Container
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		c, err := m.load(e.Name())
		if err != nil {
			continue // half-created or being removed
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out, nil
}

// Get finds a container by name, full ID or unique ID prefix.
func (m *Manager) Get(ref string) (*Container, error) {
	all, err := m.List()
	if err != nil {
		return nil, err
	}
	var matches []*Container
	for _, c := range all {
		if c.Name == ref || c.ID == ref {
			return c, nil
		}
		if strings.HasPrefix(c.ID, ref) {
			matches = append(matches, c)
		}
	}
	switch len(matches) {
	case 0:
		return nil, fmt.Errorf("%s: %w", ref, ErrNotFound)
	case 1:
		return matches[0], nil
	}
	return nil, fmt.Errorf("%q matches %d containers, use a longer ID", ref, len(matches))
}

// lock serialises operations that must see a consistent set of containers
// (name allocation, create, remove).
func (m *Manager) lock() (func(), error) {
	if err := os.MkdirAll(m.Paths.Containers(), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(m.Paths.Root, "containers.lock"), os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { f.Close() }, nil
}

// InUse reports whether any container uses the image digest.
func (m *Manager) ImageInUse(digest string) bool {
	all, _ := m.List()
	for _, c := range all {
		if c.ImageDigest == digest {
			return true
		}
	}
	return false
}

// NetworkInUse reports whether any container is attached to the network.
func (m *Manager) NetworkInUse(name string) bool {
	all, _ := m.List()
	for _, c := range all {
		for _, ep := range c.Endpoints {
			if ep.Network == name {
				return true
			}
		}
	}
	return false
}
