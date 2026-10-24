package container

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/saiaunghlyanhtet/netker/internal/datapath"
	"github.com/saiaunghlyanhtet/netker/internal/network"
)

// HookOptions describe a user BPF hook to attach to a container.
type HookOptions struct {
	Name      string // default: the object file's name without extension
	Direction string // datapath.HookEgress or datapath.HookIngress
	After     bool   // after netker's program instead of before it
	Object    string // path to the BPF object file
	Program   string // program or section name; empty: the only tc program
}

// HookRecord is a hook as stored with the container. The object file is
// copied into the container's directory, so it doesn't matter if the
// original goes away, and networks connected later get the hook too.
type HookRecord struct {
	Name      string `json:"name"`
	Direction string `json:"direction"`
	After     bool   `json:"after,omitempty"`
	Program   string `json:"program"`
	Source    string `json:"source"` // where the object was copied from
}

func (m *Manager) hookObject(c *Container, name string) string {
	return filepath.Join(m.dir(c.ID), "hooks", name+".o")
}

// AddHook attaches a hook to every eBPF interface of c.
func (m *Manager) AddHook(c *Container, o HookOptions) error {
	unlock, err := m.lock()
	if err != nil {
		return err
	}
	defer unlock()
	if c, err = m.load(c.ID); err != nil {
		return err
	}
	return m.addHook(c, o)
}

func (m *Manager) addHook(c *Container, o HookOptions) (err error) {
	if o.Name == "" {
		o.Name = strings.TrimSuffix(filepath.Base(o.Object), filepath.Ext(o.Object))
	}
	if slices.ContainsFunc(c.Hooks, func(h HookRecord) bool { return h.Name == o.Name }) {
		return fmt.Errorf("container %s already has a hook named %s", c.Name, o.Name)
	}
	if len(c.Endpoints) == 0 {
		return fmt.Errorf("container %s has no network interfaces to hook", c.Name)
	}
	spec, prog, err := datapath.LoadHookSpec(o.Object, o.Program)
	if err != nil {
		return err
	}
	obj := m.hookObject(c, o.Name)
	if err := copyFile(o.Object, obj); err != nil {
		return err
	}
	h := datapath.Hook{Name: o.Name, Direction: o.Direction, After: o.After, Spec: spec, Program: prog}
	var done []*network.Endpoint
	defer func() {
		if err != nil {
			for _, ep := range done {
				m.Networks.DetachHook(c.ID, ep, o.Direction, o.Name)
			}
			os.Remove(obj)
		}
	}()
	for _, ep := range c.Endpoints {
		if err := m.Networks.AttachHook(c.ID, ep, h); err != nil {
			return err
		}
		done = append(done, ep)
	}
	abs, _ := filepath.Abs(o.Object)
	c.Hooks = append(c.Hooks, HookRecord{Name: o.Name, Direction: o.Direction, After: o.After, Program: prog, Source: abs})
	return m.save(c)
}

// applyHooks attaches c's recorded hooks to an endpoint added later.
func (m *Manager) applyHooks(c *Container, ep *network.Endpoint) error {
	var errs []error
	for _, r := range c.Hooks {
		spec, prog, err := datapath.LoadHookSpec(m.hookObject(c, r.Name), r.Program)
		if err == nil {
			err = m.Networks.AttachHook(c.ID, ep, datapath.Hook{Name: r.Name, Direction: r.Direction, After: r.After, Spec: spec, Program: prog})
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("hook %s on %s: %w", r.Name, ep.IfName, err))
		}
	}
	return errors.Join(errs...)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// RemoveHook detaches the hook name from every interface of c and forgets it.
func (m *Manager) RemoveHook(c *Container, name string) error {
	unlock, err := m.lock()
	if err != nil {
		return err
	}
	defer unlock()
	if c, err = m.load(c.ID); err != nil {
		return err
	}
	i := slices.IndexFunc(c.Hooks, func(h HookRecord) bool { return h.Name == name })
	if i < 0 {
		return fmt.Errorf("container %s has no hook named %s", c.Name, name)
	}
	r := c.Hooks[i]
	var errs []error
	for _, ep := range c.Endpoints {
		if err := m.Networks.DetachHook(c.ID, ep, r.Direction, r.Name); err != nil {
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	os.Remove(m.hookObject(c, name))
	c.Hooks = slices.Delete(c.Hooks, i, i+1)
	return m.save(c)
}

// HookState is a recorded hook on one interface, with what bpffs says.
type HookState struct {
	Container string `json:"container"`
	HookRecord
	IfName    string `json:"ifname"`
	ProgramID uint32 `json:"program_id"`
	State     string `json:"state"` // attached, defunct or missing
}

// Hooks lists c's hooks per interface.
func (m *Manager) Hooks(c *Container) ([]HookState, error) {
	pinned, err := m.Networks.Datapath().HookLinks(c.ID)
	if err != nil {
		return nil, err
	}
	var out []HookState
	for _, r := range c.Hooks {
		for _, ep := range c.Endpoints {
			st := HookState{Container: c.Name, HookRecord: r, IfName: ep.IfName, State: "missing"}
			for _, p := range pinned {
				if p.HostIf == ep.HostIf && p.Direction == r.Direction && p.Name == r.Name {
					st.ProgramID, st.State = p.ProgramID, "attached"
					if p.Defunct {
						st.State = "defunct"
					}
				}
			}
			out = append(out, st)
		}
	}
	return out, nil
}
