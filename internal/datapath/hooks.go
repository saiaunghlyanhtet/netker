package datapath

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Hook directions, named from the container's point of view.
const (
	HookEgress  = "egress"  // what the container sends: BPF_NETKIT_PEER
	HookIngress = "ingress" // what's delivered to it: BPF_NETKIT_PRIMARY
)

// Hook is a user BPF program on a container's netkit device, next to
// netker's own program for that direction.
type Hook struct {
	Name      string `json:"name"`
	Direction string `json:"direction"`
	After     bool   `json:"after,omitempty"` // after netker's program instead of before it
	// Spec and Program select the program to attach. Spec is the parsed
	// object file (see LoadHookSpec).
	Spec    *ebpf.CollectionSpec `json:"-"`
	Program string               `json:"program"`
}

var hookNameRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

// LoadHookSpec reads a hook's object file and picks its program: the one
// named (by function or section name), or the only SCHED_CLS program.
func LoadHookSpec(path, name string) (*ebpf.CollectionSpec, string, error) {
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return nil, "", fmt.Errorf("read hook %s: %w", path, err)
	}
	var found []string
	for fn, ps := range spec.Programs {
		if name != "" && fn != name && ps.SectionName != name {
			continue
		}
		if ps.Type != ebpf.SchedCLS {
			if name != "" {
				return nil, "", fmt.Errorf("hook program %s is %s, not a SCHED_CLS (tc) program", fn, ps.Type)
			}
			continue
		}
		found = append(found, fn)
	}
	sort.Strings(found)
	switch {
	case len(found) == 1:
		return spec, found[0], nil
	case len(found) == 0 && name != "":
		return nil, "", fmt.Errorf("no program %q in %s", name, path)
	case len(found) == 0:
		return nil, "", fmt.Errorf("no SCHED_CLS (tc) program in %s", path)
	}
	return nil, "", fmt.Errorf("%s has several programs (%s); pick one with --program", path, strings.Join(found, ", "))
}

func hookAttachType(direction string) (ebpf.AttachType, string, error) {
	switch direction {
	case HookEgress:
		return ebpf.AttachNetkitPeer, "peer", nil
	case HookIngress:
		return ebpf.AttachNetkitPrimary, "primary", nil
	}
	return 0, "", fmt.Errorf("hook direction %q: want %s or %s", direction, HookEgress, HookIngress)
}

func (d *Datapath) hooksDir(containerID string) string {
	return filepath.Join(d.root, "hooks", containerID)
}

// hookPin is where a hook's link is pinned. Hooks live apart from netker's
// own links, so "datapath upgrade" never replaces them with netker's
// programs.
func (d *Datapath) hookPin(containerID, hostIf, direction, name string) string {
	return filepath.Join(d.hooksDir(containerID), hostIf+"-"+direction+"-"+name)
}

// AttachHook loads h's program and attaches it to the device hostIf, just
// before (or after) netker's program for that direction. Hooks are
// attached through the primary, like netker's programs, so nothing inside
// the container can remove them.
func (d *Datapath) AttachHook(containerID, hostIf string, hostIfIndex int, h Hook) (err error) {
	if err := d.Load(); err != nil {
		return err
	}
	if !hookNameRE.MatchString(h.Name) {
		return fmt.Errorf("invalid hook name %q", h.Name)
	}
	typ, side, err := hookAttachType(h.Direction)
	if err != nil {
		return err
	}
	pin := d.hookPin(containerID, hostIf, h.Direction, h.Name)
	if _, err := os.Stat(pin); err == nil {
		return fmt.Errorf("hook %s is already attached to %s", h.Name, hostIf)
	}
	netkerLink, err := link.LoadPinnedLink(d.linkPin(containerID, hostIf, side), nil)
	if err != nil {
		return fmt.Errorf("netker's %s program on %s: %w", h.Direction, hostIf, err)
	}
	defer netkerLink.Close()
	anchor := link.BeforeLink(netkerLink)
	if h.After {
		anchor = link.AfterLink(netkerLink)
	}

	// Load only the chosen program (and the maps it uses).
	spec := h.Spec.Copy()
	for fn := range spec.Programs {
		if fn != h.Program {
			delete(spec.Programs, fn)
		}
	}
	ps, ok := spec.Programs[h.Program]
	if !ok {
		return fmt.Errorf("no program %q in the hook object", h.Program)
	}
	ps.AttachType = typ
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("load hook %s: %w", h.Name, err)
	}
	defer coll.Close()

	l, err := link.AttachNetkit(link.NetkitOptions{
		Interface: hostIfIndex,
		Program:   coll.Programs[h.Program],
		Attach:    typ,
		Anchor:    anchor,
	})
	if err != nil {
		return fmt.Errorf("attach hook %s to %s: %w", h.Name, hostIf, err)
	}
	defer l.Close()
	if err := os.MkdirAll(d.hooksDir(containerID), 0o700); err != nil {
		return err
	}
	// The pinned link keeps the program (and its maps) loaded.
	return l.Pin(pin)
}

// DetachHook removes one hook from hostIf. A missing hook is an error.
func (d *Datapath) DetachHook(containerID, hostIf, direction, name string) error {
	pin := d.hookPin(containerID, hostIf, direction, name)
	l, err := link.LoadPinnedLink(pin, nil)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("no hook %s on %s", name, hostIf)
	}
	if err != nil {
		// Defunct (device gone): just drop the pin.
		return os.Remove(pin)
	}
	defer l.Close()
	if err := l.Unpin(); err != nil {
		return err
	}
	os.Remove(d.hooksDir(containerID))
	return nil
}

// DetachHooks removes every hook on hostIf, e.g. when its endpoint goes.
func (d *Datapath) DetachHooks(containerID, hostIf string) error {
	entries, err := os.ReadDir(d.hooksDir(containerID))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var errs []error
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), hostIf+"-") {
			continue
		}
		p := filepath.Join(d.hooksDir(containerID), e.Name())
		if l, err := link.LoadPinnedLink(p, nil); err == nil {
			errs = append(errs, l.Unpin())
			l.Close()
		} else {
			errs = append(errs, os.Remove(p))
		}
	}
	os.Remove(d.hooksDir(containerID))
	return errors.Join(errs...)
}

// HookLink is a pinned hook as found in bpffs.
type HookLink struct {
	HostIf    string `json:"host_if"`
	Direction string `json:"direction"`
	Name      string `json:"name"`
	ProgramID uint32 `json:"program_id"`
	Defunct   bool   `json:"defunct"` // the device is gone
}

// HookLinks lists the hooks pinned for a container.
func (d *Datapath) HookLinks(containerID string) ([]HookLink, error) {
	entries, err := os.ReadDir(d.hooksDir(containerID))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []HookLink
	for _, e := range entries {
		// <hostIf>-<direction>-<name>; host interface names have no '-'.
		hostIf, rest, ok := strings.Cut(e.Name(), "-")
		if !ok {
			continue
		}
		dir, name, ok := strings.Cut(rest, "-")
		if !ok {
			continue
		}
		hl := HookLink{HostIf: hostIf, Direction: dir, Name: name}
		l, err := link.LoadPinnedLink(filepath.Join(d.hooksDir(containerID), e.Name()), nil)
		if err != nil {
			hl.Defunct = true
		} else {
			if info, err := l.Info(); err == nil {
				hl.ProgramID = uint32(info.Program)
				if nk := info.Netkit(); nk != nil && nk.Ifindex == 0 {
					hl.Defunct = true
				}
			}
			l.Close()
		}
		out = append(out, hl)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].HostIf < out[j].HostIf
	})
	return out, nil
}

// gcHooks removes the hook pins of containers keep reports as gone.
func (d *Datapath) gcHooks(keep func(string) bool) int {
	n := 0
	cids, _ := os.ReadDir(filepath.Join(d.root, "hooks"))
	for _, c := range cids {
		if keep(c.Name()) {
			continue
		}
		hls, _ := d.HookLinks(c.Name())
		for _, hl := range hls {
			d.DetachHooks(c.Name(), hl.HostIf)
			n++
		}
		os.Remove(d.hooksDir(c.Name()))
	}
	return n
}
