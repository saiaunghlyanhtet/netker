package datapath

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
)

// ErrIncompatibleMaps means pinned maps were created by a netker version
// with a different map layout. Loading would fail for every map, so netker
// refuses until "netker system datapath upgrade" rebuilds them.
var ErrIncompatibleMaps = errors.New("pinned datapath maps have a different layout")

// IncompatibleMap names a pinned map and how its layout differs.
type IncompatibleMap struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

type IncompatibleMapsError struct {
	Maps []IncompatibleMap
}

func (e *IncompatibleMapsError) Error() string {
	var parts []string
	for _, m := range e.Maps {
		parts = append(parts, fmt.Sprintf("%s (%s)", m.Name, m.Reason))
	}
	return fmt.Sprintf("pinned datapath maps from another netker version don't match this one: %s; run \"netker system datapath upgrade\" to rebuild them",
		strings.Join(parts, ", "))
}

func (e *IncompatibleMapsError) Unwrap() error { return ErrIncompatibleMaps }

// CheckMaps compares every pinned map with this binary's map specs.
func (d *Datapath) CheckMaps() ([]IncompatibleMap, error) {
	spec, err := loadNetker()
	if err != nil {
		return nil, err
	}
	var out []IncompatibleMap
	for name, ms := range spec.Maps {
		if ms.Pinning != ebpf.PinByName {
			continue
		}
		m, err := ebpf.LoadPinnedMap(filepath.Join(d.mapsDir(), name), nil)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("pinned map %s: %w", name, err)
		}
		err = ms.Compatible(m)
		m.Close()
		if err != nil {
			reason := strings.TrimSuffix(err.Error(), ": "+ebpf.ErrMapIncompatible.Error())
			out = append(out, IncompatibleMap{Name: name, Reason: reason})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// RebuildMaps loads this binary's datapath with every incompatible map
// replaced by a fresh, unpinned one, and leaves the old pins in place (as
// Cilium's loader does, pkg/bpf/collection.go). The caller restores
// endpoints and ports into the new maps and calls FinishRebuild, which
// moves every program onto them and only then replaces the pins. If
// anything fails before that, bpffs is unchanged: running containers keep
// the old maps, and the next netker run sees the same state.
func (d *Datapath) RebuildMaps() ([]IncompatibleMap, error) {
	d.Close()
	bad, err := d.CheckMaps()
	if err != nil {
		return nil, err
	}
	spec, err := loadNetker()
	if err != nil {
		return nil, err
	}
	for _, m := range bad {
		spec.Maps[m.Name].Pinning = ebpf.PinNone
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: d.mapsDir()},
	})
	if err != nil {
		return nil, fmt.Errorf("load eBPF datapath: %w", err)
	}
	// Take the maps to re-pin before Assign moves them out of coll.
	pending := map[string]*ebpf.Map{}
	for _, m := range bad {
		pending[m.Name] = coll.Maps[m.Name]
	}
	var objs netkerObjects
	if err := coll.Assign(&objs); err != nil {
		coll.Close()
		return nil, err
	}
	coll.Close()
	d.objs = &objs
	d.pendingPins = pending
	return bad, nil
}

// FinishRebuild updates every pinned link to this binary's programs, which
// use the new maps, and then points the pins at the new maps. The old maps
// go away with the last program using them.
func (d *Datapath) FinishRebuild() (int, error) {
	n, err := d.Upgrade()
	if err != nil {
		return n, err
	}
	var errs []error
	for name, m := range d.pendingPins {
		p := filepath.Join(d.mapsDir(), name)
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("replace pin %s: %w", name, err))
			continue
		}
		if err := m.Pin(p); err != nil {
			errs = append(errs, fmt.Errorf("pin new map %s: %w", name, err))
		}
	}
	d.pendingPins = nil
	return n, errors.Join(errs...)
}
