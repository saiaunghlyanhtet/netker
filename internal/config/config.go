// Package config holds filesystem locations and global settings.
package config

import (
	"os"
	"path/filepath"
)

// Paths are the directories netker keeps state in. They can be overridden
// with NETKER_ROOT and NETKER_RUN, which the tests and the unprivileged
// sandbox (hack/sandbox.sh) rely on.
type Paths struct {
	Root string // persistent state: images, containers, networks, ipam
	Run  string // runtime state: netns bind mounts, OCI runtime state
}

func DefaultPaths() Paths {
	p := Paths{Root: "/var/lib/netker", Run: "/run/netker"}
	if v := os.Getenv("NETKER_ROOT"); v != "" {
		p.Root = v
	}
	if v := os.Getenv("NETKER_RUN"); v != "" {
		p.Run = v
	}
	return p
}

func (p Paths) Images() string             { return filepath.Join(p.Root, "images") }
func (p Paths) Containers() string         { return filepath.Join(p.Root, "containers") }
func (p Paths) Networks() string           { return filepath.Join(p.Root, "networks") }
func (p Paths) IPAM() string               { return filepath.Join(p.Root, "ipam") }
func (p Paths) NetNS() string              { return filepath.Join(p.Run, "netns") }
func (p Paths) RuntimeRoot() string        { return filepath.Join(p.Run, "runtime") }
func (p Paths) Container(id string) string { return filepath.Join(p.Containers(), id) }

// Runtime returns the OCI runtime binary (crun by default, NETKER_RUNTIME to override).
func Runtime() string {
	if v := os.Getenv("NETKER_RUNTIME"); v != "" {
		return v
	}
	return "crun"
}

// CgroupManager is passed to the OCI runtime as --cgroup-manager when set
// (e.g. "disabled" inside the unprivileged sandbox).
func CgroupManager() string {
	return os.Getenv("NETKER_CGROUP_MANAGER")
}
