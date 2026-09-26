// Package oci generates OCI runtime specs and drives an OCI runtime (crun or
// runc) through its CLI.
package oci

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

// SpecOptions is everything netker decides about a container's process and
// namespaces.
type SpecOptions struct {
	Args     []string
	Env      []string
	Cwd      string
	User     string // "uid[:gid]" or "name[:group]", resolved against the rootfs
	Tty      bool
	Hostname string
	// NetNSPath joins an existing network namespace; empty with HostNetwork
	// false creates a fresh one; HostNetwork shares the host's.
	NetNSPath   string
	HostNetwork bool
	// Files bind-mounted read-only over /etc/hosts, /etc/hostname and
	// /etc/resolv.conf.
	HostsFile, HostnameFile, ResolvConf string
	Rootfs                              string // absolute path, used to resolve users
}

// Same default capability set as Docker.
var defaultCaps = []string{
	"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FSETID", "CAP_FOWNER", "CAP_MKNOD",
	"CAP_NET_RAW", "CAP_SETGID", "CAP_SETUID", "CAP_SETFCAP", "CAP_SETPCAP",
	"CAP_NET_BIND_SERVICE", "CAP_SYS_CHROOT", "CAP_KILL", "CAP_AUDIT_WRITE",
}

func Spec(o SpecOptions) (*specs.Spec, error) {
	uid, gid, err := resolveUser(o.Rootfs, o.User)
	if err != nil {
		return nil, err
	}
	cwd := o.Cwd
	if cwd == "" {
		cwd = "/"
	}
	env := o.Env
	if !hasEnv(env, "PATH") {
		env = append([]string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}, env...)
	}
	if o.Tty && !hasEnv(env, "TERM") {
		env = append(env, "TERM=xterm")
	}
	env = append(env, "HOSTNAME="+o.Hostname)

	caps := append([]string(nil), defaultCaps...)
	s := &specs.Spec{
		Version:  specs.Version,
		Hostname: o.Hostname,
		Root:     &specs.Root{Path: "rootfs"},
		Process: &specs.Process{
			Terminal: o.Tty,
			User:     specs.User{UID: uid, GID: gid},
			Args:     o.Args,
			Env:      env,
			Cwd:      cwd,
			Capabilities: &specs.LinuxCapabilities{
				Bounding:  caps,
				Effective: caps,
				Permitted: caps,
			},
			Rlimits: []specs.POSIXRlimit{nofileLimit()},
		},
		Mounts: []specs.Mount{
			{Destination: "/proc", Type: "proc", Source: "proc", Options: []string{"nosuid", "noexec", "nodev"}},
			{Destination: "/dev", Type: "tmpfs", Source: "tmpfs", Options: []string{"nosuid", "strictatime", "mode=755", "size=65536k"}},
			{Destination: "/dev/pts", Type: "devpts", Source: "devpts", Options: []string{"nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"}},
			{Destination: "/dev/shm", Type: "tmpfs", Source: "shm", Options: []string{"nosuid", "noexec", "nodev", "mode=1777", "size=65536k"}},
			{Destination: "/dev/mqueue", Type: "mqueue", Source: "mqueue", Options: []string{"nosuid", "noexec", "nodev"}},
			{Destination: "/sys", Type: "sysfs", Source: "sysfs", Options: []string{"nosuid", "noexec", "nodev", "ro"}},
			{Destination: "/sys/fs/cgroup", Type: "cgroup", Source: "cgroup", Options: []string{"nosuid", "noexec", "nodev", "relatime", "ro"}},
		},
		Linux: &specs.Linux{
			Namespaces: []specs.LinuxNamespace{
				{Type: specs.PIDNamespace},
				{Type: specs.IPCNamespace},
				{Type: specs.UTSNamespace},
				{Type: specs.MountNamespace},
				{Type: specs.CgroupNamespace},
			},
			MaskedPaths: []string{
				"/proc/acpi", "/proc/asound", "/proc/kcore", "/proc/keys", "/proc/latency_stats",
				"/proc/timer_list", "/proc/timer_stats", "/proc/sched_debug", "/proc/scsi",
				"/sys/firmware", "/sys/devices/virtual/powercap",
			},
			ReadonlyPaths: []string{
				"/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger",
			},
		},
	}
	switch {
	case o.HostNetwork:
		// No network namespace entry: share the host's.
	case o.NetNSPath != "":
		s.Linux.Namespaces = append(s.Linux.Namespaces, specs.LinuxNamespace{Type: specs.NetworkNamespace, Path: o.NetNSPath})
	default:
		s.Linux.Namespaces = append(s.Linux.Namespaces, specs.LinuxNamespace{Type: specs.NetworkNamespace})
	}
	for dst, src := range map[string]string{"/etc/hosts": o.HostsFile, "/etc/hostname": o.HostnameFile, "/etc/resolv.conf": o.ResolvConf} {
		if src != "" {
			s.Mounts = append(s.Mounts, specs.Mount{Destination: dst, Type: "bind", Source: src, Options: []string{"rbind", "ro"}})
		}
	}
	return s, nil
}

// nofileLimit gives containers netker's own hard NOFILE limit as both soft
// and hard limit. Asking for more fails when netker can't raise its own
// limit (e.g. inside a user namespace).
func nofileLimit() specs.POSIXRlimit {
	var rl unix.Rlimit
	limit := uint64(1048576)
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &rl); err == nil && rl.Max < limit {
		limit = rl.Max
	}
	return specs.POSIXRlimit{Type: "RLIMIT_NOFILE", Hard: limit, Soft: limit}
}

func hasEnv(env []string, key string) bool {
	for _, e := range env {
		if strings.HasPrefix(e, key+"=") {
			return true
		}
	}
	return false
}

// resolveUser turns "user[:group]" into numeric IDs, looking names up in the
// container's /etc/passwd and /etc/group.
func resolveUser(rootfs, user string) (uint32, uint32, error) {
	if user == "" {
		return 0, 0, nil
	}
	u, g, hasGroup := strings.Cut(user, ":")
	uid, primaryGID, err := lookup(filepath.Join(rootfs, "etc/passwd"), u, true)
	if err != nil {
		return 0, 0, err
	}
	gid := primaryGID
	if hasGroup {
		if gid, _, err = lookup(filepath.Join(rootfs, "etc/group"), g, false); err != nil {
			return 0, 0, err
		}
	}
	return uid, gid, nil
}

// lookup resolves a name or number in a passwd/group file. For passwd it
// also returns the primary GID.
func lookup(file, name string, passwd bool) (uint32, uint32, error) {
	if n, err := strconv.ParseUint(name, 10, 32); err == nil {
		id := uint32(n)
		if !passwd {
			return id, 0, nil
		}
		// Numeric UID: use its passwd GID when present, else the same number.
		gid := id
		if f, err := os.Open(file); err == nil {
			defer f.Close()
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				p := strings.Split(sc.Text(), ":")
				if len(p) >= 4 && p[2] == name {
					if v, err := strconv.ParseUint(p[3], 10, 32); err == nil {
						gid = uint32(v)
					}
				}
			}
		}
		return id, gid, nil
	}
	f, err := os.Open(file)
	if err != nil {
		return 0, 0, fmt.Errorf("resolve %q: %w", name, err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.Split(sc.Text(), ":")
		if len(p) < 3 || p[0] != name {
			continue
		}
		id, err := strconv.ParseUint(p[2], 10, 32)
		if err != nil {
			return 0, 0, fmt.Errorf("bad entry for %q in %s", name, file)
		}
		var gid uint64
		if passwd && len(p) >= 4 {
			gid, _ = strconv.ParseUint(p[3], 10, 32)
		}
		return uint32(id), uint32(gid), nil
	}
	return 0, 0, fmt.Errorf("%q not found in %s", name, file)
}
