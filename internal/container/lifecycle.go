package container

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/saiaunghlyanhtet/netker/internal/idutil"
	"github.com/saiaunghlyanhtet/netker/internal/image"
	"github.com/saiaunghlyanhtet/netker/internal/netns"
	"github.com/saiaunghlyanhtet/netker/internal/network"
	"github.com/saiaunghlyanhtet/netker/internal/oci"
)

type CreateOptions struct {
	Image      string
	Name       string
	Cmd        []string // overrides the image's Cmd
	Entrypoint *string  // overrides the image's Entrypoint ("" clears it)
	Env        []string
	Workdir    string
	User       string
	Tty        bool
	Hostname   string
	Network    string // network name, "host" or "none"; default "netker"
	IP         netip.Addr
	Ports      []network.PortMapping
	AutoRemove bool
	Pull       io.Writer // progress output if the image has to be pulled
}

// Create sets up everything for a container without starting it.
func (m *Manager) Create(o CreateOptions) (c *Container, err error) {
	img, err := m.Images.Get(o.Image)
	if errors.Is(err, image.ErrNotFound) {
		img, err = m.Images.Pull(o.Image, o.Pull)
	}
	if err != nil {
		return nil, err
	}
	args, err := commandLine(img, o)
	if err != nil {
		return nil, err
	}

	unlock, err := m.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()

	name := o.Name
	if name == "" {
		name, err = m.freeName()
		if err != nil {
			return nil, err
		}
	} else {
		if err := idutil.ValidateName(name); err != nil {
			return nil, err
		}
		if _, err := m.Get(name); err == nil {
			return nil, fmt.Errorf("the container name %q is already in use", name)
		}
	}

	id := idutil.NewID()
	c = &Container{
		ID:          id,
		Name:        name,
		Image:       img.Ref,
		ImageDigest: img.Digest,
		Created:     time.Now().UTC(),
		Args:        args,
		Env:         mergeEnv(img.Config.Env, o.Env),
		Cwd:         firstNonEmpty(o.Workdir, img.Config.WorkingDir),
		User:        firstNonEmpty(o.User, img.Config.User),
		Tty:         o.Tty,
		Hostname:    firstNonEmpty(o.Hostname, idutil.Short(id)),
		Network:     firstNonEmpty(o.Network, network.DefaultName),
		Ports:       o.Ports,
		AutoRemove:  o.AutoRemove,
	}
	if len(c.Ports) > 0 && (c.Network == network.ModeHost || c.Network == network.ModeNone) {
		return nil, fmt.Errorf("port publishing needs a netker network, not --network %s", c.Network)
	}
	defer func() {
		if err != nil {
			m.teardown(c)
		}
	}()

	for _, d := range []string{filepath.Join(m.dir(id), "upper"), filepath.Join(m.dir(id), "work"), m.rootfs(id)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return c, err
		}
	}
	if err := m.save(c); err != nil {
		return c, err
	}
	if err := m.mountRootfs(c); err != nil {
		return c, err
	}
	if err := m.setupNetwork(c, o.IP); err != nil {
		return c, err
	}
	if err := m.writeEtcFiles(c); err != nil {
		return c, err
	}
	if err := m.writeSpec(c, img); err != nil {
		return c, err
	}
	return c, m.save(c)
}

func commandLine(img *image.Image, o CreateOptions) ([]string, error) {
	entry := img.Config.Entrypoint
	cmd := img.Config.Cmd
	if o.Entrypoint != nil {
		entry = nil
		if *o.Entrypoint != "" {
			entry = []string{*o.Entrypoint}
		}
		// Like Docker: overriding the entrypoint drops the image's Cmd.
		cmd = nil
	}
	if len(o.Cmd) > 0 {
		cmd = o.Cmd
	}
	args := append(append([]string{}, entry...), cmd...)
	if len(args) == 0 {
		return nil, fmt.Errorf("no command specified and image %s has none", img.Ref)
	}
	return args, nil
}

func mergeEnv(base, override []string) []string {
	out := append([]string{}, base...)
	for _, e := range override {
		k, _, _ := strings.Cut(e, "=")
		replaced := false
		for i, b := range out {
			if bk, _, _ := strings.Cut(b, "="); bk == k {
				out[i] = e
				replaced = true
			}
		}
		if !replaced {
			out = append(out, e)
		}
	}
	return out
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (m *Manager) freeName() (string, error) {
	for i := 0; i < 100; i++ {
		n := idutil.RandomName()
		if _, err := m.Get(n); err != nil {
			return n, nil
		}
	}
	return "", fmt.Errorf("could not find a free container name")
}

func (m *Manager) mountRootfs(c *Container) error {
	img, err := m.Images.Get(c.ImageDigest[len("sha256:"):])
	if err != nil {
		return err
	}
	target := m.rootfs(c.ID)
	if mounted(target) {
		return nil
	}
	opts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s",
		img.Rootfs, filepath.Join(m.dir(c.ID), "upper"), filepath.Join(m.dir(c.ID), "work"))
	err = unix.Mount("overlay", target, "overlay", 0, opts)
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EPERM) {
		// Inside a user namespace overlayfs needs user.* xattrs.
		err = unix.Mount("overlay", target, "overlay", 0, opts+",userxattr")
	}
	if err != nil {
		return fmt.Errorf("mount overlay rootfs: %w", err)
	}
	return nil
}

// mounted reports whether path is a mount point.
func mounted(path string) bool {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) > 4 && fields[4] == path {
			return true
		}
	}
	return false
}

func (m *Manager) setupNetwork(c *Container, ip netip.Addr) error {
	if c.Network == network.ModeHost {
		return nil
	}
	c.NetNSPath = filepath.Join(m.Paths.NetNS(), c.ID)
	if err := netns.Create(c.NetNSPath); err != nil {
		return err
	}
	if c.Network == network.ModeNone {
		return netns.Do(c.NetNSPath, netns.LoopbackUp)
	}
	n, err := m.Networks.Get(c.Network)
	if err != nil {
		return err
	}
	ep, err := m.Networks.Attach(n, c.ID, c.NetNSPath, 0, ip)
	if err != nil {
		return err
	}
	c.Endpoints = append(c.Endpoints, ep)
	if err := m.save(c); err != nil {
		return err
	}
	return network.PublishPorts(c.ID, ep.IP.String(), c.Ports)
}

func (m *Manager) writeEtcFiles(c *Container) error {
	dir := m.dir(c.ID)
	var hosts strings.Builder
	hosts.WriteString("127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n")
	for _, ep := range c.Endpoints {
		fmt.Fprintf(&hosts, "%s\t%s %s\n", ep.IP, c.Hostname, c.Name)
	}
	if err := os.WriteFile(filepath.Join(dir, "hosts"), []byte(hosts.String()), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "hostname"), []byte(c.Hostname+"\n"), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "resolv.conf"), resolvConf(c.Network == network.ModeHost), 0o644)
}

// resolvConf returns the host's resolver config, avoiding loopback resolvers
// (e.g. systemd-resolved's 127.0.0.53) that aren't reachable from a
// container's own network namespace.
func resolvConf(hostNetwork bool) []byte {
	candidates := []string{"/etc/resolv.conf"}
	if !hostNetwork {
		candidates = append(candidates, "/run/systemd/resolve/resolv.conf")
	}
	for _, p := range candidates {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if hostNetwork || !onlyLoopbackNameservers(string(data)) {
			return data
		}
	}
	return []byte("nameserver 8.8.8.8\nnameserver 1.1.1.1\n")
}

func onlyLoopbackNameservers(conf string) bool {
	found := false
	for _, line := range strings.Split(conf, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != "nameserver" {
			continue
		}
		found = true
		if a, err := netip.ParseAddr(f[1]); err == nil && !a.IsLoopback() {
			return false
		}
	}
	return found
}

func (m *Manager) writeSpec(c *Container, img *image.Image) error {
	dir := m.dir(c.ID)
	s, err := oci.Spec(oci.SpecOptions{
		Args:         c.Args,
		Env:          c.Env,
		Cwd:          c.Cwd,
		User:         c.User,
		Tty:          c.Tty,
		Hostname:     c.Hostname,
		NetNSPath:    c.NetNSPath,
		HostNetwork:  c.Network == network.ModeHost,
		HostsFile:    filepath.Join(dir, "hosts"),
		HostnameFile: filepath.Join(dir, "hostname"),
		ResolvConf:   filepath.Join(dir, "resolv.conf"),
		Rootfs:       img.Rootfs,
	})
	if err != nil {
		return err
	}
	return oci.WriteSpec(m.bundle(c.ID), s)
}

// Start runs a created or exited container in the background.
func (m *Manager) Start(c *Container) error {
	if err := m.prepareStart(c); err != nil {
		return err
	}
	log, err := os.OpenFile(m.LogPath(c.ID), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer log.Close()
	return m.rt.RunDetached(c.ID, m.bundle(c.ID), log)
}

// Run runs the container attached to the given stdio and returns its exit
// code. Output is not written to the container log.
func (m *Manager) Run(c *Container, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	if err := m.prepareStart(c); err != nil {
		return -1, err
	}
	return m.rt.RunForeground(c.ID, m.bundle(c.ID), stdin, stdout, stderr)
}

func (m *Manager) prepareStart(c *Container) error {
	switch m.Status(c) {
	case "running":
		return fmt.Errorf("container %s is already running", c.Name)
	case "exited":
		// The OCI runtime can't restart a stopped container; drop its state.
		if err := m.rt.Delete(c.ID, false); err != nil && !errors.Is(err, oci.ErrNotExist) {
			return err
		}
	}
	return m.mountRootfs(c)
}

// Stop sends SIGTERM, then SIGKILL after timeout.
func (m *Manager) Stop(c *Container, timeout time.Duration) error {
	if m.Status(c) != "running" {
		return nil
	}
	if err := m.rt.Kill(c.ID, "TERM"); err != nil && !errors.Is(err, oci.ErrNotExist) {
		return err
	}
	if m.waitStopped(c, timeout) {
		return nil
	}
	if err := m.rt.Kill(c.ID, "KILL"); err != nil && !errors.Is(err, oci.ErrNotExist) {
		return err
	}
	if !m.waitStopped(c, 5*time.Second) {
		return fmt.Errorf("container %s did not stop", c.Name)
	}
	return nil
}

func (m *Manager) Kill(c *Container, signal string) error {
	if m.Status(c) != "running" {
		return fmt.Errorf("container %s is not running", c.Name)
	}
	return m.rt.Kill(c.ID, signal)
}

func (m *Manager) waitStopped(c *Container, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if m.Status(c) != "running" {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

func (m *Manager) Exec(c *Container, tty bool, env []string, cwd string, args []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	if m.Status(c) != "running" {
		return -1, fmt.Errorf("container %s is not running", c.Name)
	}
	// Always pass the whole environment: crun 1.14 (Ubuntu 24.04) replaces
	// the process environment with --env values instead of adding them.
	full := mergeEnv(oci.ProcessEnv(c.Env, c.Hostname, tty), env)
	return m.rt.Exec(c.ID, tty, full, cwd, args, stdin, stdout, stderr)
}

// Remove deletes a container. A running container needs force.
func (m *Manager) Remove(c *Container, force bool) error {
	if m.Status(c) == "running" && !force {
		return fmt.Errorf("container %s is running: stop it first or use --force", c.Name)
	}
	unlock, err := m.lock()
	if err != nil {
		return err
	}
	defer unlock()
	return m.teardown(c)
}

// teardown releases everything a container holds. It tolerates partially
// created containers and resources that are already gone.
func (m *Manager) teardown(c *Container) error {
	var errs []error
	if err := m.rt.Delete(c.ID, true); err != nil && !errors.Is(err, oci.ErrNotExist) {
		errs = append(errs, err)
	}
	if len(c.Ports) > 0 {
		if err := network.UnpublishPorts(c.ID); err != nil {
			errs = append(errs, err)
		}
	}
	for _, ep := range c.Endpoints {
		if err := m.Networks.Detach(ep, c.ID); err != nil {
			errs = append(errs, err)
		}
	}
	if c.NetNSPath != "" {
		if err := netns.Delete(c.NetNSPath); err != nil {
			errs = append(errs, err)
		}
	}
	if err := unix.Unmount(m.rootfs(c.ID), unix.MNT_DETACH); err != nil && !errors.Is(err, unix.EINVAL) && !errors.Is(err, unix.ENOENT) {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		// Keep the record so the user can retry.
		return errors.Join(errs...)
	}
	return removeAll(m.dir(c.ID))
}

// removeAll is os.RemoveAll that also handles read-only directories left
// in the overlay upper dir.
func removeAll(dir string) error {
	filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && info.IsDir() && info.Mode()&0o200 == 0 {
			os.Chmod(p, info.Mode().Perm()|0o700)
		}
		return nil
	})
	return os.RemoveAll(dir)
}
