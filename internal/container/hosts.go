package container

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/saiaunghlyanhtet/netker/internal/idutil"
)

// hostsFile renders c's /etc/hosts: its own addresses, then every other
// container that shares a network with it, by name and hostname, at the
// address it has on that shared network. Containers on other networks
// aren't listed, like Docker's per-network name resolution.
func hostsFile(c *Container, all []*Container) []byte {
	var b strings.Builder
	b.WriteString("127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n")
	for _, ep := range c.Endpoints {
		fmt.Fprintf(&b, "%s\t%s\n", ep.IP, names(c))
	}
	mine := map[string]bool{}
	for _, ep := range c.Endpoints {
		mine[ep.Network] = true
	}
	peers := slices.Clone(all)
	sort.Slice(peers, func(i, j int) bool { return peers[i].Name < peers[j].Name })
	for _, d := range peers {
		if d.ID == c.ID {
			continue
		}
		for _, ep := range d.Endpoints {
			if mine[ep.Network] {
				fmt.Fprintf(&b, "%s\t%s\n", ep.IP, names(d))
			}
		}
	}
	return []byte(b.String())
}

// names lists the names a container answers to: its name, its hostname
// and its short ID, without repeats.
func names(c *Container) string {
	var out []string
	for _, n := range []string{c.Name, c.Hostname, idutil.Short(c.ID)} {
		if n != "" && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return strings.Join(out, " ")
}

// refreshHosts rewrites /etc/hosts of every container on one of networks,
// plus extra. Callers hold the container lock. The files are bind-mounted
// into the containers and rewritten in place, so running containers see
// the change.
func (m *Manager) refreshHosts(networks []string, extra ...*Container) error {
	all, err := m.List()
	if err != nil {
		return err
	}
	var errs []error
	for _, d := range all {
		affected := slices.ContainsFunc(extra, func(e *Container) bool { return e.ID == d.ID })
		for _, ep := range d.Endpoints {
			affected = affected || slices.Contains(networks, ep.Network)
		}
		if affected {
			errs = append(errs, m.writeHosts(d, all))
		}
	}
	return errors.Join(errs...)
}

func (m *Manager) writeHosts(c *Container, all []*Container) error {
	return os.WriteFile(filepath.Join(m.dir(c.ID), "hosts"), hostsFile(c, all), 0o644)
}
