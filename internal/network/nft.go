package network

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
)

// All legacy-datapath rules live in one table and are tagged with a comment,
// so they can be found and deleted by owner without touching anything else.
const nftTable = "netker"

const nftBase = `
add table ip netker
add chain ip netker postrouting { type nat hook postrouting priority srcnat; policy accept; }
add chain ip netker prerouting { type nat hook prerouting priority dstnat; policy accept; }
add chain ip netker output { type nat hook output priority dstnat; policy accept; }
add chain ip netker forward { type filter hook forward priority filter; policy accept; }
`

// nftBase6 is the IPv6 counterpart, used by networks with an IPv6 subnet.
const nftBase6 = `
add table ip6 netker
add chain ip6 netker postrouting { type nat hook postrouting priority srcnat; policy accept; }
add chain ip6 netker forward { type filter hook forward priority filter; policy accept; }
`

var nftFamilies = []string{"ip", "ip6"}

func netComment(name string) string { return "netker:net:" + name }
func ctrComment(id string) string   { return "netker:ctr:" + id }

func nft(script string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

type nftRule struct {
	Family  string
	Chain   string
	Handle  int
	Comment string
}

// listRules lists the rules in netker's table of one family (ip or ip6).
func listRules(family string) ([]nftRule, error) {
	out, err := exec.Command("nft", "-j", "list", "table", family, nftTable).Output()
	if err != nil {
		// The table doesn't exist yet.
		return nil, nil
	}
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, fmt.Errorf("parse nft output: %w", err)
	}
	var rules []nftRule
	for _, obj := range doc.Nftables {
		raw, ok := obj["rule"]
		if !ok {
			continue
		}
		var r struct {
			Chain   string `json:"chain"`
			Handle  int    `json:"handle"`
			Comment string `json:"comment"`
		}
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, err
		}
		rules = append(rules, nftRule{Family: family, Chain: r.Chain, Handle: r.Handle, Comment: r.Comment})
	}
	return rules, nil
}

func deleteRulesWithComment(comment string) error {
	var b strings.Builder
	for _, family := range nftFamilies {
		rules, err := listRules(family)
		if err != nil {
			return err
		}
		for _, r := range rules {
			if r.Comment == comment {
				fmt.Fprintf(&b, "delete rule %s %s %s handle %d\n", family, nftTable, r.Chain, r.Handle)
			}
		}
	}
	if b.Len() == 0 {
		return nil
	}
	return nft(b.String())
}

// ensureNetworkRules installs masquerading (or, for internal networks, a
// forward drop) and the --icc=false rule for n once, for IPv4 and, if the
// network has it, IPv6.
func ensureNetworkRules(n *Network) error {
	if err := ensureFamilyRules(n, "ip", nftBase, n.Subnet); err != nil {
		return err
	}
	if n.HasIPv6() {
		return ensureFamilyRules(n, "ip6", nftBase6, n.Subnet6)
	}
	return nil
}

func ensureFamilyRules(n *Network, family, base string, subnet netip.Prefix) error {
	rules, err := listRules(family)
	if err != nil {
		return err
	}
	c := netComment(n.Name)
	for _, r := range rules {
		if r.Comment == c {
			return nil
		}
	}
	// In nft the address match keyword is the family name: "ip saddr",
	// "ip6 saddr".
	f := family
	var b strings.Builder
	b.WriteString(base)
	if n.Internal {
		fmt.Fprintf(&b, "add rule %s netker forward %s saddr %s %s daddr != %s drop comment %q\n", f, f, subnet, f, subnet, c)
		fmt.Fprintf(&b, "add rule %s netker forward %s daddr %s %s saddr != %s drop comment %q\n", f, f, subnet, f, subnet, c)
	} else {
		fmt.Fprintf(&b, "add rule %s netker postrouting %s saddr %s %s daddr != %s masquerade comment %q\n", f, f, subnet, f, subnet, c)
	}
	if n.NoICC {
		// Published ports were DNATed and stay reachable, as in BPF.
		fmt.Fprintf(&b, "add rule %s netker forward %s saddr %s %s daddr %s ct status != dnat drop comment %q\n", f, f, subnet, f, subnet, c)
	}
	return nft(b.String())
}

func removeNetworkRules(name string) error { return deleteRulesWithComment(netComment(name)) }

// nftProbe has one rule of every kind netker installs, per family: a nat
// chain with masquerade, and a forward chain matching conntrack state.
// Minimal kernels can have CONFIG_NF_TABLES without the ip or ip6 family,
// NFT_MASQ or NFT_CT (little-vm-helper's CI kernels, for one).
var nftProbe = map[string]string{
	"ip": `add table ip netker_probe
add chain ip netker_probe p { type nat hook postrouting priority srcnat; policy accept; }
add rule ip netker_probe p ip saddr 192.0.2.0/24 masquerade
add chain ip netker_probe f { type filter hook forward priority filter; policy accept; }
add rule ip netker_probe f ct status dnat accept
`,
	"ip6": `add table ip6 netker_probe
add chain ip6 netker_probe p { type nat hook postrouting priority srcnat; policy accept; }
add rule ip6 netker_probe p ip6 saddr 2001:db8::/64 masquerade
add chain ip6 netker_probe f { type filter hook forward priority filter; policy accept; }
add rule ip6 netker_probe f ct status dnat accept
`,
}

// ErrNftNotChecked means nftables support couldn't be checked: not root,
// and no unprivileged user namespaces either.
var ErrNftNotChecked = errors.New("not checked: needs root or unprivileged user namespaces")

// NftablesUsable reports whether netker's nftables rules for family ("ip"
// or "ip6") can be installed: nft is on PATH and the kernel accepts them.
// It's a dry run (nft -c), checked by the kernel but never applied.
func NftablesUsable(family string) error {
	if _, err := exec.LookPath("nft"); err != nil {
		return fmt.Errorf("nft not installed")
	}
	cmd := exec.Command("nft", "-c", "-f", "-")
	if os.Geteuid() != 0 {
		// "netker system check" without root: the families the kernel
		// supports are the same in a user and network namespace of our own.
		userns := []string{"unshare", "--user", "--map-root-user", "--net"}
		if exec.Command(userns[0], append(userns[1:], "true")...).Run() != nil {
			return ErrNftNotChecked
		}
		cmd = exec.Command(userns[0], append(userns[1:], "nft", "-c", "-f", "-")...)
	}
	cmd.Stdin = strings.NewReader(nftProbe[family])
	if out, err := cmd.CombinedOutput(); err != nil {
		msg := strings.TrimSpace(string(out))
		if i := strings.IndexByte(msg, '\n'); i > 0 {
			msg = msg[:i]
		}
		return fmt.Errorf("the kernel rejects netker's %s rules: %s", family, msg)
	}
	return nil
}

// ensureRules installs n's nftables rules for an endpoint on the given
// datapath. The legacy datapath needs them. The eBPF datapath isolates and
// masquerades in BPF, and its rules only masquerade what BPF hands to the
// host stack (fragments, other protocols, IPv6 extension headers): without
// nftables it warns once and carries on.
func (s *Store) ensureRules(n *Network, mode string) error {
	if mode == DatapathEBPF {
		families := []string{"ip"}
		if n.HasIPv6() {
			families = append(families, "ip6")
		}
		for _, f := range families {
			if err := NftablesUsable(f); err != nil {
				if !s.warnedNoNft {
					fmt.Fprintf(os.Stderr, "warning: nftables unusable (%v): traffic the eBPF datapath hands to the host stack, such as fragments, isn't masqueraded\n", err)
					s.warnedNoNft = true
				}
				return nil
			}
		}
	}
	return ensureNetworkRules(n)
}

// PortMapping publishes a container port on the host (docker -p).
type PortMapping struct {
	HostIP        string `json:"host_ip,omitempty"`
	HostPort      uint16 `json:"host_port"`
	ContainerPort uint16 `json:"container_port"`
	Protocol      string `json:"protocol"` // tcp or udp
}

func (p PortMapping) String() string {
	ip := p.HostIP
	if ip == "" {
		ip = "0.0.0.0"
	} else if strings.Contains(ip, ":") {
		ip = "[" + ip + "]"
	}
	return fmt.Sprintf("%s:%d->%d/%s", ip, p.HostPort, p.ContainerPort, p.Protocol)
}

// PublishPorts DNATs traffic addressed to the host's own addresses to the
// container, both for traffic arriving from outside (prerouting) and
// traffic generated on the host (output). Connections to 127.0.0.1 are not
// handled by the legacy datapath.
func PublishPorts(containerID string, ip string, ports []PortMapping) error {
	if len(ports) == 0 {
		return nil
	}
	c := ctrComment(containerID)
	var b strings.Builder
	b.WriteString(nftBase)
	for _, p := range ports {
		match := "fib daddr type local"
		if p.HostIP != "" {
			match = "ip daddr " + p.HostIP
		}
		for _, chain := range []string{"prerouting", "output"} {
			fmt.Fprintf(&b, "add rule ip netker %s %s %s dport %d dnat to %s:%d comment %q\n",
				chain, match, p.Protocol, p.HostPort, ip, p.ContainerPort, c)
		}
	}
	return nft(b.String())
}

func UnpublishPorts(containerID string) error { return deleteRulesWithComment(ctrComment(containerID)) }
