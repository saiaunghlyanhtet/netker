package network

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
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
