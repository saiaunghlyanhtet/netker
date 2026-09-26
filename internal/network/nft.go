package network

import (
	"bytes"
	"encoding/json"
	"fmt"
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
	Chain   string
	Handle  int
	Comment string
}

func listRules() ([]nftRule, error) {
	out, err := exec.Command("nft", "-j", "list", "table", "ip", nftTable).Output()
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
		rules = append(rules, nftRule{Chain: r.Chain, Handle: r.Handle, Comment: r.Comment})
	}
	return rules, nil
}

func deleteRulesWithComment(comment string) error {
	rules, err := listRules()
	if err != nil {
		return err
	}
	var b strings.Builder
	for _, r := range rules {
		if r.Comment == comment {
			fmt.Fprintf(&b, "delete rule ip %s %s handle %d\n", nftTable, r.Chain, r.Handle)
		}
	}
	if b.Len() == 0 {
		return nil
	}
	return nft(b.String())
}

// ensureNetworkRules installs masquerading (or, for internal networks, a
// forward drop) for n once.
func ensureNetworkRules(n *Network) error {
	rules, err := listRules()
	if err != nil {
		return err
	}
	c := netComment(n.Name)
	for _, r := range rules {
		if r.Comment == c {
			return nil
		}
	}
	var b strings.Builder
	b.WriteString(nftBase)
	if n.Internal {
		fmt.Fprintf(&b, "add rule ip netker forward ip saddr %s ip daddr != %s drop comment %q\n", n.Subnet, n.Subnet, c)
		fmt.Fprintf(&b, "add rule ip netker forward ip daddr %s ip saddr != %s drop comment %q\n", n.Subnet, n.Subnet, c)
	} else {
		fmt.Fprintf(&b, "add rule ip netker postrouting ip saddr %s ip daddr != %s masquerade comment %q\n", n.Subnet, n.Subnet, c)
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
