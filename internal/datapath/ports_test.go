package datapath

import (
	"net/netip"
	"testing"
)

func TestPortKeysFamilies(t *testing.T) {
	cases := []struct {
		host        string
		hasIPv6     bool
		want4       bool
		want6       bool
		wantErr     bool
		wantAddr6   string
		description string
	}{
		{"", false, true, false, false, "", "no host IP, IPv4-only container"},
		{"", true, true, true, false, "::", "no host IP, dual-stack container: both, like Docker"},
		{"0.0.0.0", true, true, false, false, "", "0.0.0.0 picks IPv4"},
		{"::", true, false, true, false, "::", "[::] picks IPv6"},
		{"127.0.0.1", true, true, false, false, "", "specific IPv4"},
		{"::1", true, false, true, false, "::1", "specific IPv6"},
		{"::1", false, false, false, true, "", "IPv6 host IP without container IPv6"},
	}
	for _, c := range cases {
		p := Port{HostPort: 8080, ContainerPort: 80, Protocol: "tcp"}
		if c.host != "" {
			p.HostIP = netip.MustParseAddr(c.host)
		}
		k4, k6, err := portKeys(p, c.hasIPv6)
		if (err != nil) != c.wantErr || (k4 != nil) != c.want4 || (k6 != nil) != c.want6 {
			t.Errorf("%s: v4 %v, v6 %v, err %v", c.description, k4 != nil, k6 != nil, err)
			continue
		}
		if k6 != nil && netip.AddrFrom16(k6.Addr).String() != c.wantAddr6 {
			t.Errorf("%s: IPv6 key address %s, want %s", c.description, netip.AddrFrom16(k6.Addr), c.wantAddr6)
		}
	}
}
