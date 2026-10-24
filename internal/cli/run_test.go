package cli

import (
	"testing"

	"github.com/saiaunghlyanhtet/netker/internal/container"
	"github.com/saiaunghlyanhtet/netker/internal/network"
)

func TestParsePort(t *testing.T) {
	ok := map[string]network.PortMapping{
		"8080:80":             {HostPort: 8080, ContainerPort: 80, Protocol: "tcp"},
		"8080:80/udp":         {HostPort: 8080, ContainerPort: 80, Protocol: "udp"},
		"127.0.0.1:8080:80":   {HostIP: "127.0.0.1", HostPort: 8080, ContainerPort: 80, Protocol: "tcp"},
		"[::1]:8080:80":       {HostIP: "::1", HostPort: 8080, ContainerPort: 80, Protocol: "tcp"},
		"[fd00::5]:53:53/udp": {HostIP: "fd00::5", HostPort: 53, ContainerPort: 53, Protocol: "udp"},
		"[::]:8080:80":        {HostIP: "::", HostPort: 8080, ContainerPort: 80, Protocol: "tcp"},
	}
	for in, want := range ok {
		got, err := parsePort(in)
		if err != nil || got != want {
			t.Errorf("parsePort(%q) = %+v, %v; want %+v", in, got, err, want)
		}
	}
	for _, in := range []string{"80", "::1:8080:80", "[::1]8080:80", "[10.0.0.1]:8080:80", "[::1]:1:8080:80", "8080:80/sctp", "0:80", "x:80"} {
		if _, err := parsePort(in); err == nil {
			t.Errorf("parsePort(%q) accepted", in)
		}
	}
}

func TestParseHook(t *testing.T) {
	ok := map[string]container.HookOptions{
		"egress=./x.o":              {Direction: "egress", Object: "./x.o"},
		"ingress:after=/p/y.o":      {Direction: "ingress", After: true, Object: "/p/y.o"},
		"egress:before=z.o#my_prog": {Direction: "egress", Object: "z.o", Program: "my_prog"},
	}
	for in, want := range ok {
		got, err := parseHook(in)
		if err != nil || got != want {
			t.Errorf("parseHook(%q) = %+v, %v; want %+v", in, got, err, want)
		}
	}
	for _, in := range []string{"egress", "up=x.o", "egress:middle=x.o", "egress="} {
		if _, err := parseHook(in); err == nil {
			t.Errorf("parseHook(%q) accepted", in)
		}
	}
}
