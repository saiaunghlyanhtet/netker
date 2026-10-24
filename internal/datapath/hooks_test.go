package datapath

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

func TestLoadHookSpec(t *testing.T) {
	const obj = "testdata/drop_tcp_port.o" // go generate: examples/hooks/drop_tcp_port.c
	for _, name := range []string{"", "drop_tcp_port", "tc"} {
		spec, prog, err := LoadHookSpec(obj, name)
		if err != nil {
			t.Fatalf("LoadHookSpec(%q): %v", name, err)
		}
		if prog != "drop_tcp_port" || spec.Programs[prog].Type != ebpf.SchedCLS {
			t.Fatalf("LoadHookSpec(%q) picked %q", name, prog)
		}
	}
	if _, _, err := LoadHookSpec(obj, "nope"); err == nil || !strings.Contains(err.Error(), "no program") {
		t.Fatalf("unknown program: %v", err)
	}
	if _, _, err := LoadHookSpec("testdata/missing.o", ""); err == nil {
		t.Fatal("missing object accepted")
	}
}

func TestHookAttachType(t *testing.T) {
	if typ, side, err := hookAttachType(HookEgress); err != nil || typ != ebpf.AttachNetkitPeer || side != "peer" {
		t.Fatalf("egress: %v %v %v", typ, side, err)
	}
	if typ, side, err := hookAttachType(HookIngress); err != nil || typ != ebpf.AttachNetkitPrimary || side != "primary" {
		t.Fatalf("ingress: %v %v %v", typ, side, err)
	}
	if _, _, err := hookAttachType("sideways"); err == nil {
		t.Fatal("bad direction accepted")
	}
}
