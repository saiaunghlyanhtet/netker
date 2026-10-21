package container

import (
	"testing"

	"github.com/saiaunghlyanhtet/netker/internal/network"
)

func TestDroppedTotal(t *testing.T) {
	ebpf := NetStats{Datapath: network.DatapathEBPF, Drops: map[string]uint64{"drop-icc": 3, "drop-spoof": 2}}
	ebpf.TxDropped = 99 // not used on eBPF: the datapath's counters are more precise
	if got := ebpf.DroppedTotal(); got != 5 {
		t.Fatalf("eBPF drops %d, want 5", got)
	}
	legacy := NetStats{Datapath: network.DatapathLegacy}
	legacy.TxDropped = 7
	if got := legacy.DroppedTotal(); got != 7 {
		t.Fatalf("legacy drops %d, want 7", got)
	}
}

func TestCgroupParsing(t *testing.T) {
	if p, err := parseCgroupFile("0::/system.slice/crun-abc.scope\n"); err != nil || p != "/system.slice/crun-abc.scope" {
		t.Fatalf("cgroup path %q, %v", p, err)
	}
	if _, err := parseCgroupFile("12:cpu:/foo\n"); err == nil {
		t.Fatal("cgroup v1 line accepted as v2")
	}
	cpuStat := "usage_usec 123456\nuser_usec 100000\nsystem_usec 23456\n"
	if got := keyValue(cpuStat, "usage_usec"); got != 123456 {
		t.Fatalf("usage_usec %d", got)
	}
	if got := keyValue("anon 10\ninactive_file 4096\n", "inactive_file"); got != 4096 {
		t.Fatalf("inactive_file %d", got)
	}
	r, w := ioBytes("8:0 rbytes=1000 wbytes=200 rios=3 wios=1\n259:0 rbytes=24 wbytes=8 rios=1 wios=1\n")
	if r != 1024 || w != 208 {
		t.Fatalf("io bytes %d/%d", r, w)
	}
	if got := memLimit("536870912\n"); got != 512<<20 {
		t.Fatalf("memory.max %d", got)
	}
	if got := memLimit("max\n"); got == 0 {
		t.Fatal("no host memory as the limit for memory.max=max")
	}
}

func TestCPUPercent(t *testing.T) {
	a, b := &Resources{CPUUsec: 1_000_000}, &Resources{CPUUsec: 1_500_000}
	if got := CPUPercent(a, b, 1_000_000); got != 50 {
		t.Fatalf("half a CPU over a second: %v%%", got)
	}
	if got := CPUPercent(a, &Resources{CPUUsec: 3_000_000}, 1_000_000); got != 200 {
		t.Fatalf("two CPUs: %v%%", got)
	}
	if got := CPUPercent(b, a, 1_000_000); got != 0 {
		t.Fatalf("counter going backwards (restart): %v%%", got)
	}
}
