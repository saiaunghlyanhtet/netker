package container

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const cgroupRoot = "/sys/fs/cgroup"

// Resources is a container's CPU, memory, block I/O and process usage, read
// from its cgroup (v2).
type Resources struct {
	Cgroup string `json:"cgroup"`
	// Shared is set when the container has no cgroup of its own (crun ran
	// with the cgroup manager disabled, as in the unprivileged sandbox);
	// the numbers would describe netker's cgroup, so they're left empty.
	Shared  bool   `json:"shared,omitempty"`
	CPUUsec uint64 `json:"cpu_usec"`
	// Memory and IO are false when those controllers aren't enabled for
	// the container's cgroup; the matching fields are then unknown, not 0.
	Memory   bool   `json:"memory_accounting"`
	MemUsage uint64 `json:"mem_usage"` // memory.current minus reclaimable page cache
	MemLimit uint64 `json:"mem_limit"` // memory.max, or the host's RAM without a limit
	IO       bool   `json:"io_accounting"`
	BlkRead  uint64 `json:"blk_read"`
	BlkWrite uint64 `json:"blk_write"`
	Pids     uint64 `json:"pids"`
}

// Resources reads c's usage. The cgroup is found through the container's
// init process, which works whichever cgroup manager crun used.
func (m *Manager) Resources(c *Container) (*Resources, error) {
	st, err := m.rt.State(c.ID)
	if err != nil {
		return nil, err
	}
	if st.Pid <= 0 {
		return nil, fmt.Errorf("container %s has no process", c.Name)
	}
	cg, err := processCgroup(st.Pid)
	if err != nil {
		return nil, err
	}
	r := &Resources{Cgroup: cg}
	if self, err := processCgroup(os.Getpid()); err == nil && self == cg {
		r.Shared = true
		return r, nil
	}
	dir := filepath.Join(cgroupRoot, cg)
	read := func(name string) (string, bool) {
		b, err := os.ReadFile(filepath.Join(dir, name))
		return string(b), err == nil
	}
	cpuStat, _ := read("cpu.stat")
	r.CPUUsec = keyValue(cpuStat, "usage_usec")
	if cur, ok := read("memory.current"); ok {
		r.Memory = true
		current, _ := strconv.ParseUint(strings.TrimSpace(cur), 10, 64)
		memStat, _ := read("memory.stat")
		if inactive := keyValue(memStat, "inactive_file"); inactive < current {
			// Like Docker: page cache the kernel can drop doesn't count.
			r.MemUsage = current - inactive
		}
		memMax, _ := read("memory.max")
		r.MemLimit = memLimit(memMax)
	}
	if ioStat, ok := read("io.stat"); ok {
		r.IO = true
		r.BlkRead, r.BlkWrite = ioBytes(ioStat)
	}
	pids, _ := read("pids.current")
	r.Pids, _ = strconv.ParseUint(strings.TrimSpace(pids), 10, 64)
	return r, nil
}

// processCgroup returns pid's cgroup v2 path, relative to /sys/fs/cgroup.
func processCgroup(pid int) (string, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}
	return parseCgroupFile(string(b))
}

func parseCgroupFile(s string) (string, error) {
	for _, line := range strings.Split(s, "\n") {
		if p, ok := strings.CutPrefix(line, "0::"); ok {
			return p, nil
		}
	}
	return "", fmt.Errorf("no cgroup v2 entry")
}

// keyValue finds "key value" in a flat-keyed cgroup file such as cpu.stat.
func keyValue(s, key string) uint64 {
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && f[0] == key {
			v, _ := strconv.ParseUint(f[1], 10, 64)
			return v
		}
	}
	return 0
}

// ioBytes sums rbytes and wbytes over the devices in io.stat.
func ioBytes(s string) (read, write uint64) {
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line) // "MAJ:MIN rbytes=... wbytes=... ..."
		if len(f) < 2 {
			continue
		}
		for _, kv := range f[1:] {
			k, v, _ := strings.Cut(kv, "=")
			n, _ := strconv.ParseUint(v, 10, 64)
			switch k {
			case "rbytes":
				read += n
			case "wbytes":
				write += n
			}
		}
	}
	return read, write
}

func memLimit(memoryMax string) uint64 {
	v := strings.TrimSpace(memoryMax)
	if n, err := strconv.ParseUint(v, 10, 64); err == nil {
		return n
	}
	return hostMemory()
}

// hostMemory is MemTotal from /proc/meminfo, in bytes.
func hostMemory() uint64 {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range bytes.Split(b, []byte("\n")) {
		f := strings.Fields(string(line))
		if len(f) >= 2 && f[0] == "MemTotal:" {
			kb, _ := strconv.ParseUint(f[1], 10, 64)
			return kb * 1024
		}
	}
	return 0
}

// CPUPercent is Docker's CPU %: the share of one CPU used between two
// samples taken elapsedUsec apart (it can exceed 100 with several CPUs).
func CPUPercent(before, after *Resources, elapsedUsec uint64) float64 {
	if before == nil || after == nil || elapsedUsec == 0 || after.CPUUsec < before.CPUUsec {
		return 0
	}
	return float64(after.CPUUsec-before.CPUUsec) / float64(elapsedUsec) * 100
}
