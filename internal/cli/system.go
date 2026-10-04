package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"

	"github.com/saiaunghlyanhtet/netker/internal/config"
	"github.com/saiaunghlyanhtet/netker/internal/datapath"
	"github.com/saiaunghlyanhtet/netker/internal/netkit"
)

func systemCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "system",
		Short: "Manage netker and check the host",
	}
	cmd.AddCommand(checkCmd(), datapathCmd(), gcCmd())
	return cmd
}

type check struct {
	name   string
	ok     bool
	warn   bool // not fatal
	detail string
}

func checkCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "check",
		Short: "Check that the kernel and host tools support netker",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var checks []check
			var uts unix.Utsname
			unix.Uname(&uts)
			checks = append(checks, check{name: "kernel", ok: true, detail: unix.ByteSliceToString(uts.Release[:])})

			f, err := probeNetkit()
			switch {
			case err != nil:
				checks = append(checks, check{name: "netkit devices", detail: err.Error()})
			default:
				checks = append(checks,
					check{name: "netkit L3 mode", ok: f.L3, detail: f.L3Error},
					check{name: "netkit L2 mode", ok: f.L2, detail: f.L2Error},
					check{name: "netkit scrub attributes", ok: f.Scrub, warn: !f.Scrub, detail: "kernel lacks IFLA_NETKIT_SCRUB; marks are not scrubbed per side"},
				)
			}

			var sfs unix.Statfs_t
			cg2 := unix.Statfs("/sys/fs/cgroup", &sfs) == nil && sfs.Type == unix.CGROUP2_SUPER_MAGIC
			checks = append(checks, check{name: "cgroup v2", ok: cg2})
			fsList, _ := os.ReadFile("/proc/filesystems")
			checks = append(checks, check{name: "overlayfs", ok: bytes.Contains(fsList, []byte("\toverlay\n"))})
			bpffs := unix.Statfs("/sys/fs/bpf", &sfs) == nil && sfs.Type == unix.BPF_FS_MAGIC
			checks = append(checks, check{name: "bpffs at /sys/fs/bpf", ok: bpffs, warn: !bpffs, detail: "needed by the eBPF datapath"})
			dp := manager().Networks.Datapath()
			if err := dp.Load(); err != nil {
				checks = append(checks, check{name: "eBPF datapath", warn: true, detail: "not loadable, containers use the legacy datapath: " + err.Error()})
			} else {
				checks = append(checks, check{name: "eBPF datapath", ok: true})
			}
			dp.Close()

			if r, err := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range"); err == nil {
				var lo, hi int
				fmt.Sscan(string(r), &lo, &hi)
				overlap := hi >= datapath.NATPortMin && lo <= datapath.NATPortMax
				checks = append(checks, check{name: "NAT port range", ok: !overlap, warn: overlap,
					detail: fmt.Sprintf("ip_local_port_range %d-%d overlaps the BPF NAT ports %d-%d: host connections may collide with masqueraded ones",
						lo, hi, datapath.NATPortMin, datapath.NATPortMax)})
			}

			for _, bin := range []string{config.Runtime(), "nft"} {
				p, err := exec.LookPath(bin)
				c := check{name: bin, ok: err == nil, detail: p}
				if err != nil {
					c.detail = "not found in PATH"
				}
				checks = append(checks, c)
			}
			root := os.Geteuid() == 0
			checks = append(checks, check{name: "running as root", ok: root, warn: !root, detail: "netker needs root for everything except this check"})
			if out, _ := exec.Command("systemctl", "is-active", "firewalld").Output(); strings.TrimSpace(string(out)) == "active" {
				checks = append(checks, check{name: "firewalld", warn: true, detail: "active: its forward policy may drop container traffic"})
			}

			failed := false
			for _, c := range checks {
				mark := "ok  "
				switch {
				case c.ok:
				case c.warn:
					mark = "warn"
				default:
					mark = "FAIL"
					failed = true
				}
				detail := c.detail
				if c.ok && c.name != "kernel" && c.name != config.Runtime() && c.name != "nft" {
					detail = ""
				}
				fmt.Fprintf(cmd.OutOrStdout(), "[%s] %-26s %s\n", mark, c.name, detail)
			}
			if failed {
				return ExitError{Code: 1}
			}
			return nil
		},
	}
}

// probeNetkit runs netkit.Probe directly as root, or otherwise re-executes
// netker in a new user and network namespace where it has CAP_NET_ADMIN.
func probeNetkit() (netkit.Features, error) {
	if os.Geteuid() == 0 {
		return netkit.Probe()
	}
	self, err := os.Executable()
	if err != nil {
		return netkit.Features{}, err
	}
	c := exec.Command(self, "__probe-netkit")
	c.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}
	var stderr bytes.Buffer
	c.Stderr = &stderr
	out, err := c.Output()
	if err != nil {
		return netkit.Features{}, fmt.Errorf("probe in user namespace: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	var f netkit.Features
	return f, json.Unmarshal(out, &f)
}

func probeCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "__probe-netkit",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			f, err := netkit.Probe()
			if err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(f)
		},
	}
}
