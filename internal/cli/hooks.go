package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/saiaunghlyanhtet/netker/internal/container"
	"github.com/saiaunghlyanhtet/netker/internal/datapath"
)

func hookCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "hook",
		Short: "Run your own BPF programs on containers' netkit devices",
		Long: `A hook is a tc (SCHED_CLS) BPF program attached next to netker's own on a
container's netkit device: on egress it sees what the container sends, on
ingress what's delivered to it. It runs before netker's program unless
--after is given. See bpf/include/netker_hook.h for the verdicts: before
netker, return NETKIT_NEXT to continue or NETKIT_DROP; NETKIT_PASS would
skip netker's anti-spoofing, isolation and NAT.`,
	}
	cmd.AddCommand(hookAddCmd())
	return cmd
}

func hookAddCmd() *cobra.Command {
	var o container.HookOptions
	cmd := &cobra.Command{
		Use:   "add [OPTIONS] CONTAINER egress|ingress OBJECT",
		Short: "Attach a BPF program to a container's interfaces",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			if args[1] != datapath.HookEgress && args[1] != datapath.HookIngress {
				return fmt.Errorf("direction must be egress or ingress, not %q", args[1])
			}
			o.Direction, o.Object = args[1], args[2]
			m := manager()
			c, err := m.Get(args[0])
			if err != nil {
				return err
			}
			if err := m.AddHook(c, o); err != nil {
				return err
			}
			name := o.Name
			if name == "" {
				c, _ = m.Get(c.ID)
				name = c.Hooks[len(c.Hooks)-1].Name
			}
			fmt.Fprintln(cmd.OutOrStdout(), name)
			return nil
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&o.Name, "name", "", "Hook name (default: the object file's name)")
	fl.StringVar(&o.Program, "program", "", "Program or section to use when the object has several")
	fl.BoolVar(&o.After, "after", false, "Run after netker's program instead of before it")
	return cmd
}
