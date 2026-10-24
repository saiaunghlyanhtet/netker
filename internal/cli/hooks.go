package cli

import (
	"fmt"
	"text/tabwriter"

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
	cmd.AddCommand(hookAddCmd(), hookLsCmd(), hookRmCmd())
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

func hookLsCmd() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "ls [CONTAINER...]",
		Short: "List hooks, per interface, with their state in the kernel",
		RunE: func(cmd *cobra.Command, args []string) error {
			m := manager()
			defer m.Networks.Datapath().Close()
			var cs []*container.Container
			if len(args) == 0 {
				all, err := m.List()
				if err != nil {
					return err
				}
				cs = all
			}
			for _, ref := range args {
				c, err := m.Get(ref)
				if err != nil {
					return err
				}
				cs = append(cs, c)
			}
			var rows []container.HookState
			for _, c := range cs {
				hs, err := m.Hooks(c)
				if err != nil {
					return err
				}
				rows = append(rows, hs...)
			}
			if format == "json" {
				return printJSON(cmd, rows)
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 3, ' ', 0)
			fmt.Fprintln(tw, "CONTAINER\tHOOK\tDIRECTION\tPOSITION\tIFACE\tPROGRAM\tPROGRAM ID\tSTATE")
			for _, r := range rows {
				pos := "before netker"
				if r.After {
					pos = "after netker"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\n",
					r.Container, r.Name, r.Direction, pos, r.IfName, r.Program, r.ProgramID, r.State)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&format, "format", "", "Output format: table or json")
	return cmd
}

func hookRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm CONTAINER HOOK...",
		Short: "Detach hooks from a container",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			m := manager()
			defer m.Networks.Datapath().Close()
			c, err := m.Get(args[0])
			if err != nil {
				return err
			}
			for _, name := range args[1:] {
				if err := m.RemoveHook(c, name); err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), name)
			}
			return nil
		},
	}
}
