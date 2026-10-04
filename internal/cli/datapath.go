package cli

import (
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/saiaunghlyanhtet/netker/internal/netkit"
)

func datapathCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "datapath",
		Short: "Inspect and upgrade the eBPF datapath",
	}
	cmd.AddCommand(datapathStatusCmd(), datapathUpgradeCmd(), datapathSyncCmd(), datapathResetCmd())
	return cmd
}

func datapathStatusCmd() *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show pinned links, endpoints and per-device counters",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dp := manager().Networks.Datapath()
			defer dp.Close()
			links, err := dp.Links()
			if err != nil {
				return err
			}
			eps, err := dp.Endpoints()
			if err != nil {
				return err
			}
			metrics, err := dp.Metrics()
			if err != nil {
				return err
			}
			hostLinks, err := dp.HostLinks()
			if err != nil {
				return err
			}
			ports, err := dp.Ports()
			if err != nil {
				return err
			}
			natEntries, err := dp.NATEntries()
			if err != nil {
				return err
			}
			if format == "json" {
				return printJSON(cmd, map[string]any{
					"links": links, "host_links": hostLinks, "endpoints": eps,
					"ports": ports, "nat_entries": natEntries, "metrics": metrics,
				})
			}
			out := cmd.OutOrStdout()
			tw := tabwriter.NewWriter(out, 0, 4, 3, ' ', 0)
			fmt.Fprintln(tw, "HOST HOOK\tDEVICE\tPROGRAM ID\tSTATE")
			for _, h := range hostLinks {
				state := "attached"
				if h.Defunct {
					state = "defunct"
				}
				dev := h.Device
				if h.Kind == "connect4" {
					dev = "(root cgroup)"
				}
				fmt.Fprintf(tw, "%s\t%s\t%d\t%s\n", h.Kind, dev, h.ProgramID, state)
			}
			tw.Flush()
			fmt.Fprintln(out)
			tw = tabwriter.NewWriter(out, 0, 4, 3, ' ', 0)
			fmt.Fprintln(tw, "CONTAINER\tSIDE\tIFINDEX\tPROGRAM ID\tSTATE")
			for _, l := range links {
				state := "attached"
				if l.Defunct {
					state = "defunct"
				}
				fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%s\n", shortID(l.Container), l.Side, l.Ifindex, l.ProgramID, state)
			}
			tw.Flush()
			fmt.Fprintln(out)
			tw = tabwriter.NewWriter(out, 0, 4, 3, ' ', 0)
			fmt.Fprintln(tw, "ENDPOINT IP\tPRIMARY IFINDEX\tPEER IFINDEX\tNETID")
			for _, e := range eps {
				fmt.Fprintf(tw, "%s\t%d\t%d\t%08x\n", e.IP, e.Ifindex, e.PeerIfindex, e.NetID)
			}
			tw.Flush()
			fmt.Fprintln(out)
			tw = tabwriter.NewWriter(out, 0, 4, 3, ' ', 0)
			fmt.Fprintln(tw, "PUBLISHED\tCONTAINER")
			for _, p := range ports {
				fmt.Fprintf(tw, "%s:%d/%s\t%s:%d\n", p.HostIP, p.HostPort, p.Protocol, p.ContainerIP, p.ContainerPort)
			}
			tw.Flush()
			fmt.Fprintf(out, "\nNAT entries: %d\n\n", natEntries)
			tw = tabwriter.NewWriter(out, 0, 4, 3, ' ', 0)
			fmt.Fprintln(tw, "IFINDEX\tDIRECTION\tREASON\tPACKETS\tBYTES")
			for _, m := range metrics {
				fmt.Fprintf(tw, "%d\t%s\t%s\t%d\t%d\n", m.Ifindex, m.Direction, m.Reason, m.Packets, m.Bytes)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&format, "format", "", "Output format: table or json")
	return cmd
}

func datapathUpgradeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "upgrade",
		Short: "Atomically replace the programs of every container with this binary's",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dp := manager().Networks.Datapath()
			defer dp.Close()
			n, err := dp.Upgrade()
			fmt.Fprintf(cmd.OutOrStdout(), "updated %d link(s)\n", n)
			return err
		},
	}
}

func gcCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "gc",
		Short: "Remove netkit devices, BPF links and map entries left behind by crashes",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			m := manager()
			cs, err := m.List()
			if err != nil {
				return err
			}
			known := map[string]bool{}
			for _, c := range cs {
				known[c.ID] = true
			}
			owned, err := netkit.Owned()
			if err != nil {
				return err
			}
			devs := 0
			for id, l := range owned {
				if !known[id] {
					if err := netkit.Delete(l.Attrs().Name); err == nil {
						devs++
					}
				}
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "removed %d orphaned netkit device(s)\n", devs)
			dp := m.Networks.Datapath()
			defer dp.Close()
			links, entries, err := dp.GC(func(id string) bool { return known[id] })
			if err != nil {
				fmt.Fprintf(out, "eBPF datapath not available, skipped: %v\n", err)
				return nil
			}
			fmt.Fprintf(out, "removed %d orphaned BPF link(s) and %d endpoint map entr(y/ies)\n", links, entries)
			return nil
		},
	}
}

func datapathSyncCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "sync",
		Short: "Re-read host addresses and attach to new uplinks (e.g. after a network change)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dp := manager().Networks.Datapath()
			defer dp.Close()
			return dp.EnsureHost()
		},
	}
}

func datapathResetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reset-host",
		Short: "Detach the uplink and cgroup hooks (they are re-attached by the next container)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dp := manager().Networks.Datapath()
			defer dp.Close()
			return dp.ResetHost()
		},
	}
}
