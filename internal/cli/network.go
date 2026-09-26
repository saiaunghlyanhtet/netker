package cli

import (
	"fmt"
	"net/netip"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/saiaunghlyanhtet/netker/internal/netkit"
	"github.com/saiaunghlyanhtet/netker/internal/network"
)

func networkCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "network",
		Short: "Manage networks",
	}
	cmd.AddCommand(networkCreateCmd(), networkLsCmd(), networkRmCmd(), networkInspectCmd())
	return cmd
}

func networkCreateCmd() *cobra.Command {
	var subnet, gateway, mode string
	var internal bool
	var mtu int
	cmd := &cobra.Command{
		Use:   "create [OPTIONS] NETWORK",
		Short: "Create a network",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			n := &network.Network{Name: args[0], Internal: internal, MTU: mtu}
			var err error
			if n.Subnet, err = netip.ParsePrefix(subnet); err != nil {
				return fmt.Errorf("--subnet: %w", err)
			}
			if gateway != "" {
				if n.Gateway, err = netip.ParseAddr(gateway); err != nil {
					return fmt.Errorf("--gateway: %w", err)
				}
			}
			if n.Mode, err = netkit.ParseMode(mode); err != nil {
				return err
			}
			if err := manager().Networks.Create(n); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), n.Name)
			return nil
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&subnet, "subnet", "", "IPv4 subnet in CIDR format (required)")
	fl.StringVar(&gateway, "gateway", "", "Gateway address (default: first address of the subnet)")
	fl.StringVar(&mode, "netkit-mode", "l3", "netkit device mode: l3 (no ARP) or l2")
	fl.BoolVar(&internal, "internal", false, "Restrict external access to the network")
	fl.IntVar(&mtu, "mtu", 0, "MTU of the netkit devices")
	cmd.MarkFlagRequired("subnet")
	return cmd
}

func networkLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "ls",
		Aliases: []string{"list"},
		Short:   "List networks",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			nets, err := manager().Networks.List()
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 3, ' ', 0)
			fmt.Fprintln(tw, "NAME\tSUBNET\tGATEWAY\tNETKIT MODE\tINTERNAL")
			for _, n := range nets {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%v\n", n.Name, n.Subnet, n.Gateway, n.Mode, n.Internal)
			}
			return tw.Flush()
		},
	}
}

func networkRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm NETWORK...",
		Short: "Remove one or more networks",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			m := manager()
			for _, name := range args {
				if err := m.Networks.Remove(name, m.NetworkInUse(name)); err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), name)
			}
			return nil
		},
	}
}

func networkInspectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "inspect NETWORK...",
		Short: "Show details of one or more networks",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			m := manager()
			type attached struct {
				Container string `json:"container"`
				IfName    string `json:"ifname"`
				HostIf    string `json:"host_if"`
				IP        string `json:"ip"`
			}
			type view struct {
				*network.Network
				Containers []attached `json:"containers"`
			}
			cs, err := m.List()
			if err != nil {
				return err
			}
			var out []view
			for _, name := range args {
				n, err := m.Networks.Get(name)
				if err != nil {
					return err
				}
				v := view{Network: n, Containers: []attached{}}
				for _, c := range cs {
					for _, ep := range c.Endpoints {
						if ep.Network == n.Name {
							v.Containers = append(v.Containers, attached{c.Name, ep.IfName, ep.HostIf, ep.IP.String()})
						}
					}
				}
				out = append(out, v)
			}
			return printJSON(cmd, out)
		},
	}
}
