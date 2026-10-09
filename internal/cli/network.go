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
	cmd.AddCommand(networkCreateCmd(), networkLsCmd(), networkRmCmd(), networkInspectCmd(),
		networkConnectCmd(), networkDisconnectCmd())
	return cmd
}

func networkCreateCmd() *cobra.Command {
	var subnets, gateways []string
	var mode string
	var internal, icc bool
	var mtu int
	cmd := &cobra.Command{
		Use:   "create [OPTIONS] NETWORK",
		Short: "Create a network",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			n := &network.Network{Name: args[0], Internal: internal, NoICC: !icc, MTU: mtu}
			var err error
			// One --subnet and --gateway per address family, as in Docker.
			for _, sub := range subnets {
				p, err := netip.ParsePrefix(sub)
				if err != nil {
					return fmt.Errorf("--subnet: %w", err)
				}
				dst := &n.Subnet
				if p.Addr().Is6() {
					dst = &n.Subnet6
				}
				if dst.IsValid() {
					return fmt.Errorf("--subnet: at most one IPv4 and one IPv6 subnet")
				}
				*dst = p
			}
			for _, g := range gateways {
				a, err := netip.ParseAddr(g)
				if err != nil {
					return fmt.Errorf("--gateway: %w", err)
				}
				if a.Is6() {
					n.Gateway6 = a
				} else {
					n.Gateway = a
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
	fl.StringArrayVar(&subnets, "subnet", nil, "Subnet in CIDR format: one IPv4 (required) and optionally one IPv6")
	fl.StringArrayVar(&gateways, "gateway", nil, "Gateway per family (default: the first address of each subnet)")
	fl.StringVar(&mode, "netkit-mode", "l3", "netkit device mode: l3 (no ARP) or l2")
	fl.BoolVar(&internal, "internal", false, "Restrict external access to the network")
	fl.BoolVar(&icc, "icc", true, "Allow traffic between containers of the network (--icc=false blocks it)")
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
			fmt.Fprintln(tw, "NAME\tSUBNET\tGATEWAY\tNETKIT MODE\tINTERNAL\tICC")
			for _, n := range nets {
				subnet, gateway := n.Subnet.String(), n.Gateway.String()
				if n.HasIPv6() {
					subnet += "," + n.Subnet6.String()
					gateway += "," + n.Gateway6.String()
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%v\t%v\n", n.Name, subnet, gateway, n.Mode, n.Internal, !n.NoICC)
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
				IP6       string `json:"ip6,omitempty"`
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
							a := attached{Container: c.Name, IfName: ep.IfName, HostIf: ep.HostIf, IP: ep.IP.String()}
							if ep.IP6.IsValid() {
								a.IP6 = ep.IP6.String()
							}
							v.Containers = append(v.Containers, a)
						}
					}
				}
				out = append(out, v)
			}
			return printJSON(cmd, out)
		},
	}
}

func networkConnectCmd() *cobra.Command {
	var ip string
	cmd := &cobra.Command{
		Use:   "connect [OPTIONS] NETWORK CONTAINER",
		Short: "Connect a container to a network",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			var addr netip.Addr
			if ip != "" {
				var err error
				if addr, err = netip.ParseAddr(ip); err != nil {
					return fmt.Errorf("--ip: %w", err)
				}
			}
			m := manager()
			c, err := m.Get(args[1])
			if err != nil {
				return err
			}
			return m.Connect(c, args[0], addr)
		},
	}
	cmd.Flags().StringVar(&ip, "ip", "", "IPv4 address on the network")
	return cmd
}

func networkDisconnectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "disconnect NETWORK CONTAINER",
		Short: "Disconnect a container from a network",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			m := manager()
			c, err := m.Get(args[1])
			if err != nil {
				return err
			}
			return m.Disconnect(c, args[0])
		},
	}
}
