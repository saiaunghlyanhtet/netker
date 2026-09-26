package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/saiaunghlyanhtet/netker/internal/container"
)

func stopCmd() *cobra.Command {
	var timeout int
	cmd := &cobra.Command{
		Use:   "stop [OPTIONS] CONTAINER...",
		Short: "Stop one or more running containers",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return forEach(cmd, args, func(m *container.Manager, c *container.Container) error {
				return m.Stop(c, time.Duration(timeout)*time.Second)
			})
		},
	}
	cmd.Flags().IntVarP(&timeout, "time", "t", 10, "Seconds to wait before killing the container")
	return cmd
}

func killCmd() *cobra.Command {
	var signal string
	cmd := &cobra.Command{
		Use:   "kill [OPTIONS] CONTAINER...",
		Short: "Kill one or more running containers",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return forEach(cmd, args, func(m *container.Manager, c *container.Container) error {
				return m.Kill(c, strings.TrimPrefix(signal, "SIG"))
			})
		},
	}
	cmd.Flags().StringVarP(&signal, "signal", "s", "KILL", "Signal to send")
	return cmd
}

func restartCmd() *cobra.Command {
	var timeout int
	cmd := &cobra.Command{
		Use:   "restart [OPTIONS] CONTAINER...",
		Short: "Restart one or more containers",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return forEach(cmd, args, func(m *container.Manager, c *container.Container) error {
				if err := m.Stop(c, time.Duration(timeout)*time.Second); err != nil {
					return err
				}
				return m.Start(c)
			})
		},
	}
	cmd.Flags().IntVarP(&timeout, "time", "t", 10, "Seconds to wait before killing the container")
	return cmd
}

func rmCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "rm [OPTIONS] CONTAINER...",
		Short: "Remove one or more containers",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return forEach(cmd, args, func(m *container.Manager, c *container.Container) error {
				return m.Remove(c, force)
			})
		},
	}
	cmd.Flags().BoolVarP(&force, "force", "f", false, "Kill and remove a running container")
	return cmd
}

func psCmd() *cobra.Command {
	var all, quiet bool
	var format string
	cmd := &cobra.Command{
		Use:     "ps [OPTIONS]",
		Aliases: []string{"ls"},
		Short:   "List containers",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			m := manager()
			cs, err := m.List()
			if err != nil {
				return err
			}
			type row struct {
				*container.Container
				Status string `json:"status"`
			}
			var rows []row
			for _, c := range cs {
				st := m.Status(c)
				if !all && st != "running" {
					continue
				}
				rows = append(rows, row{c, st})
			}
			out := cmd.OutOrStdout()
			switch {
			case quiet:
				for _, r := range rows {
					fmt.Fprintln(out, shortID(r.ID))
				}
				return nil
			case format == "json":
				return printJSON(cmd, rows)
			case format != "" && format != "table":
				return fmt.Errorf("unknown format %q (want table or json)", format)
			}
			tw := tabwriter.NewWriter(out, 0, 4, 3, ' ', 0)
			fmt.Fprintln(tw, "CONTAINER ID\tIMAGE\tCOMMAND\tCREATED\tSTATUS\tIP\tPORTS\tNAMES")
			for _, r := range rows {
				var ips, ports []string
				for _, ep := range r.Endpoints {
					ips = append(ips, ep.IP.String())
				}
				for _, p := range r.Ports {
					ports = append(ports, p.String())
				}
				if len(ips) == 0 {
					ips = []string{r.Network}
				}
				fmt.Fprintf(tw, "%s\t%s\t%q\t%s\t%s\t%s\t%s\t%s\n",
					shortID(r.ID), shortImage(r.Image), truncate(strings.Join(r.Args, " "), 20),
					ago(r.Created), r.Status, strings.Join(ips, ","), strings.Join(ports, ", "), r.Name)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().BoolVarP(&all, "all", "a", false, "Show all containers (default shows just running)")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Only display container IDs")
	cmd.Flags().StringVar(&format, "format", "", "Output format: table or json")
	return cmd
}

func shortImage(ref string) string {
	ref = strings.TrimPrefix(ref, "index.docker.io/")
	return strings.TrimPrefix(ref, "library/")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func ago(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d seconds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d minutes ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hours ago", int(d.Hours()))
	}
	return fmt.Sprintf("%d days ago", int(d.Hours()/24))
}

func logsCmd() *cobra.Command {
	var follow bool
	cmd := &cobra.Command{
		Use:   "logs [OPTIONS] CONTAINER",
		Short: "Fetch the logs of a container",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			m := manager()
			c, err := m.Get(args[0])
			if err != nil {
				return err
			}
			f, err := os.Open(m.LogPath(c.ID))
			if os.IsNotExist(err) {
				return nil
			}
			if err != nil {
				return err
			}
			defer f.Close()
			out := cmd.OutOrStdout()
			if _, err := io.Copy(out, f); err != nil {
				return err
			}
			for follow && m.Status(c) == "running" {
				time.Sleep(200 * time.Millisecond)
				if _, err := io.Copy(out, f); err != nil {
					return err
				}
			}
			_, err = io.Copy(out, f)
			return err
		},
	}
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "Follow log output")
	return cmd
}

func inspectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "inspect CONTAINER...",
		Short: "Show low-level information about containers",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			m := manager()
			type view struct {
				*container.Container
				Status string `json:"status"`
				Bundle string `json:"bundle"`
				Log    string `json:"log_path"`
			}
			var out []view
			for _, ref := range args {
				c, err := m.Get(ref)
				if err != nil {
					return err
				}
				out = append(out, view{c, m.Status(c), m.Paths.Container(c.ID) + "/bundle", m.LogPath(c.ID)})
			}
			return printJSON(cmd, out)
		},
	}
}

func portCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "port CONTAINER",
		Short: "List port mappings of a container",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := manager().Get(args[0])
			if err != nil {
				return err
			}
			for _, p := range c.Ports {
				ip := p.HostIP
				if ip == "" {
					ip = "0.0.0.0"
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%d/%s -> %s:%d\n", p.ContainerPort, p.Protocol, ip, p.HostPort)
			}
			return nil
		},
	}
}
