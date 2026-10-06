package cli

import (
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/saiaunghlyanhtet/netker/internal/container"
	"github.com/saiaunghlyanhtet/netker/internal/idutil"
	"github.com/saiaunghlyanhtet/netker/internal/network"
)

type createFlags struct {
	name, ip, entrypoint, workdir, user, hostname string
	env, publish, networks                        []string
	tty, interactive, rm                          bool
}

func (f *createFlags) register(cmd *cobra.Command) {
	fl := cmd.Flags()
	fl.SetInterspersed(false)
	fl.StringVar(&f.name, "name", "", "Assign a name to the container")
	fl.StringArrayVar(&f.networks, "network", nil, `Network to connect to ("host", "none" or a network name; repeat for more, default "`+network.DefaultName+`")`)
	fl.StringVar(&f.ip, "ip", "", "IPv4 address on the first network")
	fl.StringVar(&f.entrypoint, "entrypoint", "", "Overwrite the image's ENTRYPOINT")
	fl.StringVarP(&f.workdir, "workdir", "w", "", "Working directory inside the container")
	fl.StringVarP(&f.user, "user", "u", "", "Username or UID (format: <name|uid>[:<group|gid>])")
	fl.StringVarP(&f.hostname, "hostname", "h", "", "Container hostname")
	fl.StringArrayVarP(&f.env, "env", "e", nil, "Set environment variables")
	fl.StringArrayVarP(&f.publish, "publish", "p", nil, "Publish a port ([ip:]hostPort:containerPort[/proto])")
	fl.BoolVarP(&f.tty, "tty", "t", false, "Allocate a pseudo-TTY")
	fl.BoolVarP(&f.interactive, "interactive", "i", false, "Keep STDIN open")
	fl.BoolVar(&f.rm, "rm", false, "Remove the container when it exits")
	// -h is taken by --hostname, as in docker.
	cmd.Flags().Bool("help", false, "Help for "+cmd.Name())
}

func (f *createFlags) options(cmd *cobra.Command, args []string) (container.CreateOptions, error) {
	o := container.CreateOptions{
		Image:      args[0],
		Name:       f.name,
		Cmd:        args[1:],
		Env:        expandEnv(f.env),
		Workdir:    f.workdir,
		User:       f.user,
		Tty:        f.tty,
		Hostname:   f.hostname,
		Networks:   f.networks,
		AutoRemove: f.rm,
		Pull:       cmd.ErrOrStderr(),
	}
	if cmd.Flags().Changed("entrypoint") {
		o.Entrypoint = &f.entrypoint
	}
	if f.ip != "" {
		a, err := netip.ParseAddr(f.ip)
		if err != nil {
			return o, err
		}
		o.IP = a
	}
	for _, p := range f.publish {
		pm, err := parsePort(p)
		if err != nil {
			return o, err
		}
		o.Ports = append(o.Ports, pm)
	}
	return o, nil
}

// expandEnv turns "-e KEY" into KEY=<value from our environment>, like docker.
func expandEnv(env []string) []string {
	var out []string
	for _, e := range env {
		if strings.Contains(e, "=") {
			out = append(out, e)
		} else if v, ok := os.LookupEnv(e); ok {
			out = append(out, e+"="+v)
		}
	}
	return out
}

func parsePort(s string) (network.PortMapping, error) {
	pm := network.PortMapping{Protocol: "tcp"}
	spec, proto, hasProto := strings.Cut(s, "/")
	if hasProto {
		if proto != "tcp" && proto != "udp" {
			return pm, fmt.Errorf("invalid protocol in %q", s)
		}
		pm.Protocol = proto
	}
	parts := strings.Split(spec, ":")
	switch len(parts) {
	case 2:
	case 3:
		if _, err := netip.ParseAddr(parts[0]); err != nil {
			return pm, fmt.Errorf("invalid host IP in %q", s)
		}
		pm.HostIP = parts[0]
		parts = parts[1:]
	default:
		return pm, fmt.Errorf("invalid port mapping %q: use [ip:]hostPort:containerPort[/proto]", s)
	}
	hp, err1 := strconv.ParseUint(parts[0], 10, 16)
	cp, err2 := strconv.ParseUint(parts[1], 10, 16)
	if err1 != nil || err2 != nil || hp == 0 || cp == 0 {
		return pm, fmt.Errorf("invalid port numbers in %q", s)
	}
	pm.HostPort, pm.ContainerPort = uint16(hp), uint16(cp)
	return pm, nil
}

func runCmd() *cobra.Command {
	var f createFlags
	var detach bool
	cmd := &cobra.Command{
		Use:   "run [OPTIONS] IMAGE [COMMAND] [ARG...]",
		Short: "Create and run a new container",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if detach && f.rm {
				return fmt.Errorf("--rm with --detach is not supported yet")
			}
			o, err := f.options(cmd, args)
			if err != nil {
				return err
			}
			m := manager()
			c, err := m.Create(o)
			if err != nil {
				return err
			}
			if detach {
				if err := m.Start(c); err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), c.ID)
				return nil
			}
			var stdin io.Reader
			if f.interactive {
				stdin = cmd.InOrStdin()
			}
			code, runErr := m.Run(c, stdin, cmd.OutOrStdout(), cmd.ErrOrStderr())
			if f.rm {
				if err := m.Remove(c, true); err != nil {
					fmt.Fprintln(cmd.ErrOrStderr(), "Error removing container:", err)
				}
			}
			if runErr != nil {
				return runErr
			}
			if code != 0 {
				return ExitError{Code: code}
			}
			return nil
		},
	}
	f.register(cmd)
	cmd.Flags().BoolVarP(&detach, "detach", "d", false, "Run in the background and print the container ID")
	return cmd
}

func createCmd() *cobra.Command {
	var f createFlags
	cmd := &cobra.Command{
		Use:   "create [OPTIONS] IMAGE [COMMAND] [ARG...]",
		Short: "Create a new container without starting it",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if f.rm {
				return fmt.Errorf("--rm is only supported with a foreground run")
			}
			o, err := f.options(cmd, args)
			if err != nil {
				return err
			}
			c, err := manager().Create(o)
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), c.ID)
			return nil
		},
	}
	f.register(cmd)
	return cmd
}

func startCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "start CONTAINER...",
		Short: "Start one or more stopped containers",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return forEach(cmd, args, func(m *container.Manager, c *container.Container) error {
				return m.Start(c)
			})
		},
	}
}

func execCmd() *cobra.Command {
	var tty, interactive bool
	var env []string
	var workdir string
	cmd := &cobra.Command{
		Use:   "exec [OPTIONS] CONTAINER COMMAND [ARG...]",
		Short: "Run a command in a running container",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			m := manager()
			c, err := m.Get(args[0])
			if err != nil {
				return err
			}
			var stdin io.Reader
			if interactive {
				stdin = cmd.InOrStdin()
			}
			code, err := m.Exec(c, tty, expandEnv(env), workdir, args[1:], stdin, cmd.OutOrStdout(), cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			if code != 0 {
				return ExitError{Code: code}
			}
			return nil
		},
	}
	fl := cmd.Flags()
	fl.SetInterspersed(false)
	fl.BoolVarP(&tty, "tty", "t", false, "Allocate a pseudo-TTY")
	fl.BoolVarP(&interactive, "interactive", "i", false, "Keep STDIN open")
	fl.StringArrayVarP(&env, "env", "e", nil, "Set environment variables")
	fl.StringVarP(&workdir, "workdir", "w", "", "Working directory inside the container")
	return cmd
}

func shortID(id string) string { return idutil.Short(id) }
