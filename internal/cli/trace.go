package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/saiaunghlyanhtet/netker/internal/container"
	"github.com/saiaunghlyanhtet/netker/internal/datapath"
	"github.com/saiaunghlyanhtet/netker/internal/network"
)

func netCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "net",
		Short: "Observe the eBPF datapath",
	}
	cmd.AddCommand(traceCmd(), hookCmd())
	return cmd
}

func traceCmd() *cobra.Command {
	var dropsOnly bool
	var ip, format string
	var count int
	cmd := &cobra.Command{
		Use:   "trace [OPTIONS] [CONTAINER...]",
		Short: "Show datapath verdicts as packets go through (drops only with --drops)",
		Long: `Show what the eBPF datapath does with packets: forwarded, NATed,
delivered, or dropped and why. With --drops, only drops are shown; they are
always reported by the datapath. Otherwise tracing of every verdict is
switched on while this command runs, for the given containers or all of
them, and switched off again within seconds after it stops.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var filterIP netip.Addr
			if ip != "" {
				a, err := netip.ParseAddr(ip)
				if err != nil {
					return fmt.Errorf("--ip: %w", err)
				}
				filterIP = a
			}
			if format != "" && format != "json" && format != "table" {
				return fmt.Errorf("unknown format %q (want table or json)", format)
			}
			m := manager()
			opts := datapath.TraceOptions{All: !dropsOnly}
			for _, ref := range args {
				c, err := m.Get(ref)
				if err != nil {
					return err
				}
				n := 0
				for _, ep := range c.Endpoints {
					if ep.Datapath == network.DatapathEBPF {
						opts.Ifindexes = append(opts.Ifindexes, uint32(ep.HostIfIndex))
						opts.Addrs = append(opts.Addrs, ep.IP)
						if ep.IP6.IsValid() {
							opts.Addrs = append(opts.Addrs, ep.IP6)
						}
						n++
					}
				}
				if n == 0 {
					return fmt.Errorf("container %s has no eBPF endpoints to trace", c.Name)
				}
			}
			names := newIfNames(m)
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			dp := m.Networks.Datapath()
			defer dp.Close()
			what := "every verdict"
			if dropsOnly {
				what = "drops"
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "tracing %s (Ctrl-C to stop)\n", what)

			out := cmd.OutOrStdout()
			enc := json.NewEncoder(out)
			shown := 0
			err := dp.Trace(ctx, opts, func(ev datapath.Event) bool {
				if filterIP.IsValid() && ev.Src.Addr() != filterIP && ev.Dst.Addr() != filterIP {
					return true
				}
				if format == "json" {
					enc.Encode(struct {
						datapath.Event
						Device string `json:"device"`
					}{ev, names.of(ev.Ifindex)})
				} else {
					fmt.Fprintln(out, formatEvent(ev, names.of(ev.Ifindex)))
				}
				shown++
				return count == 0 || shown < count
			})
			if err == context.Canceled {
				return nil
			}
			return err
		},
	}
	fl := cmd.Flags()
	fl.BoolVar(&dropsOnly, "drops", false, "Only show drops")
	fl.StringVar(&ip, "ip", "", "Only show packets from or to this address")
	fl.IntVar(&count, "count", 0, "Exit after this many events (0: until interrupted)")
	fl.StringVar(&format, "format", "", "Output format: table or json")
	return cmd
}

func formatEvent(ev datapath.Event, device string) string {
	kind := "TRACE"
	if ev.Drop {
		kind = "DROP"
	}
	if ev.Proto == "" && ev.Ifindex == 0 && ev.Len == 0 {
		// lost events and the like
		return fmt.Sprintf("%s  %s", ev.Time.Format("15:04:05.000000"), ev.Reason)
	}
	flow := ev.Proto
	if ev.Src.Addr().IsValid() {
		flow = fmt.Sprintf("%s %s -> %s", ev.Proto, endpointStr(ev.Src), endpointStr(ev.Dst))
	}
	return fmt.Sprintf("%s  %-5s  %-15s  %-7s  %-16s  %s  %dB",
		ev.Time.Format("15:04:05.000000"), kind, ev.Reason, ev.Direction, device, flow, ev.Len)
}

func endpointStr(ap netip.AddrPort) string {
	if ap.Port() == 0 {
		return ap.Addr().String()
	}
	return ap.String()
}

// ifNames maps primary ifindexes to "container/ethN", reloading the
// container records when an unknown device shows up (at most once a second).
type ifNames struct {
	m      *container.Manager
	names  map[uint32]string
	loaded time.Time
}

func newIfNames(m *container.Manager) *ifNames {
	n := &ifNames{m: m}
	n.load()
	return n
}

func (n *ifNames) load() {
	n.names = map[uint32]string{}
	n.loaded = time.Now()
	cs, _ := n.m.List()
	for _, c := range cs {
		for _, ep := range c.Endpoints {
			n.names[uint32(ep.HostIfIndex)] = c.Name + "/" + ep.IfName
		}
	}
}

func (n *ifNames) of(ifindex uint32) string {
	if ifindex == 0 {
		return "-"
	}
	name, ok := n.names[ifindex]
	if !ok && time.Since(n.loaded) > time.Second {
		n.load()
		name, ok = n.names[ifindex]
	}
	if !ok {
		return fmt.Sprintf("if%d", ifindex)
	}
	return name
}
