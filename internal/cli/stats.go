package cli

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/saiaunghlyanhtet/netker/internal/container"
	"github.com/saiaunghlyanhtet/netker/internal/datapath"
)

// containerStats is one row of "netker stats".
type containerStats struct {
	ID         string               `json:"id"`
	Name       string               `json:"name"`
	CPUPercent float64              `json:"cpu_percent"`
	Resources  *container.Resources `json:"resources,omitempty"`
	Net        []container.NetStats `json:"net"`
}

func (s containerStats) netTotals() (rx, tx, dropped uint64) {
	for _, n := range s.Net {
		rx += n.RxBytes
		tx += n.TxBytes
		dropped += n.DroppedTotal()
	}
	return
}

func statsCmd() *cobra.Command {
	var noStream, netDetail bool
	var format string
	cmd := &cobra.Command{
		Use:   "stats [OPTIONS] [CONTAINER...]",
		Short: "Show resource usage of running containers",
		RunE: func(cmd *cobra.Command, args []string) error {
			if format != "" && format != "json" && format != "table" {
				return fmt.Errorf("unknown format %q (want table or json)", format)
			}
			m := manager()
			dp := m.Networks.Datapath()
			defer dp.Close()
			out := cmd.OutOrStdout()
			// CPU % needs two readings: each sample is compared with the
			// previous one (or, the first time, one taken just before).
			prev := map[string]*container.Resources{}
			var prevAt time.Time
			sample := func() ([]containerStats, error) {
				if len(prev) == 0 {
					first, _ := collectStats(m, dp, args)
					for _, r := range first {
						prev[r.ID] = r.Resources
					}
					prevAt = time.Now()
					time.Sleep(500 * time.Millisecond)
				}
				rows, err := collectStats(m, dp, args)
				if err != nil {
					return nil, err
				}
				now := time.Now()
				elapsed := uint64(now.Sub(prevAt).Microseconds())
				for i := range rows {
					rows[i].CPUPercent = container.CPUPercent(prev[rows[i].ID], rows[i].Resources, elapsed)
					prev[rows[i].ID] = rows[i].Resources
				}
				prevAt = now
				return rows, nil
			}
			render := func(rows []containerStats) error {
				if format == "json" {
					return printJSON(cmd, rows)
				}
				if netDetail {
					return printNetStats(out, rows)
				}
				return printStats(out, rows)
			}
			if noStream {
				rows, err := sample()
				if err != nil {
					return err
				}
				return render(rows)
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			clear := format != "json" && isTerminal(out)
			tick := time.NewTicker(2 * time.Second)
			defer tick.Stop()
			for {
				rows, err := sample()
				if err != nil {
					return err
				}
				if clear {
					fmt.Fprint(out, "\033[H\033[2J")
				}
				if err := render(rows); err != nil {
					return err
				}
				select {
				case <-ctx.Done():
					return nil
				case <-tick.C:
				}
			}
		},
	}
	fl := cmd.Flags()
	fl.BoolVar(&noStream, "no-stream", false, "Print one sample and exit")
	fl.BoolVar(&netDetail, "net", false, "Show network counters per interface, with drops by reason")
	fl.StringVar(&format, "format", "", "Output format: table or json")
	return cmd
}

func collectStats(m *container.Manager, dp *datapath.Datapath, refs []string) ([]containerStats, error) {
	var cs []*container.Container
	if len(refs) > 0 {
		for _, ref := range refs {
			c, err := m.Get(ref)
			if err != nil {
				return nil, err
			}
			cs = append(cs, c)
		}
	} else {
		all, err := m.List()
		if err != nil {
			return nil, err
		}
		for _, c := range all {
			if m.Status(c) == "running" {
				cs = append(cs, c)
			}
		}
	}
	// Without the eBPF datapath (unprivileged, legacy) there are no drop
	// counters; the device counters still work.
	metrics, _ := dp.Metrics()
	var rows []containerStats
	for _, c := range cs {
		net, err := m.NetStats(c, metrics)
		if err != nil {
			return nil, fmt.Errorf("container %s: %w", c.Name, err)
		}
		row := containerStats{ID: c.ID, Name: c.Name, Net: net}
		// A container that just exited has no process; show what's left.
		if res, err := m.Resources(c); err == nil && !res.Shared {
			row.Resources = res
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Name < rows[j].Name })
	return rows, nil
}

func printStats(w io.Writer, rows []containerStats) error {
	tw := tabwriter.NewWriter(w, 0, 4, 3, ' ', 0)
	fmt.Fprintln(tw, "CONTAINER ID\tNAME\tCPU %\tMEM USAGE / LIMIT\tMEM %\tNET I/O\tDROPS\tBLOCK I/O\tPIDS")
	for _, r := range rows {
		cpu, mem, memPct, blk, pids := "-", "-", "-", "-", "-"
		if res := r.Resources; res != nil {
			cpu = fmt.Sprintf("%.2f%%", r.CPUPercent)
			if res.Memory {
				mem = humanBinary(res.MemUsage) + " / " + humanBinary(res.MemLimit)
				if res.MemLimit > 0 {
					memPct = fmt.Sprintf("%.2f%%", float64(res.MemUsage)/float64(res.MemLimit)*100)
				}
			}
			if res.IO {
				blk = humanSize(int64(res.BlkRead)) + " / " + humanSize(int64(res.BlkWrite))
			}
			pids = fmt.Sprint(res.Pids)
		}
		netIO, drops := "-", "-"
		if len(r.Net) > 0 {
			rx, tx, d := r.netTotals()
			netIO = humanSize(int64(rx)) + " / " + humanSize(int64(tx))
			drops = fmt.Sprint(d)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			shortID(r.ID), r.Name, cpu, mem, memPct, netIO, drops, blk, pids)
	}
	return tw.Flush()
}

func printNetStats(w io.Writer, rows []containerStats) error {
	tw := tabwriter.NewWriter(w, 0, 4, 3, ' ', 0)
	fmt.Fprintln(tw, "NAME\tIFACE\tNETWORK\tDATAPATH\tRX\tTX\tDROPS")
	for _, r := range rows {
		for _, n := range r.Net {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s (%d pkts)\t%s (%d pkts)\t%s\n",
				r.Name, n.IfName, n.Network, n.Datapath,
				humanSize(int64(n.RxBytes)), n.RxPackets, humanSize(int64(n.TxBytes)), n.TxPackets,
				dropsDetail(n))
		}
	}
	return tw.Flush()
}

// dropsDetail lists drops by reason, most first ("drop-icc=3, drop-spoof=1").
func dropsDetail(n container.NetStats) string {
	if n.Drops == nil {
		return fmt.Sprint(n.DroppedTotal())
	}
	type kv struct {
		k string
		v uint64
	}
	var l []kv
	for k, v := range n.Drops {
		l = append(l, kv{k, v})
	}
	sort.Slice(l, func(i, j int) bool { return l[i].v > l[j].v || (l[i].v == l[j].v && l[i].k < l[j].k) })
	var parts []string
	for _, e := range l {
		parts = append(parts, fmt.Sprintf("%s=%d", e.k, e.v))
	}
	return strings.Join(parts, ", ")
}

// humanBinary formats memory in binary units, as Docker does (MiB, GiB).
func humanBinary(n uint64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	f := float64(n)
	i := 0
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	return fmt.Sprintf("%.4g%s", f, units[i])
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}
