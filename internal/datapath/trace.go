package datapath

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"
)

// Event is one datapath event: a drop, or (while tracing) any other
// verdict. The packet fields are decoded from the bytes the kernel
// captured; for a NATed packet they show it after translation.
type Event struct {
	Time      time.Time `json:"time"`
	Drop      bool      `json:"drop"`
	Reason    string    `json:"reason"`
	Direction string    `json:"direction"`
	Ifindex   uint32    `json:"ifindex"`
	Len       uint32    `json:"len"`
	Packet
}

// Packet is what netker understands of a captured packet.
type Packet struct {
	Proto string         `json:"proto"` // tcp, udp, icmp, icmpv6, arp or the EtherType
	Src   netip.AddrPort `json:"src"`
	Dst   netip.AddrPort `json:"dst"`
}

// TraceOptions selects what Trace reports.
type TraceOptions struct {
	// All reports every verdict, not only drops.
	All bool
	// Ifindexes restricts events to these primary devices, in BPF.
	Ifindexes []uint32
	// Addrs also keeps drops from or to these addresses on other devices:
	// a drop is reported on the sender's device, so a packet another
	// container tried to send to a traced one shows up there.
	Addrs []netip.Addr
}

const (
	eventDrop     = 1
	eventHdrLen   = 24 // struct event_hdr
	traceFIfindex = 0x1
	// traceLease is how far ahead a tracer keeps the deadline; it renews
	// every second, so a killed tracer stops tracing within this time.
	traceLease = 3 * time.Second
)

// Trace calls fn for each event until ctx is done or fn returns false.
// Drops are always sent by the datapath; with opts.All, Trace also turns on
// tracing of the other verdicts for as long as it runs.
func (d *Datapath) Trace(ctx context.Context, opts TraceOptions, fn func(Event) bool) error {
	if err := d.Load(); err != nil {
		return err
	}
	rd, err := perf.NewReader(d.objs.NetkerEvents, 64*os.Getpagesize())
	if err != nil {
		return fmt.Errorf("open event buffer: %w", err)
	}
	defer rd.Close()

	if opts.All {
		if err := d.setTraceFilter(opts.Ifindexes); err != nil {
			return err
		}
		defer d.stopTracing()
		if err := d.renewTrace(len(opts.Ifindexes) > 0); err != nil {
			return err
		}
		go func() {
			t := time.NewTicker(time.Second)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					d.renewTrace(len(opts.Ifindexes) > 0)
				}
			}
		}()
	}

	watch := map[uint32]bool{}
	for _, i := range opts.Ifindexes {
		watch[i] = true
	}
	addrs := map[netip.Addr]bool{}
	for _, a := range opts.Addrs {
		addrs[a] = true
	}
	// Close, not SetDeadline: a blocked Read holds the lock SetDeadline
	// needs, so a deadline only takes effect once another event arrives.
	// Close interrupts Read right away.
	go func() {
		<-ctx.Done()
		rd.Close()
	}()
	clock := newMonoClock()
	for {
		rec, err := rd.Read()
		if errors.Is(err, perf.ErrClosed) {
			return ctx.Err()
		}
		if err != nil {
			return err
		}
		if rec.LostSamples > 0 {
			if !fn(Event{Time: time.Now(), Reason: fmt.Sprintf("lost %d events", rec.LostSamples)}) {
				return nil
			}
			continue
		}
		ev, ok := decodeEvent(rec.RawSample, clock)
		if !ok {
			continue
		}
		// Drops aren't filtered in BPF.
		if len(watch) > 0 && !watch[ev.Ifindex] &&
			!(ev.Drop && (addrs[ev.Src.Addr()] || addrs[ev.Dst.Addr()])) {
			continue
		}
		if !fn(ev) {
			return nil
		}
	}
}

func (d *Datapath) setTraceFilter(ifindexes []uint32) error {
	var k uint32
	var v uint8
	var old []uint32
	it := d.objs.NetkerTraceIfindex.Iterate()
	for it.Next(&k, &v) {
		old = append(old, k)
	}
	for _, k := range old {
		d.objs.NetkerTraceIfindex.Delete(k)
	}
	for _, i := range ifindexes {
		if err := d.objs.NetkerTraceIfindex.Put(i, uint8(1)); err != nil {
			return err
		}
	}
	return nil
}

func (d *Datapath) renewTrace(filtered bool) error {
	cfg := netkerTraceCfg{UntilNs: uint64(monotonicNow() + traceLease)}
	if filtered {
		cfg.Flags = traceFIfindex
	}
	return d.objs.NetkerTrace.Put(uint32(0), cfg)
}

func (d *Datapath) stopTracing() {
	d.objs.NetkerTrace.Put(uint32(0), netkerTraceCfg{})
	d.setTraceFilter(nil)
}

// TraceActive reports whether a tracer currently holds the lease.
func (d *Datapath) TraceActive() (bool, error) {
	if err := d.Load(); err != nil {
		return false, err
	}
	var cfg netkerTraceCfg
	if err := d.objs.NetkerTrace.Lookup(uint32(0), &cfg); err != nil {
		return false, err
	}
	return cfg.UntilNs > uint64(monotonicNow()), nil
}

// monotonicNow is CLOCK_MONOTONIC, the clock bpf_ktime_get_ns() reads.
func monotonicNow() time.Duration {
	var ts unix.Timespec
	unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return time.Duration(ts.Nano())
}

// monoClock converts bpf_ktime_get_ns() timestamps to wall-clock time.
type monoClock struct {
	wall time.Time
	mono time.Duration
}

func newMonoClock() monoClock { return monoClock{wall: time.Now(), mono: monotonicNow()} }

func (c monoClock) at(ns uint64) time.Time {
	return c.wall.Add(time.Duration(ns) - c.mono)
}

func decodeEvent(b []byte, clock monoClock) (Event, bool) {
	if len(b) < eventHdrLen {
		return Event{}, false
	}
	capLen := binary.NativeEndian.Uint32(b[12:16])
	ev := Event{
		Drop:      b[0] == eventDrop,
		Reason:    Reasons[b[1]],
		Direction: "egress",
		Ifindex:   binary.NativeEndian.Uint32(b[4:8]),
		Len:       binary.NativeEndian.Uint32(b[8:12]),
		Time:      clock.at(binary.NativeEndian.Uint64(b[16:24])),
	}
	if b[2] == 1 {
		ev.Direction = "ingress"
	}
	if ev.Reason == "" {
		ev.Reason = fmt.Sprintf("reason-%d", b[1])
	}
	pkt := b[eventHdrLen:]
	if int(capLen) < len(pkt) {
		pkt = pkt[:capLen]
	}
	ev.Packet = DecodePacket(pkt)
	return ev, true
}

// DecodePacket reads the Ethernet, IPv4/IPv6 and TCP/UDP/ICMP headers at
// the start of a frame. Whatever is missing or unknown stays zero.
func DecodePacket(b []byte) Packet {
	var p Packet
	if len(b) < 14 {
		return p
	}
	etherType := binary.BigEndian.Uint16(b[12:14])
	b = b[14:]
	var proto uint8
	var src, dst netip.Addr
	switch etherType {
	case unix.ETH_P_ARP:
		p.Proto = "arp"
		if len(b) >= 28 {
			p.Src = netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[14:18])), 0)
			p.Dst = netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[24:28])), 0)
		}
		return p
	case unix.ETH_P_IP:
		if len(b) < 20 {
			return p
		}
		ihl := int(b[0]&0xf) * 4
		proto = b[9]
		src = netip.AddrFrom4([4]byte(b[12:16]))
		dst = netip.AddrFrom4([4]byte(b[16:20]))
		if ihl < 20 || len(b) < ihl {
			b = nil
		} else {
			b = b[ihl:]
		}
	case unix.ETH_P_IPV6:
		if len(b) < 40 {
			return p
		}
		proto = b[6]
		src = netip.AddrFrom16([16]byte(b[8:24]))
		dst = netip.AddrFrom16([16]byte(b[24:40]))
		b = b[40:]
	default:
		p.Proto = fmt.Sprintf("0x%04x", etherType)
		return p
	}
	var sport, dport uint16
	switch proto {
	case unix.IPPROTO_TCP, unix.IPPROTO_UDP:
		p.Proto = map[uint8]string{unix.IPPROTO_TCP: "tcp", unix.IPPROTO_UDP: "udp"}[proto]
		if len(b) >= 4 {
			sport, dport = binary.BigEndian.Uint16(b[0:2]), binary.BigEndian.Uint16(b[2:4])
		}
	case unix.IPPROTO_ICMP:
		p.Proto = "icmp"
	case unix.IPPROTO_ICMPV6:
		p.Proto = "icmpv6"
	default:
		p.Proto = fmt.Sprintf("ip-proto-%d", proto)
	}
	p.Src = netip.AddrPortFrom(src, sport)
	p.Dst = netip.AddrPortFrom(dst, dport)
	return p
}
