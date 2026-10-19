package datapath

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func frame(etherType uint16, payload ...[]byte) []byte {
	b := make([]byte, 12, 64)
	b = binary.BigEndian.AppendUint16(b, etherType)
	for _, p := range payload {
		b = append(b, p...)
	}
	return b
}

func ipv4(proto byte, src, dst string) []byte {
	h := make([]byte, 20)
	h[0] = 0x45
	h[9] = proto
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(h[12:], s[:])
	copy(h[16:], d[:])
	return h
}

func ipv6(proto byte, src, dst string) []byte {
	h := make([]byte, 40)
	h[0] = 0x60
	h[6] = proto
	s, d := netip.MustParseAddr(src).As16(), netip.MustParseAddr(dst).As16()
	copy(h[8:], s[:])
	copy(h[24:], d[:])
	return h
}

func ports(s, d uint16) []byte {
	return binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16(nil, s), d)
}

func TestDecodePacket(t *testing.T) {
	cases := []struct {
		name string
		b    []byte
		want Packet
	}{
		{"ipv4 tcp", frame(0x0800, ipv4(6, "10.87.0.2", "10.87.0.3"), ports(41234, 9000)),
			Packet{"tcp", netip.MustParseAddrPort("10.87.0.2:41234"), netip.MustParseAddrPort("10.87.0.3:9000")}},
		{"ipv6 udp", frame(0x86dd, ipv6(17, "fd00::2", "fd00::3"), ports(53000, 53)),
			Packet{"udp", netip.MustParseAddrPort("[fd00::2]:53000"), netip.MustParseAddrPort("[fd00::3]:53")}},
		{"icmp", frame(0x0800, ipv4(1, "10.0.0.1", "10.0.0.2")),
			Packet{"icmp", netip.MustParseAddrPort("10.0.0.1:0"), netip.MustParseAddrPort("10.0.0.2:0")}},
		{"tcp ports cut off", frame(0x0800, ipv4(6, "10.0.0.1", "10.0.0.2")),
			Packet{"tcp", netip.MustParseAddrPort("10.0.0.1:0"), netip.MustParseAddrPort("10.0.0.2:0")}},
		{"other ethertype", frame(0x88cc), Packet{Proto: "0x88cc"}},
		{"too short", []byte{1, 2, 3}, Packet{}},
	}
	for _, c := range cases {
		if got := DecodePacket(c.b); got != c.want {
			t.Errorf("%s: got %+v, want %+v", c.name, got, c.want)
		}
	}
	arp := make([]byte, 28)
	sip, tip := netip.MustParseAddr("10.0.0.5").As4(), netip.MustParseAddr("10.0.0.1").As4()
	copy(arp[14:], sip[:])
	copy(arp[24:], tip[:])
	if got := DecodePacket(frame(0x0806, arp)); got.Proto != "arp" || got.Src.Addr() != netip.AddrFrom4(sip) || got.Dst.Addr() != netip.AddrFrom4(tip) {
		t.Errorf("arp: %+v", got)
	}
}

func TestDecodeEvent(t *testing.T) {
	pkt := frame(0x0800, ipv4(6, "10.87.0.2", "10.88.0.2"), ports(1, 2))
	hdr := make([]byte, eventHdrLen)
	hdr[0], hdr[1], hdr[2] = eventDrop, 11, 0 // drop-policy, egress
	binary.NativeEndian.PutUint32(hdr[4:], 42)
	binary.NativeEndian.PutUint32(hdr[8:], 60)
	binary.NativeEndian.PutUint32(hdr[12:], uint32(len(pkt)))
	clock := monoClock{wall: time.Unix(1000, 0), mono: 5 * time.Second}
	binary.NativeEndian.PutUint64(hdr[16:], uint64(6*time.Second))
	// perf pads samples to 8 bytes; the padding must not be decoded.
	ev, ok := decodeEvent(append(append(hdr, pkt...), 0, 0, 0), clock)
	if !ok || !ev.Drop || ev.Reason != "drop-policy" || ev.Direction != "egress" || ev.Ifindex != 42 || ev.Len != 60 {
		t.Fatalf("event %+v", ev)
	}
	if !ev.Time.Equal(time.Unix(1001, 0)) {
		t.Fatalf("time %v, want 1s after the wall clock reference", ev.Time)
	}
	if ev.Dst != netip.MustParseAddrPort("10.88.0.2:2") {
		t.Fatalf("packet %+v", ev.Packet)
	}
}
