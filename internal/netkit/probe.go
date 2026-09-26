package netkit

import (
	"fmt"
	"runtime"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Features reports which netkit capabilities the running kernel supports.
type Features struct {
	L3      bool   `json:"l3"`
	L2      bool   `json:"l2"`
	Scrub   bool   `json:"scrub"`
	L3Error string `json:"l3_error,omitempty"`
	L2Error string `json:"l2_error,omitempty"`
}

// Probe creates throwaway netkit pairs inside a fresh network namespace.
// It needs CAP_NET_ADMIN and CAP_SYS_ADMIN, which an unprivileged user can
// get inside a new user namespace.
func Probe() (Features, error) {
	type result struct {
		f   Features
		err error
	}
	ch := make(chan result, 1)
	go func() {
		// Never unlocked: the thread is left in the scratch namespace and
		// is discarded by the Go runtime when this goroutine exits.
		runtime.LockOSThread()
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			ch <- result{err: fmt.Errorf("unshare netns: %w", err)}
			return
		}
		var f Features
		if err := probeOne(netlink.NETKIT_MODE_L3, &f.Scrub); err != nil {
			f.L3Error = err.Error()
		} else {
			f.L3 = true
		}
		if err := probeOne(netlink.NETKIT_MODE_L2, nil); err != nil {
			f.L2Error = err.Error()
		} else {
			f.L2 = true
		}
		ch <- result{f: f}
	}()
	r := <-ch
	return r.f, r.err
}

func probeOne(mode netlink.NetkitMode, scrub *bool) error {
	nk := &netlink.Netkit{
		LinkAttrs:  netlink.LinkAttrs{Name: "nkprobe0"},
		Mode:       mode,
		Policy:     netlink.NETKIT_POLICY_FORWARD,
		PeerPolicy: netlink.NETKIT_POLICY_BLACKHOLE,
		Scrub:      netlink.NETKIT_SCRUB_NONE,
		PeerScrub:  netlink.NETKIT_SCRUB_DEFAULT,
	}
	nk.SetPeerAttrs(&netlink.LinkAttrs{Name: "nkprobe1"})
	if err := netlink.LinkAdd(nk); err != nil {
		return err
	}
	defer netlink.LinkDel(nk)
	l, err := netlink.LinkByName("nkprobe0")
	if err != nil {
		return err
	}
	got, ok := l.(*netlink.Netkit)
	if !ok {
		return fmt.Errorf("created link has type %q, not netkit", l.Type())
	}
	if !got.IsPrimary() {
		return fmt.Errorf("nkprobe0 is not the primary device")
	}
	if got.PeerPolicy != netlink.NETKIT_POLICY_BLACKHOLE {
		return fmt.Errorf("peer policy not applied")
	}
	if scrub != nil {
		*scrub = got.SupportsScrub()
	}
	return nil
}
