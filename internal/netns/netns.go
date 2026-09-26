// Package netns creates persistent, bind-mounted network namespaces and runs
// code inside them.
package netns

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/vishvananda/netlink"
	vnetns "github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// Create makes a new network namespace and bind-mounts it at path so it
// outlives the creating thread. The caller's namespace is left unchanged.
func Create(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|os.O_CREATE|os.O_EXCL, 0o444)
	if err != nil {
		return err
	}
	f.Close()

	errCh := make(chan error, 1)
	go func() {
		// This goroutine's thread ends up in the new namespace, so it is
		// never unlocked: the Go runtime then discards the thread on exit.
		runtime.LockOSThread()
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			errCh <- fmt.Errorf("unshare netns: %w", err)
			return
		}
		src := fmt.Sprintf("/proc/self/task/%d/ns/net", unix.Gettid())
		if err := unix.Mount(src, path, "none", unix.MS_BIND, ""); err != nil {
			errCh <- fmt.Errorf("bind mount netns: %w", err)
			return
		}
		errCh <- nil
	}()
	if err := <-errCh; err != nil {
		os.Remove(path)
		return err
	}
	return nil
}

// Delete unmounts and removes a namespace created by Create. Missing paths
// are not an error.
func Delete(path string) error {
	if err := unix.Unmount(path, unix.MNT_DETACH); err != nil && !errors.Is(err, unix.EINVAL) && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("unmount %s: %w", path, err)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// LoopbackUp brings up "lo" in the current namespace.
func LoopbackUp() error {
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return err
	}
	return netlink.LinkSetUp(lo)
}

// Do runs fn with the calling goroutine's thread switched into the namespace
// at path, then switches back.
func Do(path string, fn func() error) error {
	target, err := vnetns.GetFromPath(path)
	if err != nil {
		return fmt.Errorf("open netns %s: %w", path, err)
	}
	defer target.Close()
	return DoHandle(target, fn)
}

// DoHandle is Do for an already-open namespace handle.
func DoHandle(target vnetns.NsHandle, fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	orig, err := vnetns.Get()
	if err != nil {
		return err
	}
	defer orig.Close()
	if err := vnetns.Set(target); err != nil {
		return fmt.Errorf("setns: %w", err)
	}
	fnErr := fn()
	if err := vnetns.Set(orig); err != nil {
		// The thread is stuck in the wrong namespace; never hand it back.
		runtime.LockOSThread()
		return errors.Join(fnErr, fmt.Errorf("restore netns: %w", err))
	}
	return fnErr
}
