// Package ipam is a file-backed IPv4 address allocator. Each network has one
// JSON file guarded by an flock, so concurrent netker invocations are safe
// without a daemon.
package ipam

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

var ErrExhausted = errors.New("address pool exhausted")

type Pool struct {
	path    string
	subnet  netip.Prefix
	gateway netip.Addr
}

type state struct {
	// Allocated maps address -> owner (container ID).
	Allocated map[string]string `json:"allocated"`
	// Last is where the next search starts, so freed addresses aren't
	// reused immediately.
	Last string `json:"last,omitempty"`
}

// New returns the pool for subnet stored at dir/<name>.json. The network and
// broadcast addresses and the gateway are never handed out.
func New(dir, name string, subnet netip.Prefix, gateway netip.Addr) (*Pool, error) {
	if !subnet.Addr().Is4() {
		return nil, fmt.Errorf("only IPv4 subnets are supported, got %s", subnet)
	}
	if subnet.Bits() > 30 {
		return nil, fmt.Errorf("subnet %s is too small", subnet)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &Pool{path: filepath.Join(dir, name+".json"), subnet: subnet.Masked(), gateway: gateway}, nil
}

// Allocate reserves an address for owner. If want is valid, that exact
// address is reserved or an error is returned.
func (p *Pool) Allocate(owner string, want netip.Addr) (netip.Addr, error) {
	var got netip.Addr
	err := p.update(func(s *state) error {
		if want.IsValid() {
			if err := p.usable(want); err != nil {
				return err
			}
			if o, ok := s.Allocated[want.String()]; ok {
				return fmt.Errorf("address %s already in use by %s", want, o)
			}
			got = want
		} else {
			start := p.first()
			if last, err := netip.ParseAddr(s.Last); err == nil && p.subnet.Contains(last) {
				start = last.Next()
			}
			a, err := p.search(s, start)
			if err != nil {
				return err
			}
			got = a
			s.Last = a.String()
		}
		s.Allocated[got.String()] = owner
		return nil
	})
	return got, err
}

// Release frees addr. Releasing an unknown address is a no-op.
func (p *Pool) Release(addr netip.Addr) error {
	return p.update(func(s *state) error {
		delete(s.Allocated, addr.String())
		return nil
	})
}

// ReleaseOwner frees every address held by owner.
func (p *Pool) ReleaseOwner(owner string) error {
	return p.update(func(s *state) error {
		for a, o := range s.Allocated {
			if o == owner {
				delete(s.Allocated, a)
			}
		}
		return nil
	})
}

func (p *Pool) usable(a netip.Addr) error {
	if !p.subnet.Contains(a) {
		return fmt.Errorf("address %s not in subnet %s", a, p.subnet)
	}
	if a == p.subnet.Addr() || a == p.broadcast() || a == p.gateway {
		return fmt.Errorf("address %s is reserved", a)
	}
	return nil
}

func (p *Pool) first() netip.Addr { return p.subnet.Addr().Next() }

func (p *Pool) broadcast() netip.Addr {
	b := p.subnet.Addr().As4()
	v := binary.BigEndian.Uint32(b[:]) | (1<<(32-p.subnet.Bits()) - 1)
	binary.BigEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b)
}

func (p *Pool) search(s *state, start netip.Addr) (netip.Addr, error) {
	size := 1 << (32 - p.subnet.Bits())
	a := start
	for i := 0; i < size; i++ {
		if !p.subnet.Contains(a) {
			a = p.first()
		}
		if _, used := s.Allocated[a.String()]; !used && p.usable(a) == nil {
			return a, nil
		}
		a = a.Next()
	}
	return netip.Addr{}, fmt.Errorf("%s: %w", p.subnet, ErrExhausted)
}

func (p *Pool) update(fn func(*state) error) error {
	// The lock lives in its own file because the state file is replaced by
	// rename, which would leave a lock on the old inode.
	f, err := os.OpenFile(p.path+".lock", os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		return err
	}
	s := state{Allocated: map[string]string{}}
	data, err := os.ReadFile(p.path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &s); err != nil {
			return fmt.Errorf("corrupt ipam state %s: %w", p.path, err)
		}
		if s.Allocated == nil {
			s.Allocated = map[string]string{}
		}
	}
	if err := fn(&s); err != nil {
		return err
	}
	out, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	// Write via a temp file so a crash never leaves a truncated state file.
	tmp := p.path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p.path)
}
