package netkit

import "testing"

func TestOwnerOf(t *testing.T) {
	id := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cases := map[string]string{
		OwnerAltName(id, 0): id,
		OwnerAltName(id, 7): id,
		"netker-" + id:      id, // single-device tag from older versions
	}
	for alt, want := range cases {
		if got, ok := ownerOf(alt); !ok || got != want {
			t.Errorf("ownerOf(%q) = %q, %v; want %q", alt, got, ok, want)
		}
	}
	for _, alt := range []string{"netker-", "eth0", "nk123"} {
		if _, ok := ownerOf(alt); ok {
			t.Errorf("ownerOf(%q) matched", alt)
		}
	}
}
