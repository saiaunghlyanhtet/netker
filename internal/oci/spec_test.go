package oci

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func fakeRootfs(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "etc"), 0o755)
	os.WriteFile(filepath.Join(root, "etc/passwd"), []byte("root:x:0:0::/root:/bin/sh\nnginx:x:101:102::/var/lib/nginx:/sbin/nologin\n"), 0o644)
	os.WriteFile(filepath.Join(root, "etc/group"), []byte("root:x:0:\nnginx:x:102:\nwww:x:33:\n"), 0o644)
	return root
}

func TestResolveUser(t *testing.T) {
	root := fakeRootfs(t)
	cases := []struct {
		in       string
		uid, gid uint32
		wantErr  bool
	}{
		{"", 0, 0, false},
		{"nginx", 101, 102, false},
		{"nginx:www", 101, 33, false},
		{"1000", 1000, 1000, false},
		{"101", 101, 102, false},
		{"1000:33", 1000, 33, false},
		{"nobody", 0, 0, true},
	}
	for _, c := range cases {
		uid, gid, err := resolveUser(root, c.in)
		if (err != nil) != c.wantErr || uid != c.uid || gid != c.gid {
			t.Errorf("resolveUser(%q) = %d, %d, %v; want %d, %d, err=%v", c.in, uid, gid, err, c.uid, c.gid, c.wantErr)
		}
	}
}

func TestSpecNetworkNamespace(t *testing.T) {
	root := fakeRootfs(t)
	netns := func(s *specs.Spec) *specs.LinuxNamespace {
		for i, ns := range s.Linux.Namespaces {
			if ns.Type == specs.NetworkNamespace {
				return &s.Linux.Namespaces[i]
			}
		}
		return nil
	}
	s, _ := Spec(SpecOptions{Args: []string{"sh"}, Rootfs: root, NetNSPath: "/run/netker/netns/x"})
	if ns := netns(s); ns == nil || ns.Path != "/run/netker/netns/x" {
		t.Fatalf("expected netns path, got %+v", ns)
	}
	s, _ = Spec(SpecOptions{Args: []string{"sh"}, Rootfs: root, HostNetwork: true})
	if netns(s) != nil {
		t.Fatal("host network must not create a netns")
	}
	s, _ = Spec(SpecOptions{Args: []string{"sh"}, Rootfs: root})
	if ns := netns(s); ns == nil || ns.Path != "" {
		t.Fatal("expected a fresh netns")
	}
}

func TestSpecVersionAcceptedByOldCrun(t *testing.T) {
	s, err := Spec(SpecOptions{Args: []string{"sh"}, Rootfs: fakeRootfs(t)})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s.Version, "1.0") {
		t.Fatalf("ociVersion %q: older crun only accepts versions containing \"1.0\"", s.Version)
	}
}

func TestProcessEnv(t *testing.T) {
	env := ProcessEnv([]string{"FOO=1"}, "box", true)
	for _, want := range []string{"PATH=", "FOO=1", "TERM=xterm", "HOSTNAME=box"} {
		if !hasEnv(env, strings.SplitN(want, "=", 2)[0]) {
			t.Errorf("missing %s in %v", want, env)
		}
	}
	if got := ProcessEnv([]string{"PATH=/x"}, "box", false); got[0] != "PATH=/x" || hasEnv(got, "TERM") {
		t.Errorf("PATH overridden or TERM set without a tty: %v", got)
	}
}
