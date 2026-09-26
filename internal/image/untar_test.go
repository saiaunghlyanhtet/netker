package image

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

type entry struct {
	hdr  tar.Header
	body string
}

func mkTar(t *testing.T, entries []entry) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		h := e.hdr
		h.Size = int64(len(e.body))
		if h.Mode == 0 {
			h.Mode = 0o644
		}
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(e.body))
	}
	tw.Close()
	return &buf
}

func TestUntarBasic(t *testing.T) {
	root := t.TempDir()
	tr := mkTar(t, []entry{
		{hdr: tar.Header{Name: "etc/", Typeflag: tar.TypeDir, Mode: 0o755}},
		{hdr: tar.Header{Name: "etc/hostname", Typeflag: tar.TypeReg}, body: "box\n"},
		{hdr: tar.Header{Name: "bin/su", Typeflag: tar.TypeReg, Mode: 0o4755}, body: "x"},
		{hdr: tar.Header{Name: "etc/alias", Typeflag: tar.TypeSymlink, Linkname: "hostname"}},
		{hdr: tar.Header{Name: "etc/hard", Typeflag: tar.TypeLink, Linkname: "etc/hostname"}},
	})
	if _, err := Untar(tr, root); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "etc/alias")); string(b) != "box\n" {
		t.Fatalf("symlink content %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "etc/hard")); string(b) != "box\n" {
		t.Fatalf("hardlink content %q", b)
	}
	fi, err := os.Stat(filepath.Join(root, "bin/su"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSetuid == 0 {
		t.Fatalf("setuid bit lost: %v", fi.Mode())
	}
}

func TestUntarStaysInsideRoot(t *testing.T) {
	outside := t.TempDir()
	root := t.TempDir()
	tr := mkTar(t, []entry{
		{hdr: tar.Header{Name: "../../escape", Typeflag: tar.TypeReg}, body: "x"},
		// A symlink pointing outside, then a write through it.
		{hdr: tar.Header{Name: "evil", Typeflag: tar.TypeSymlink, Linkname: outside}},
		{hdr: tar.Header{Name: "evil/pwned", Typeflag: tar.TypeReg}, body: "x"},
		{hdr: tar.Header{Name: "hl", Typeflag: tar.TypeLink, Linkname: "../../../etc/passwd"}},
	})
	// The hardlink resolves to <root>/etc/passwd, which doesn't exist.
	Untar(tr, root)
	if _, err := os.Stat(filepath.Join(outside, "pwned")); err == nil {
		t.Fatal("wrote through a symlink outside the root")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(root), "escape")); err == nil {
		t.Fatal("wrote outside the root with ..")
	}
	if _, err := os.Stat(filepath.Join(root, "escape")); err != nil {
		t.Fatalf("../../escape should land at <root>/escape: %v", err)
	}
}
