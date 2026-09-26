// Package image pulls OCI/Docker images and keeps them unpacked on disk as
// read-only lower directories for overlayfs.
package image

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"golang.org/x/sys/unix"

	"github.com/saiaunghlyanhtet/netker/internal/config"
)

var ErrNotFound = errors.New("image not found")

// Image is an unpacked image.
type Image struct {
	Ref    string    `json:"ref"`    // normalised, e.g. index.docker.io/library/alpine:latest
	Digest string    `json:"digest"` // manifest digest
	Size   int64     `json:"size"`
	Pulled time.Time `json:"pulled"`
	Config v1.Config `json:"config"`
	Rootfs string    `json:"-"`
}

type Store struct {
	dir string
}

func NewStore(p config.Paths) *Store { return &Store{dir: p.Images()} }

func (s *Store) indexPath() string { return filepath.Join(s.dir, "index.json") }

func (s *Store) imageDir(digest string) string {
	return filepath.Join(s.dir, strings.ReplaceAll(digest, ":", "-"))
}

// Normalize expands short references (alpine -> index.docker.io/library/alpine:latest).
func Normalize(ref string) (string, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return "", err
	}
	return r.Name(), nil
}

func (s *Store) readIndex() (map[string]string, error) {
	idx := map[string]string{}
	data, err := os.ReadFile(s.indexPath())
	if os.IsNotExist(err) {
		return idx, nil
	}
	if err != nil {
		return nil, err
	}
	return idx, json.Unmarshal(data, &idx)
}

func (s *Store) writeIndex(idx map[string]string) error {
	data, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.indexPath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.indexPath())
}

// Get returns a locally available image by reference or digest prefix.
func (s *Store) Get(ref string) (*Image, error) {
	idx, err := s.readIndex()
	if err != nil {
		return nil, err
	}
	digest, ok := "", false
	if n, err := Normalize(ref); err == nil {
		digest, ok = idx[n]
	}
	if !ok {
		for _, d := range idx {
			if strings.HasPrefix(strings.TrimPrefix(d, "sha256:"), ref) && len(ref) >= 6 {
				digest, ok = d, true
				break
			}
		}
	}
	if !ok {
		return nil, fmt.Errorf("%s: %w", ref, ErrNotFound)
	}
	return s.load(digest)
}

func (s *Store) load(digest string) (*Image, error) {
	dir := s.imageDir(digest)
	data, err := os.ReadFile(filepath.Join(dir, "image.json"))
	if err != nil {
		return nil, err
	}
	var img Image
	if err := json.Unmarshal(data, &img); err != nil {
		return nil, err
	}
	img.Rootfs = filepath.Join(dir, "rootfs")
	return &img, nil
}

// List returns all local images, one entry per reference.
func (s *Store) List() ([]*Image, error) {
	idx, err := s.readIndex()
	if err != nil {
		return nil, err
	}
	var out []*Image
	for ref, d := range idx {
		img, err := s.load(d)
		if err != nil {
			return nil, err
		}
		img.Ref = ref
		out = append(out, img)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ref < out[j].Ref })
	return out, nil
}

// Pull fetches ref for the host platform and unpacks it. Progress lines are
// written to w.
func (s *Store) Pull(ref string, w io.Writer) (*Image, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return nil, err
	}
	platform := v1.Platform{OS: "linux", Architecture: runtime.GOARCH}
	fmt.Fprintf(w, "Pulling %s (%s/%s)\n", r.Name(), platform.OS, platform.Architecture)
	remoteImg, err := remote.Image(r,
		remote.WithPlatform(platform),
		remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return nil, fmt.Errorf("pull %s: %w", r.Name(), err)
	}
	digest, err := remoteImg.Digest()
	if err != nil {
		return nil, err
	}
	cfg, err := remoteImg.ConfigFile()
	if err != nil {
		return nil, err
	}
	var size int64
	if layers, err := remoteImg.Layers(); err == nil {
		for _, l := range layers {
			if s, err := l.Size(); err == nil {
				size += s
			}
		}
	}

	dir := s.imageDir(digest.String())
	if _, err := os.Stat(filepath.Join(dir, "image.json")); err != nil {
		if err := s.unpack(remoteImg, dir, w); err != nil {
			return nil, err
		}
		img := Image{Ref: r.Name(), Digest: digest.String(), Size: size, Pulled: time.Now().UTC(), Config: cfg.Config}
		data, _ := json.MarshalIndent(img, "", "  ")
		if err := os.WriteFile(filepath.Join(dir, "image.json"), data, 0o644); err != nil {
			return nil, err
		}
	} else {
		fmt.Fprintf(w, "Image is up to date (%s)\n", digest)
	}

	idx, err := s.readIndex()
	if err != nil {
		return nil, err
	}
	idx[r.Name()] = digest.String()
	if err := s.writeIndex(idx); err != nil {
		return nil, err
	}
	fmt.Fprintf(w, "Digest: %s\n", digest)
	img, err := s.load(digest.String())
	if err != nil {
		return nil, err
	}
	img.Ref = r.Name()
	return img, nil
}

func (s *Store) unpack(img v1.Image, dir string, w io.Writer) error {
	tmp := dir + ".partial"
	os.RemoveAll(tmp)
	rootfs := filepath.Join(tmp, "rootfs")
	if err := os.MkdirAll(rootfs, 0o755); err != nil {
		return err
	}
	layers, _ := img.Layers()
	fmt.Fprintf(w, "Unpacking %d layer(s)\n", len(layers))
	// mutate.Extract flattens the layers and applies whiteouts.
	rc := mutate.Extract(img)
	defer rc.Close()
	res, err := Untar(rc, rootfs)
	if err != nil {
		os.RemoveAll(tmp)
		return err
	}
	if res.SkippedDevices > 0 || res.ChownFailures > 0 {
		fmt.Fprintf(w, "warning: skipped %d device node(s), %d ownership change(s) failed (unprivileged?)\n",
			res.SkippedDevices, res.ChownFailures)
	}
	os.RemoveAll(dir)
	return os.Rename(tmp, dir)
}

// Remove deletes a reference; the unpacked data is deleted once no
// reference points to it. inUse reports whether a container uses the digest.
func (s *Store) Remove(ref string, inUse func(digest string) bool) error {
	img, err := s.Get(ref)
	if err != nil {
		return err
	}
	idx, err := s.readIndex()
	if err != nil {
		return err
	}
	if inUse(img.Digest) {
		return fmt.Errorf("image %s is used by a container", ref)
	}
	for r, d := range idx {
		if d == img.Digest {
			delete(idx, r)
		}
	}
	if err := s.writeIndex(idx); err != nil {
		return err
	}
	return removeAllWritable(s.imageDir(img.Digest))
}

// removeAllWritable is os.RemoveAll that first makes read-only directories
// writable (images contain them, e.g. /proc with mode 0555).
func removeAllWritable(dir string) error {
	filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && info.IsDir() && info.Mode()&0o200 == 0 {
			unix.Chmod(p, uint32(info.Mode().Perm()|0o700))
		}
		return nil
	})
	return os.RemoveAll(dir)
}
