package image

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	securejoin "github.com/cyphar/filepath-securejoin"
	"golang.org/x/sys/unix"
)

type UntarResult struct {
	SkippedDevices int
	ChownFailures  int
}

// Untar extracts a tar stream into root. Every path, including symlink and
// hardlink targets, is resolved as if root were "/", so a malicious image
// can't write outside root.
func Untar(r io.Reader, root string) (UntarResult, error) {
	var res UntarResult
	tr := tar.NewReader(r)
	type dirTime struct {
		path  string
		mtime time.Time
	}
	var dirs []dirTime
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return res, err
		}
		target, err := securejoin.SecureJoin(root, hdr.Name)
		if err != nil {
			return res, fmt.Errorf("%s: %w", hdr.Name, err)
		}
		if target == root {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return res, err
		}
		mode := os.FileMode(hdr.Mode).Perm()
		if hdr.Mode&04000 != 0 {
			mode |= os.ModeSetuid
		}
		if hdr.Mode&02000 != 0 {
			mode |= os.ModeSetgid
		}
		if hdr.Mode&01000 != 0 {
			mode |= os.ModeSticky
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if fi, err := os.Lstat(target); err == nil && !fi.IsDir() {
				os.Remove(target)
			}
			if err := os.Mkdir(target, 0o755); err != nil && !os.IsExist(err) {
				return res, err
			}
			dirs = append(dirs, dirTime{target, hdr.ModTime})
		case tar.TypeReg:
			os.Remove(target)
			f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return res, err
			}
			_, err = io.Copy(f, tr)
			f.Close()
			if err != nil {
				return res, err
			}
		case tar.TypeSymlink:
			os.Remove(target)
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				return res, err
			}
		case tar.TypeLink:
			src, err := securejoin.SecureJoin(root, hdr.Linkname)
			if err != nil {
				return res, err
			}
			os.Remove(target)
			if err := os.Link(src, target); err != nil {
				return res, err
			}
			continue // shares the inode, metadata already set
		case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
			devType := uint32(unix.S_IFCHR)
			switch hdr.Typeflag {
			case tar.TypeBlock:
				devType = unix.S_IFBLK
			case tar.TypeFifo:
				devType = unix.S_IFIFO
			}
			os.Remove(target)
			dev := unix.Mkdev(uint32(hdr.Devmajor), uint32(hdr.Devminor))
			if err := unix.Mknod(target, devType|uint32(hdr.Mode&0o7777), int(dev)); err != nil {
				if errors.Is(err, unix.EPERM) {
					res.SkippedDevices++
					continue
				}
				return res, err
			}
		default:
			continue
		}

		if err := os.Lchown(target, hdr.Uid, hdr.Gid); err != nil {
			if !errors.Is(err, unix.EPERM) && !errors.Is(err, unix.EINVAL) {
				return res, err
			}
			res.ChownFailures++
		}
		if hdr.Typeflag == tar.TypeSymlink {
			ts := []unix.Timespec{unix.NsecToTimespec(hdr.ModTime.UnixNano()), unix.NsecToTimespec(hdr.ModTime.UnixNano())}
			unix.UtimesNanoAt(unix.AT_FDCWD, target, ts, unix.AT_SYMLINK_NOFOLLOW)
			continue
		}
		// chmod after chown: chown clears setuid/setgid bits.
		if err := os.Chmod(target, mode); err != nil {
			return res, err
		}
		if hdr.Typeflag != tar.TypeDir {
			os.Chtimes(target, hdr.ModTime, hdr.ModTime)
		}
	}
	// Directory mtimes last, since creating entries inside changes them.
	for i := len(dirs) - 1; i >= 0; i-- {
		os.Chtimes(dirs[i].path, dirs[i].mtime, dirs[i].mtime)
	}
	return res, nil
}
