// Package atomicfile stages file contents beside their destination before replacement.
package atomicfile

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
)

// Write replaces path after write, Sync, and Close all succeed. Existing regular
// files keep their permissions; new files use perm subject to the process umask.
// A destination symlink is replaced. Call Resolve first to write through it.
// The callback must not close the supplied file.
func Write(path string, perm os.FileMode, write func(*os.File) error) error {
	return replace(osFS{}, path, perm, write)
}

// WriteRoot is Write for a name inside root: the temporary file and the rename
// are both confined to root.
func WriteRoot(root *os.Root, name string, perm os.FileMode, write func(*os.File) error) error {
	return replace(root, name, perm, write)
}

// filesystem is the part of *os.Root that replace needs; osFS is the same
// operations on unconfined paths.
type filesystem interface {
	Lstat(name string) (os.FileInfo, error)
	OpenFile(name string, flag int, perm os.FileMode) (*os.File, error)
	Remove(name string) error
	Rename(oldname, newname string) error
}

type osFS struct{}

func (osFS) Lstat(name string) (os.FileInfo, error) { return os.Lstat(name) }
func (osFS) OpenFile(name string, flag int, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(name, flag, perm)
}
func (osFS) Remove(name string) error             { return os.Remove(name) }
func (osFS) Rename(oldname, newname string) error { return os.Rename(oldname, newname) }

func replace(fsys filesystem, path string, perm os.FileMode, write func(*os.File) error) error {
	info, err := fsys.Lstat(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	preserve := err == nil && info.Mode().IsRegular()
	if preserve {
		perm = info.Mode().Perm()
	}

	temp := filepath.Join(filepath.Dir(path), ".ipsw-"+rand.Text()+".tmp")
	f, err := fsys.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	defer func() {
		_ = f.Close()
		_ = fsys.Remove(temp)
	}()
	if preserve {
		// Restore bits masked by the umask when recreating an existing file.
		if err := f.Chmod(perm); err != nil {
			return err
		}
	}
	if err := write(f); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return fsys.Rename(temp, path)
}

// Resolve follows destination symlinks, including links to a missing final
// component. The destination's parent directory must already exist.
func Resolve(path string) (string, error) {
	const maxSymlinks = 255
	for range maxSymlinks {
		dir, base := filepath.Split(path)
		if dir == "" {
			dir = "."
		}
		dir, err := filepath.EvalSymlinks(dir)
		if err != nil {
			return "", err
		}
		path = filepath.Join(dir, base)
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			return path, nil
		}
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink == 0 {
			return path, nil
		}
		target, err := os.Readlink(path)
		if err != nil {
			return "", err
		}
		path = target
		if !filepath.IsAbs(target) {
			// Preserve '..' until EvalSymlinks resolves the parent components.
			path = dir + string(os.PathSeparator) + target
		}
	}
	return "", fmt.Errorf("too many symbolic links resolving %q", path)
}
