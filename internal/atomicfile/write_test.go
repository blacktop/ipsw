package atomicfile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteSyncFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "output")
	if err := os.WriteFile(path, []byte("previous"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := Write(path, 0o644, func(f *os.File) error {
		if _, err := f.WriteString("replacement"); err != nil {
			return err
		}
		// Force the subsequent Sync to fail on a real file descriptor.
		return f.Close()
	})
	if !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Write error = %v, want os.ErrClosed", err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "previous" {
		t.Fatalf("previous output = %q, %v", got, err)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 1 {
		t.Fatalf("failed write left unexpected files: %v, %v", entries, err)
	}
}

func TestResolveSymlinkParentsAndLoop(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "nested", "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("nested", "child"), filepath.Join(dir, "alias")); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "output")
	if err := os.Symlink("alias"+string(os.PathSeparator)+".."+string(os.PathSeparator)+"missing", link); err != nil {
		t.Fatal(err)
	}
	got, err := Resolve(link)
	parent, parentErr := filepath.EvalSymlinks(filepath.Join(dir, "nested"))
	if err != nil || parentErr != nil || got != filepath.Join(parent, "missing") {
		t.Fatalf("Resolve = %q, %v; parent = %q, %v", got, err, parent, parentErr)
	}
	loop := filepath.Join(dir, "loop")
	if err := os.Symlink("loop", loop); err != nil {
		t.Fatal(err)
	}
	if _, err := Resolve(loop); err == nil {
		t.Fatal("Resolve accepted a symlink loop")
	}
}
