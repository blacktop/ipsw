//go:build unix

package testutil

import (
	"errors"
	"os"
	"sync"
	"syscall"
	"testing"
)

// ExhaustFDs lowers the descriptor limit and opens files until none are left.
// Call the returned func before asserting: it closes them and restores the
// limit, so the test can report again.
func ExhaustFDs(t testing.TB) (release func()) {
	t.Helper()
	var limit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
		t.Fatal(err)
	}
	lowered := limit
	lowered.Cur = 64
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lowered); err != nil {
		t.Fatal(err)
	}
	var held []*os.File
	release = sync.OnceFunc(func() {
		for _, f := range held {
			f.Close()
		}
		if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
			t.Errorf("failed to restore descriptor limit: %v", err)
		}
	})
	t.Cleanup(release)
	for {
		f, err := os.Open(os.DevNull)
		if errors.Is(err, syscall.EMFILE) {
			return release
		}
		if err != nil {
			release()
			t.Fatalf("failed to exhaust descriptors: %v", err)
		}
		held = append(held, f)
	}
}
