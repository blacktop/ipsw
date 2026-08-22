//go:build !ios && (darwin || dragonfly || freebsd || linux || netbsd || openbsd)

package download

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestAppStorePatchLockSerializes(t *testing.T) {
	if path := os.Getenv("IPSW_TEST_APPSTORE_PATCH_LOCK"); path != "" {
		fmt.Println("ready")
		unlock, err := acquireAppStorePatchLock(t.Context(), path, true)
		if err != nil {
			t.Fatal(err)
		}
		defer unlock()
		fmt.Println("acquired")
		return
	}

	path := filepath.Join(t.TempDir(), "app.ipa.lock")
	unlockFirst, err := acquireAppStorePatchLock(t.Context(), path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if unlockFirst != nil {
			unlockFirst()
		}
	}()

	cmd := exec.Command(os.Args[0], "-test.run", "^TestAppStorePatchLockSerializes$")
	cmd.Env = append(os.Environ(), "IPSW_TEST_APPSTORE_PATCH_LOCK="+path)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()

	lines := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
		close(lines)
	}()
	select {
	case line := <-lines:
		if line != "ready" {
			t.Fatalf("helper output = %q, want ready", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("lock helper did not become ready")
	}

	select {
	case line := <-lines:
		t.Fatalf("second lock acquired before the first was released: %q", line)
	case <-time.After(150 * time.Millisecond):
	}

	unlockFirst()
	unlockFirst = nil
	select {
	case line := <-lines:
		if line != "acquired" {
			t.Fatalf("helper output = %q, want acquired", line)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second lock did not acquire after release")
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestAppStorePatchLockHonorsCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.ipa.lock")
	unlock, err := acquireAppStorePatchLock(t.Context(), path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := acquireAppStorePatchLock(ctx, path, true); err == nil {
		t.Fatal("contended lock ignored cancellation")
	}
}

func TestAppStorePatchLockNonBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.ipa.lock")
	unlock, err := acquireAppStorePatchLock(t.Context(), path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()

	if _, err := acquireAppStorePatchLock(t.Context(), path, false); !errors.Is(err, errAppStorePatchLocked) {
		t.Fatalf("nonblocking lock error = %v, want errAppStorePatchLocked", err)
	}
}
