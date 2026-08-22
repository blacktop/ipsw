//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package download

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	godl "github.com/blacktop/go-download"
)

func TestDownloadSkipAllOnlySkipsActiveLock(t *testing.T) {
	payload := []byte("synthetic firmware payload")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		http.ServeContent(w, r, "test.ipsw", time.Time{}, bytes.NewReader(payload))
	}))
	t.Cleanup(server.Close)

	destName := filepath.Join(t.TempDir(), "test.ipsw")
	lockDownloadStage(t, destName)

	d := &Download{URL: server.URL + "/test.ipsw", DestName: destName}
	if _, err := d.Do(); !errors.Is(err, godl.ErrLocked) {
		t.Fatalf("Do() error = %v, want ErrLocked", err)
	}

	d.skipAll = true
	status, err := d.Do()
	if err != nil {
		t.Fatalf("Do() with skip-all error = %v, want nil", err)
	}
	if status != Skipped {
		t.Fatalf("Do() with skip-all status = %v, want Skipped", status)
	}
	d.restartAll = true
	if status, err := d.Do(); err != nil || status != Skipped {
		t.Fatalf("Do() with restart-all and skip-all = (%v, %v), want (Skipped, nil)", status, err)
	}
	if _, err := os.Stat(destName); !os.IsNotExist(err) {
		t.Fatalf("destination stat error = %v, want absent while another download owns the stage", err)
	}
}

func TestDownloadSkipAllRestartFailsClosedWhenLockProbeFails(t *testing.T) {
	dir := t.TempDir()
	destName := filepath.Join(dir, "test.ipsw")
	if err := os.WriteFile(destName+PartSuffix, []byte("active stage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	d := &Download{
		URL:        "https://example.invalid/test.ipsw",
		DestName:   destName,
		skipAll:    true,
		restartAll: true,
	}
	status, err := d.DoContext(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if status != Skipped {
		t.Fatalf("DoContext() status = %v, want Skipped", status)
	}
	if _, err := os.Stat(destName + PartSuffix); err != nil {
		t.Fatalf("active stage was not preserved: %v", err)
	}
}

func TestDownloadInstallerDoesNotVerifySkippedPackage(t *testing.T) {
	payload := []byte("synthetic installer package")
	var integrityHits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/integrity" {
			integrityHits.Add(1)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		http.ServeContent(w, r, "InstallAssistant.pkg", time.Time{}, bytes.NewReader(payload))
	}))
	t.Cleanup(server.Close)

	workDir := t.TempDir()
	folder := filepath.Join(workDir, "Synthetic_1.0_A1")
	if err := os.MkdirAll(folder, 0o750); err != nil {
		t.Fatal(err)
	}
	destName := filepath.Join(folder, "InstallAssistant.pkg")
	lockDownloadStage(t, destName)

	info := ProductInfo{
		Title:   "Synthetic",
		Version: "1.0",
		Build:   "A1",
		Product: Product{Packages: []Package{{
			URL:              server.URL + "/InstallAssistant.pkg",
			IntegrityDataURL: server.URL + "/integrity",
		}}},
	}
	if err := info.DownloadInstallerContext(t.Context(), workDir, "", false, true, false, true); err != nil {
		t.Fatalf("DownloadInstallerContext() error = %v, want nil", err)
	}
	if got := integrityHits.Load(); got != 0 {
		t.Fatalf("integrity endpoint hits = %d, want 0 for a skipped package", got)
	}
}

func lockDownloadStage(t *testing.T, destName string) {
	t.Helper()
	owner, err := os.OpenFile(destName+PartSuffix, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	if err := syscall.Flock(int(owner.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
}
