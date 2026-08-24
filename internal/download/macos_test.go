package download

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDownloadInstallerUsesMetadataURL(t *testing.T) {
	payload := []byte("synthetic installer metadata")
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.ServeContent(w, r, "InstallAssistant.pkg", time.Time{}, bytes.NewReader(payload))
	}))
	t.Cleanup(server.Close)

	info := ProductInfo{
		Title:   "Synthetic",
		Version: "1.0",
		Build:   "A1",
		Product: Product{Packages: []Package{{
			MetadataURL: server.URL + "/InstallAssistant.pkg",
			Digest:      "metadata-digest-does-not-leak",
		}}},
	}
	workDir := t.TempDir()
	if err := info.DownloadInstallerContext(t.Context(), workDir, "", false, false, false, true); err != nil {
		t.Fatal(err)
	}
	if hits.Load() == 0 {
		t.Fatal("metadata URL was not requested")
	}
	got, err := os.ReadFile(filepath.Join(workDir, "Synthetic_1.0_A1", "InstallAssistant.pkg"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("downloaded metadata = %q, want %q", got, payload)
	}
}

func TestDownloadInstallerRejectsExistingCorruptPackage(t *testing.T) {
	want := []byte("expected package")
	integrityData := makeSHA256Chunklist(t, want)
	var packageHits atomic.Int32
	var integrityHits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/InstallAssistant.pkg":
			packageHits.Add(1)
			_, _ = w.Write(want)
		case "/integrity":
			integrityHits.Add(1)
			_, _ = w.Write(integrityData)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	info := ProductInfo{
		Title:   "Synthetic",
		Version: "1.0",
		Build:   "A1",
		Product: Product{Packages: []Package{{
			URL:              server.URL + "/InstallAssistant.pkg",
			IntegrityDataURL: server.URL + "/integrity",
		}}},
	}
	workDir := t.TempDir()
	packagePath := filepath.Join(workDir, "Synthetic_1.0_A1", "InstallAssistant.pkg")
	if err := os.MkdirAll(filepath.Dir(packagePath), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(packagePath, []byte("corrupt package!"), 0600); err != nil {
		t.Fatal(err)
	}

	err := info.DownloadInstallerContext(t.Context(), workDir, "", false, false, false, true)
	if err == nil || !strings.Contains(err.Error(), "integrity check failed") {
		t.Fatalf("DownloadInstallerContext error = %v, want integrity failure", err)
	}
	if packageHits.Load() != 0 {
		t.Fatalf("package endpoint hits = %d, want existing file to be checked before redownload", packageHits.Load())
	}
	if integrityHits.Load() != 1 {
		t.Fatalf("integrity endpoint hits = %d, want 1", integrityHits.Load())
	}
	if _, err := os.Stat(packagePath); !os.IsNotExist(err) {
		t.Fatalf("invalid package remains on disk: %v", err)
	}
}

func TestDownloadInstallerPreservesPackageWhenChunklistIsInvalid(t *testing.T) {
	want := []byte("valid package")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/integrity" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("invalid chunklist"))
	}))
	t.Cleanup(server.Close)

	info := ProductInfo{
		Title:   "Synthetic",
		Version: "1.0",
		Build:   "A1",
		Product: Product{Packages: []Package{{
			URL:              server.URL + "/InstallAssistant.pkg",
			IntegrityDataURL: server.URL + "/integrity",
		}}},
	}
	workDir := t.TempDir()
	packagePath := filepath.Join(workDir, "Synthetic_1.0_A1", "InstallAssistant.pkg")
	if err := os.MkdirAll(filepath.Dir(packagePath), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(packagePath, want, 0600); err != nil {
		t.Fatal(err)
	}

	err := info.DownloadInstallerContext(t.Context(), workDir, "", false, false, false, true)
	if err == nil || !strings.Contains(err.Error(), "chunklist") {
		t.Fatalf("DownloadInstallerContext error = %v, want chunklist failure", err)
	}
	got, err := os.ReadFile(packagePath)
	if err != nil {
		t.Fatalf("valid package was removed: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("package = %q, want %q", got, want)
	}
}
