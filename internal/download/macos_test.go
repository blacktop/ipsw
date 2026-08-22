package download

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
