package download

import (
	"bytes"
	"crypto/sha1"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	internaldownload "github.com/blacktop/ipsw/internal/download"
)

func TestRunIPSWDownloadDispatchesAndRecordsVerifiedChecksum(t *testing.T) {
	payload := []byte("synthetic firmware payload")
	sum := fmt.Sprintf("%x", sha1.Sum(payload))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		http.ServeContent(w, r, "test.ipsw", time.Time{}, bytes.NewReader(payload))
	}))
	t.Cleanup(server.Close)

	t.Chdir(t.TempDir())
	destName := filepath.Join("downloads", "test.ipsw")
	if err := os.MkdirAll(filepath.Dir(destName), 0o755); err != nil {
		t.Fatal(err)
	}
	downloader := internaldownload.NewDownload("", false, false, false, false)
	downloader.URL = server.URL + "/test.ipsw"
	downloader.Sha1 = sum
	downloader.DestName = destName

	created, err := runIPSWDownload(t.Context(), downloader, sum, destName, true)
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("runIPSWDownload() created = false, want true")
	}
	got, err := os.ReadFile(destName)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("downloaded bytes = %q, want %q", got, payload)
	}
	checksums, err := os.ReadFile(sha1ChecksumsFile)
	if err != nil {
		t.Fatal(err)
	}
	want := sum + "  " + destName + "\n"
	if string(checksums) != want {
		t.Fatalf("checksum record = %q, want %q", checksums, want)
	}
}

func TestAppendSHA1Checksum(t *testing.T) {
	t.Run("valid digest", func(t *testing.T) {
		t.Chdir(t.TempDir())
		sum := strings.Repeat("A", 40)
		if err := appendSHA1Checksum("  "+sum+"  ", "file.ipsw"); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(sha1ChecksumsFile)
		if err != nil {
			t.Fatal(err)
		}
		want := strings.ToLower(sum) + "  file.ipsw\n"
		if string(got) != want {
			t.Fatalf("checksum record = %q, want %q", got, want)
		}
	})

	t.Run("invalid digest", func(t *testing.T) {
		t.Chdir(t.TempDir())
		if err := appendSHA1Checksum("{{n/a}}", "file.ipsw"); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(sha1ChecksumsFile); !os.IsNotExist(err) {
			t.Fatalf("stat checksum file error = %v, want file absent", err)
		}
	})
}
