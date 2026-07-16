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
)

func TestDownloadChecksumMismatchKeepsPartialFile(t *testing.T) {
	payload := []byte("synthetic firmware payload")
	server := newDownloadTestServer(t, payload)

	destName := filepath.Join(t.TempDir(), "test.ipsw")
	d := NewDownload("", false, false, false, false, false, false)
	d.client = server.Client()
	d.URL = server.URL
	d.Sha1 = strings.Repeat("0", sha1.Size*2)
	d.DestName = destName

	err := d.Do()
	if err == nil {
		t.Fatal("Do() error = nil, want checksum mismatch")
	}
	actual := fmt.Sprintf("%x", sha1.Sum(payload))
	if !strings.Contains(err.Error(), d.Sha1) || !strings.Contains(err.Error(), actual) {
		t.Fatalf("Do() error = %q, want expected and actual SHA-1 values", err)
	}
	if _, err := os.Stat(destName); !os.IsNotExist(err) {
		t.Fatalf("final file stat error = %v, want file not to exist", err)
	}
	got, err := os.ReadFile(destName + ".download")
	if err != nil {
		t.Fatalf("read retained download: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("retained download = %q, want %q", got, payload)
	}
}

func TestDownloadIgnoreSHA1RenamesFile(t *testing.T) {
	payload := []byte("synthetic firmware payload")
	server := newDownloadTestServer(t, payload)

	destName := filepath.Join(t.TempDir(), "test.ipsw")
	d := NewDownload("", false, false, false, false, true, false)
	d.client = server.Client()
	d.URL = server.URL
	d.Sha1 = strings.Repeat("0", sha1.Size*2)
	d.DestName = destName

	if err := d.Do(); err != nil {
		t.Fatalf("Do() error = %v, want nil", err)
	}
	got, err := os.ReadFile(destName)
	if err != nil {
		t.Fatalf("read final download: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("final download = %q, want %q", got, payload)
	}
	if _, err := os.Stat(destName + ".download"); !os.IsNotExist(err) {
		t.Fatalf("partial file stat error = %v, want file not to exist", err)
	}
}

func TestDownloadIgnoreSHA1FinalizesCompletePartial(t *testing.T) {
	payload := []byte("synthetic firmware payload")
	getRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
		w.Header().Set("Accept-Ranges", "bytes")
		if r.Method != http.MethodHead {
			getRequests++
			http.Error(w, "unexpected GET", http.StatusRequestedRangeNotSatisfiable)
		}
	}))
	defer server.Close()

	destName := filepath.Join(t.TempDir(), "test.ipsw")
	if err := os.WriteFile(destName+".download", payload, 0o600); err != nil {
		t.Fatalf("write complete partial: %v", err)
	}
	d := NewDownload("", false, false, true, false, true, false)
	d.client = server.Client()
	d.URL = server.URL
	d.Sha1 = strings.Repeat("0", sha1.Size*2)
	d.DestName = destName

	if err := d.Do(); err != nil {
		t.Fatalf("Do() error = %v, want nil", err)
	}
	if getRequests != 0 {
		t.Fatalf("GET requests = %d, want 0", getRequests)
	}
	got, err := os.ReadFile(destName)
	if err != nil {
		t.Fatalf("read finalized download: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("finalized download = %q, want %q", got, payload)
	}
}

func TestDownloadResetsResumeStateBeforeReuse(t *testing.T) {
	oldPayload := []byte("old synthetic payload")
	newPayload := []byte("new synthetic payload")
	getRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(len(newPayload)))
		if r.Method != http.MethodHead {
			getRequests++
			_, _ = w.Write(newPayload)
		}
	}))
	defer server.Close()

	destName := filepath.Join(t.TempDir(), "test.ipsw")
	if err := os.WriteFile(destName+".download", oldPayload, 0o600); err != nil {
		t.Fatalf("write stale partial: %v", err)
	}
	d := NewDownload("", false, false, true, false, true, false)
	d.client = server.Client()
	d.URL = server.URL
	d.DestName = destName
	d.size = int64(len(oldPayload))
	d.bytesResumed = int64(len(oldPayload))
	d.canResume = true

	if err := d.Do(); err != nil {
		t.Fatalf("Do() error = %v, want nil", err)
	}
	if getRequests != 1 {
		t.Fatalf("GET requests = %d, want 1", getRequests)
	}
	got, err := os.ReadFile(destName)
	if err != nil {
		t.Fatalf("read final download: %v", err)
	}
	if !bytes.Equal(got, newPayload) {
		t.Fatalf("final download = %q, want %q", got, newPayload)
	}
}

func newDownloadTestServer(t *testing.T, payload []byte) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
		if r.Method != http.MethodHead {
			_, _ = w.Write(payload)
		}
	}))
	t.Cleanup(server.Close)
	return server
}
