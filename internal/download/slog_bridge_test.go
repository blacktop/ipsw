package download

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/apex/log"
	"github.com/apex/log/handlers/memory"
)

func captureApexLog(t *testing.T, level log.Level) *memory.Handler {
	t.Helper()
	previous := log.Log
	handler := memory.New()
	log.Log = &log.Logger{Handler: handler, Level: level}
	t.Cleanup(func() { log.Log = previous })
	return handler
}

func TestEngineLoggerBridgesMeasurementsAtDebug(t *testing.T) {
	handler := captureApexLog(t, log.DebugLevel)

	logger := engineLogger().With("url", "https://cdn.invalid/file.ipsw?accessKey=synthetic-secret")
	logger.Debug("election", "parts", 8, "protocol", "http/1.1")

	if len(handler.Entries) != 1 {
		t.Fatalf("bridged entries = %d, want 1", len(handler.Entries))
	}
	entry := handler.Entries[0]
	if entry.Message != "godl: election" {
		t.Fatalf("message = %q, want godl: election", entry.Message)
	}
	if got := entry.Fields["parts"]; fmt.Sprint(got) != "8" {
		t.Fatalf("parts field = %v, want 8", got)
	}
	url, _ := entry.Fields["url"].(string)
	if strings.Contains(url, "synthetic-secret") {
		t.Fatalf("bridged url leaks signed query values: %s", url)
	}
	if !strings.Contains(url, "cdn.invalid") {
		t.Fatalf("bridged url lost its host: %s", url)
	}
}

func TestEngineLoggerSilentBelowDebug(t *testing.T) {
	handler := captureApexLog(t, log.InfoLevel)

	engineLogger().Debug("election", "parts", 8)
	engineLogger().Info("resume", "bytes", 42)

	if len(handler.Entries) != 0 {
		t.Fatalf("bridged entries at info level = %d, want 0", len(handler.Entries))
	}
}

func TestDownloadSHA256Verification(t *testing.T) {
	payload := []byte("synthetic kdk payload")
	goodSHA256 := fmt.Sprintf("%x", sha256.Sum256(payload))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		http.ServeContent(w, r, "kdk.dmg", time.Time{}, bytes.NewReader(payload))
	}))
	t.Cleanup(server.Close)

	run := func(t *testing.T, d *Download, sha string) (Status, error, string) {
		t.Helper()
		dest := filepath.Join(t.TempDir(), "kdk.dmg")
		status, err := d.DoRequestContext(t.Context(), &FileRequest{
			URL: server.URL + "/kdk.dmg", SHA256: sha, DestName: dest,
		})
		return status, err, dest
	}

	t.Run("match", func(t *testing.T) {
		d := &Download{}
		t.Cleanup(d.Close)
		status, err, dest := run(t, d, goodSHA256)
		if err != nil || status != Downloaded {
			t.Fatalf("DoRequestContext = (%v, %v), want (Downloaded, nil)", status, err)
		}
		body, err := os.ReadFile(dest)
		if err != nil || !bytes.Equal(body, payload) {
			t.Fatalf("downloaded bytes differ from source (%v)", err)
		}
	})

	t.Run("mismatch retains stage", func(t *testing.T) {
		d := &Download{}
		t.Cleanup(d.Close)
		_, err, dest := run(t, d, strings.Repeat("0", sha256.Size*2))
		if err == nil {
			t.Fatal("mismatched SHA-256 did not fail the download")
		}
		if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
			t.Fatalf("dest stat = %v, want mismatched file not installed", statErr)
		}
		if _, statErr := os.Stat(dest + PartSuffix); statErr != nil {
			t.Fatalf("staged partial stat = %v, want bytes retained", statErr)
		}
	})

	t.Run("invalid digest downloads unverified", func(t *testing.T) {
		d := &Download{}
		t.Cleanup(d.Close)
		status, err, _ := run(t, d, "{{n/a}}")
		if err != nil || status != Downloaded {
			t.Fatalf("DoRequestContext = (%v, %v), want unverified success", status, err)
		}
	})

	t.Run("ignore flag disables verification", func(t *testing.T) {
		d := &Download{ignoreSha1: true}
		t.Cleanup(d.Close)
		status, err, _ := run(t, d, strings.Repeat("0", sha256.Size*2))
		if err != nil || status != Downloaded {
			t.Fatalf("DoRequestContext = (%v, %v), want success with verification disabled", status, err)
		}
	})
}

func TestValidSHA256(t *testing.T) {
	valid := strings.Repeat("aB", sha256.Size)
	for _, test := range []struct {
		value string
		want  bool
	}{
		{value: valid, want: true},
		{value: "  " + valid + "  ", want: true},
		{value: "{{n/a}}", want: false},
		{value: strings.Repeat("0", sha256.Size*2-1), want: false},
		{value: strings.Repeat("g", sha256.Size*2), want: false},
	} {
		if got := ValidSHA256(test.value); got != test.want {
			t.Errorf("ValidSHA256(%q) = %v, want %v", test.value, got, test.want)
		}
	}
}
