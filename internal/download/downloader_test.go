package download

import (
	"bytes"
	"context"
	"crypto/sha1"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	godl "github.com/blacktop/go-download"
)

func TestDownload(t *testing.T) {
	payload := []byte("synthetic firmware payload")
	goodSha1 := fmt.Sprintf("%x", sha1.Sum(payload))
	badSha1 := strings.Repeat("0", sha1.Size*2)

	tests := []struct {
		name       string
		cfg        Download // flag fields only; URL/Sha1/DestName are filled in
		sha1       string
		partial    string // suffix of a pre-existing partial file ("" = none)
		authClient bool   // exercise the authenticated-session transport branch
		wantErr    []string
		wantPart   bool
	}{
		{
			name: "good checksum renames file",
			cfg:  Download{},
			sha1: goodSha1,
		},
		{
			name:     "checksum mismatch retains file",
			cfg:      Download{},
			sha1:     badSha1,
			wantErr:  []string{badSha1, goodSha1},
			wantPart: true,
		},
		{
			name: "ignore sha1 renames file",
			cfg:  Download{ignoreSha1: true},
			sha1: badSha1,
		},
		{
			name:    "skip all resumes inactive partial",
			cfg:     Download{skipAll: true},
			partial: PartSuffix,
		},
		{
			name:    "restart all discards stale partial",
			cfg:     Download{restartAll: true},
			partial: PartSuffix,
		},
		{
			name:    "legacy partial is retained",
			cfg:     Download{},
			partial: legacySuffix,
		},
		{
			name:    "skip all does not skip legacy partial",
			cfg:     Download{skipAll: true},
			partial: legacySuffix,
		},
		{
			name: "invalid published sha1 downloads unverified",
			cfg:  Download{},
			sha1: "{{n/a}}",
		},
		{
			name:       "authenticated client transport is used",
			cfg:        Download{},
			authClient: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("ETag", `"v1"`)
				http.ServeContent(w, r, "test.ipsw", time.Time{}, bytes.NewReader(payload))
			}))
			t.Cleanup(server.Close)

			destName := filepath.Join(t.TempDir(), "test.ipsw")
			if tt.partial != "" {
				if err := os.WriteFile(destName+tt.partial, []byte("stale partial"), 0o600); err != nil {
					t.Fatalf("write partial: %v", err)
				}
			}
			d := tt.cfg // copy: keep the table entry pristine
			d.URL = server.URL + "/test.ipsw"
			d.Sha1 = tt.sha1
			d.DestName = destName
			if tt.authClient {
				d.client = server.Client()
			}

			_, err := d.Do()
			for _, want := range tt.wantErr {
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Fatalf("Do() error = %v, want it to contain %q", err, want)
				}
			}
			if len(tt.wantErr) == 0 && err != nil {
				t.Fatalf("Do() error = %v, want nil", err)
			}

			if len(tt.wantErr) > 0 {
				if _, err := os.Stat(destName); !os.IsNotExist(err) {
					t.Fatalf("final file stat error = %v, want file not to exist", err)
				}
				if tt.wantPart {
					if _, err := os.Stat(destName + PartSuffix); err != nil {
						t.Fatalf("staged partial stat error = %v, want mismatched bytes retained", err)
					}
				} else {
					if _, err := os.Stat(destName + PartSuffix); !os.IsNotExist(err) {
						t.Fatalf("staged partial stat error = %v, want no staged file", err)
					}
				}
				return
			}
			got, err := os.ReadFile(destName)
			if err != nil {
				t.Fatalf("read final download: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("final download = %q, want %q", got, payload)
			}
			for _, suffix := range []string{PartSuffix, StateSuffix} {
				if _, err := os.Stat(destName + suffix); !os.IsNotExist(err) {
					t.Fatalf("staging file %s%s left behind", destName, suffix)
				}
			}
			if tt.partial == legacySuffix {
				// legacy partials may be complete: never destroy user data
				if _, err := os.Stat(destName + legacySuffix); err != nil {
					t.Fatalf("legacy partial stat error = %v, want file retained", err)
				}
			}
		})
	}
}

func TestValidSHA1(t *testing.T) {
	valid := strings.Repeat("aB", sha1.Size)
	for _, test := range []struct {
		value string
		want  bool
	}{
		{value: valid, want: true},
		{value: "  " + valid + "  ", want: true},
		{value: "{{n/a}}", want: false},
		{value: strings.Repeat("g", sha1.Size*2), want: false},
		{value: strings.Repeat("0", sha1.Size*2-1), want: false},
	} {
		if got := ValidSHA1(test.value); got != test.want {
			t.Errorf("ValidSHA1(%q) = %v, want %v", test.value, got, test.want)
		}
	}
}

func TestDownloadChecksumMismatchFinalizesWithoutRefetch(t *testing.T) {
	payload := bytes.Repeat([]byte{0xa5}, 3<<20)
	goodSha1 := fmt.Sprintf("%x", sha1.Sum(payload))
	badSha1 := strings.Repeat("0", sha1.Size*2)
	var requests atomic.Int32
	var retainedStageOnly atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("ETag", `"v1"`)
		if retainedStageOnly.Load() {
			if r.Header.Get("Range") != "bytes=0-" {
				t.Errorf("corrected-checksum request Range = %q, want bytes=0-", r.Header.Get("Range"))
			}
			w.Header().Set("Accept-Ranges", "bytes")
			w.Header().Set("Content-Range", fmt.Sprintf("bytes 0-%d/%d", len(payload)-1, len(payload)))
			w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
			w.WriteHeader(http.StatusPartialContent)
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
			<-r.Context().Done()
			return
		}
		http.ServeContent(w, r, "test.ipsw", time.Time{}, bytes.NewReader(payload))
	}))
	t.Cleanup(server.Close)

	destName := filepath.Join(t.TempDir(), "test.ipsw")
	d := &Download{URL: server.URL + "/test.ipsw", Sha1: badSha1, DestName: destName}
	// keep the request count deterministic: skip the redirect preflight
	d.resolveFinalURL = func(_ context.Context, u string) (string, error) { return u, nil }
	_, err := d.Do()
	var checksumErr *godl.ChecksumError
	if !errors.As(err, &checksumErr) {
		t.Fatalf("Do() error = %v, want ChecksumError", err)
	}
	if checksumErr.Path != destName+PartSuffix {
		t.Fatalf("ChecksumError.Path = %q, want %q", checksumErr.Path, destName+PartSuffix)
	}
	for _, suffix := range []string{PartSuffix, StateSuffix} {
		if _, err := os.Stat(destName + suffix); err != nil {
			t.Fatalf("stat retained %s: %v", suffix, err)
		}
	}

	before := requests.Load()
	retainedStageOnly.Store(true)
	d.Sha1 = goodSha1
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if _, err := d.DoContext(ctx); err != nil {
		t.Fatalf("Do() with corrected checksum: %v", err)
	}
	if delta := requests.Load() - before; delta != 1 {
		t.Fatalf("corrected-checksum rerun made %d requests, want one body-free validator election", delta)
	}
	got, err := os.ReadFile(destName)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("finalized bytes differ from source")
	}
}

func TestDownloadHTMLErrorPageFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		_, _ = w.Write([]byte("<html><body>File not found</body></html>"))
	}))
	t.Cleanup(server.Close)

	destName := filepath.Join(t.TempDir(), "test.ipsw")
	d := &Download{
		URL:      server.URL + "/test.ipsw?accessKey=synthetic-secret",
		DestName: destName,
	}
	_, err := d.Do()
	if _, ok := errors.AsType[*godl.ContentTypeError](err); !ok {
		t.Fatalf("Do() error = %v, want *godl.ContentTypeError", err)
	}
	// batch runs need attribution: which URL and which file failed
	if !strings.Contains(err.Error(), destName) || !strings.Contains(err.Error(), server.URL) {
		t.Fatalf("Do() error = %v, want it to name the destination and source URL", err)
	}
	if strings.Contains(err.Error(), "synthetic-secret") {
		t.Fatalf("Do() error leaks signed query values: %v", err)
	}
	if _, statErr := os.Stat(destName); !os.IsNotExist(statErr) {
		t.Fatalf("stat %s error = %v, want dest absent so reruns retry the download", destName, statErr)
	}
	for _, suffix := range []string{".html", PartSuffix, StateSuffix} {
		if _, statErr := os.Stat(destName + suffix); !os.IsNotExist(statErr) {
			t.Fatalf("stat %s%s error = %v, want rejected response absent", destName, suffix, statErr)
		}
	}
}

func TestDownloadBatchDoesNotRetainIdleConnections(t *testing.T) {
	payload := []byte("synthetic firmware payload")
	tests := []struct {
		name  string
		setup func(*httptest.Server) (*Download, string)
	}{
		{
			name: "direct single stream",
			setup: func(server *httptest.Server) (*Download, string) {
				return NewDownload("", false, false, false, false), server.URL + "/single.ipsw"
			},
		},
		{
			name: "proxy",
			setup: func(server *httptest.Server) (*Download, string) {
				return NewDownload(server.URL, false, false, false, false), "http://firmware.invalid/test.ipsw"
			},
		},
		{
			name: "direct redirect to proxy",
			setup: func(server *httptest.Server) (*Download, string) {
				originHost := strings.TrimPrefix(server.URL, "http://")
				proxyURL := &url.URL{Scheme: "http", Host: originHost}
				d := NewDownload("", false, false, false, false)
				d.proxyFn = func(req *http.Request) (*url.URL, error) {
					if req.URL.Host == originHost {
						return nil, nil
					}
					return proxyURL, nil
				}
				return d, server.URL + "/redirect.ipsw"
			},
		},
		{
			name: "authenticated client",
			setup: func(server *httptest.Server) (*Download, string) {
				d := NewDownload("", false, false, false, false)
				d.client = server.Client()
				return d, server.URL + "/test.ipsw"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var mu sync.Mutex
			connections := make(map[net.Conn]http.ConnState)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/redirect.ipsw" {
					http.Redirect(w, r, "http://firmware.invalid/test.ipsw", http.StatusFound)
					return
				}
				if r.URL.Path == "/single.ipsw" {
					w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
					_, _ = w.Write(payload) // intentionally ignore the Range probe
					return
				}
				http.ServeContent(w, r, "test.ipsw", time.Time{}, bytes.NewReader(payload))
			}))
			server.Config.ConnState = func(conn net.Conn, state http.ConnState) {
				mu.Lock()
				defer mu.Unlock()
				if state == http.StateClosed || state == http.StateHijacked {
					delete(connections, conn)
					return
				}
				connections[conn] = state
			}
			server.Start()
			t.Cleanup(server.Close)
			t.Cleanup(server.CloseClientConnections)

			d, downloadURL := tt.setup(server)
			dir := t.TempDir()
			for i := range 40 {
				d.URL = downloadURL
				d.DestName = filepath.Join(dir, fmt.Sprintf("test-%d.ipsw", i))
				if _, err := d.Do(); err != nil {
					t.Fatalf("Do() download %d: %v", i, err)
				}
			}

			d.Close() // releases cached engine and preflight pools

			// the server observes client-side closes asynchronously
			deadline := time.Now().Add(5 * time.Second)
			openConnections := 0
			for {
				mu.Lock()
				openConnections = len(connections)
				mu.Unlock()
				if openConnections <= 2 || time.Now().After(deadline) {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			if openConnections > 2 {
				t.Fatalf("open connections after batch = %d, want at most 2", openConnections)
			}
		})
	}
}

type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("connection refused")
}

type borrowedClosingTransport struct {
	http.RoundTripper
	closes atomic.Int32
}

func (t *borrowedClosingTransport) CloseIdleConnections() {
	t.closes.Add(1)
}

func TestDownloadDoesNotCloseBorrowedTransport(t *testing.T) {
	payload := []byte("synthetic firmware payload")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "test.ipsw", time.Time{}, bytes.NewReader(payload))
	}))
	t.Cleanup(server.Close)

	transport := &borrowedClosingTransport{RoundTripper: server.Client().Transport}
	d := &Download{
		URL:      server.URL + "/test.ipsw",
		DestName: filepath.Join(t.TempDir(), "test.ipsw"),
		client:   &http.Client{Transport: transport},
	}
	if _, err := d.Do(); err != nil {
		t.Fatalf("Do() error = %v, want nil", err)
	}
	if got := transport.closes.Load(); got != 0 {
		t.Fatalf("caller-owned transport close count = %d, want 0", got)
	}
}

func TestDownloadErrorRedactsNestedSignedURL(t *testing.T) {
	d := &Download{
		URL:      "http://cdn.invalid/test.ipsw?accessKey=synthetic-secret",
		DestName: filepath.Join(t.TempDir(), "test.ipsw"),
		client:   &http.Client{Transport: failingTransport{}},
	}
	_, err := d.Do()
	if err == nil {
		t.Fatal("Do() error = nil, want transport failure")
	}
	if strings.Contains(err.Error(), "synthetic-secret") {
		t.Fatalf("Do() error leaks signed query credentials: %v", err)
	}
	if !strings.Contains(err.Error(), "/test.ipsw") {
		t.Fatalf("Do() error lost useful URL context: %v", err)
	}
}

func TestDownloadErrorRedactsOpaqueURL(t *testing.T) {
	d := &Download{
		URL:      "https:user:synthetic-secret@cdn.invalid/file.ipsw",
		DestName: filepath.Join(t.TempDir(), "test.ipsw"),
	}
	_, err := d.Do()
	if err == nil {
		t.Fatal("Do() error = nil, want malformed URL failure")
	}
	if strings.Contains(err.Error(), "synthetic-secret") {
		t.Fatalf("Do() error leaks opaque URL credentials: %v", err)
	}
}

func TestDownloadDoContextCancelsRequest(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}))
	t.Cleanup(server.Close)

	ctx, cancel := context.WithCancel(t.Context())
	d := &Download{
		URL:      server.URL + "/test.ipsw",
		DestName: filepath.Join(t.TempDir(), "test.ipsw"),
	}
	done := make(chan error, 1)
	go func() { done <- func() error { _, err := d.DoContext(ctx); return err }() }()
	<-started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("DoContext() error = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("DoContext() did not stop after parent cancellation")
	}
}

func TestDownloadUnknownSizeCompletes(t *testing.T) {
	payload := []byte("chunked payload with no content length")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // no Content-Length: chunked, size unknown
		_, _ = w.Write(payload)
	}))
	t.Cleanup(server.Close)

	destName := filepath.Join(t.TempDir(), "test.bin")
	d := &Download{
		URL:      server.URL + "/test.bin",
		DestName: destName,
	}
	if _, err := d.Do(); err != nil {
		t.Fatalf("Do() error = %v, want nil", err)
	}
	got, err := os.ReadFile(destName)
	if err != nil {
		t.Fatalf("read final download: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("final download = %q, want %q", got, payload)
	}
}
