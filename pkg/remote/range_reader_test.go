package remote

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRangeReader(t *testing.T) {
	payload := bytes.Repeat([]byte("range"), 3<<20)
	for _, mode := range []string{"valid", "ignored", "wrong-range", "short", "changed"} {
		t.Run(mode, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("ETag", `"v1"`)
				if r.Method == "HEAD" {
					w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
					return
				}
				if mode == "ignored" {
					w.WriteHeader(200)
					return
				}
				var start, end int
				fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-%d", &start, &end)
				cr := fmt.Sprintf("bytes %d-%d/%d", start, end, len(payload))
				if mode == "wrong-range" {
					cr = "bytes 0-1/2"
				}
				if mode == "changed" {
					w.Header().Set("ETag", `"v2"`)
				}
				w.Header().Set("Content-Range", cr)
				w.WriteHeader(206)
				if mode == "short" {
					w.Write([]byte{0})
					return
				}
				w.Write(payload[start : end+1])
			}))
			defer s.Close()
			r, err := NewRangeReader(s.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			b := make([]byte, 100)
			_, err = r.ReadAt(b, 3)
			if mode != "valid" {
				if err == nil {
					t.Fatal("accepted invalid range")
				}
				return
			}
			if err != nil || !bytes.Equal(b, payload[3:103]) {
				t.Fatal(err)
			}
			calls, _ := r.Stats()
			r.ReadAt(b, 4)
			again, _ := r.Stats()
			if calls != again {
				t.Fatal("metadata cache miss")
			}
			for off := int64(0); off < int64(len(payload)); off += rangePageSize {
				if _, err := r.ReadAt(b, off); err != nil {
					t.Fatal(err)
				}
			}
			if r.cache.Len()*rangePageSize > rangeCacheSize {
				t.Fatal("unbounded cache")
			}
			if n, err := r.ReadAt(b, int64(len(payload)-3)); n != 3 || err != io.EOF {
				t.Fatalf("EOF: %d %v", n, err)
			}
			if _, err := r.ReadAt(b, -1); err == nil {
				t.Fatal("accepted negative offset")
			}
		})
	}
}

func TestRangeReaderRetries(t *testing.T) {
	delay := rangeRetryDelay
	t.Cleanup(func() { rangeRetryDelay = delay })
	rangeRetryDelay = time.Millisecond
	payload := bytes.Repeat([]byte("retry"), 1000)
	for _, tc := range []struct {
		name     string
		failures int
		ok       bool
	}{{"transient", rangeAttempts - 1, true}, {"persistent", rangeAttempts, false}} {
		t.Run(tc.name, func(t *testing.T) {
			gets := 0
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "HEAD" {
					w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
					return
				}
				if gets++; gets <= tc.failures {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				var start, end int
				fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-%d", &start, &end)
				w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(payload)))
				w.WriteHeader(206)
				w.Write(payload[start : end+1])
			}))
			defer s.Close()
			r, err := NewRangeReader(s.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			b := make([]byte, 10)
			_, err = r.ReadAt(b, 5)
			if (err == nil) != tc.ok || (tc.ok && !bytes.Equal(b, payload[5:15])) {
				t.Fatalf("read after %d failures: %v", tc.failures, err)
			}
			if requests, _ := r.Stats(); requests != int64(min(tc.failures+1, rangeAttempts)) {
				t.Fatalf("requests: %d", requests)
			}
		})
	}
}
