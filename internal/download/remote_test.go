package download

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNormalizeRemoteZipBlockSize(t *testing.T) {
	tests := []struct {
		name      string
		blockSize int
		want      int
	}{
		{name: "unset", blockSize: 0, want: DefaultRemoteZipBlockSize},
		{name: "negative", blockSize: -1, want: DefaultRemoteZipBlockSize},
		{name: "tiny", blockSize: 1, want: DefaultRemoteZipBlockSize},
		{name: "default", blockSize: DefaultRemoteZipBlockSize, want: DefaultRemoteZipBlockSize},
		{name: "custom", blockSize: 4 * 1024 * 1024, want: 4 * 1024 * 1024},
		{name: "too large", blockSize: math.MaxInt, want: LargeRemoteZipBlockSize},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := NormalizeRemoteZipBlockSize(test.blockSize); got != test.want {
				t.Fatalf("NormalizeRemoteZipBlockSize(%d) = %d, want %d", test.blockSize, got, test.want)
			}
		})
	}
}

func TestRemoteZipBlockSizeForMemberSize(t *testing.T) {
	tests := []struct {
		name string
		size uint64
		want int
	}{
		{name: "tiny", size: 1024, want: DefaultRemoteZipBlockSize},
		{name: "one megabyte", size: 1 * 1024 * 1024, want: DefaultRemoteZipBlockSize},
		{name: "small", size: 2 * 1024 * 1024, want: smallRemoteZipBlockSize},
		{name: "medium", size: 12 * 1024 * 1024, want: mediumRemoteZipBlockSize},
		{name: "large", size: 64 * 1024 * 1024, want: LargeRemoteZipBlockSize},
		{name: "huge", size: 1024 * 1024 * 1024, want: LargeRemoteZipBlockSize},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := RemoteZipBlockSizeForMemberSize(test.size); got != test.want {
				t.Fatalf("RemoteZipBlockSizeForMemberSize(%d) = %d, want %d", test.size, got, test.want)
			}
		})
	}
}

func TestNewRemoteZipReaderUsesConfiguredBlockSize(t *testing.T) {
	spans := readRemoteZipMemberRangeSpans(t, smallRemoteZipBlockSize)
	if !hasBlockMultiple(spans, smallRemoteZipBlockSize) {
		t.Fatalf("range spans %v do not include a multiple of configured block size %d", spans, smallRemoteZipBlockSize)
	}
}

func TestNewRemoteZipReaderClampsTinyBlockSize(t *testing.T) {
	spans := readRemoteZipMemberRangeSpans(t, 1)
	if !hasBlockMultiple(spans, DefaultRemoteZipBlockSize) {
		t.Fatalf("range spans %v do not include a multiple of default block size %d", spans, DefaultRemoteZipBlockSize)
	}
}

func readRemoteZipMemberRangeSpans(t *testing.T, blockSize int) []int64 {
	t.Helper()

	var zipData bytes.Buffer
	zw := zip.NewWriter(&zipData)
	w, err := zw.CreateHeader(&zip.FileHeader{
		Name:   "payload.bin",
		Method: zip.Store,
	})
	if err != nil {
		t.Fatalf("create zip member: %v", err)
	}
	payload := bytes.Repeat([]byte("A"), 2*1024*1024)
	if _, err := w.Write(payload); err != nil {
		t.Fatalf("write zip member: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}

	var (
		mu    sync.Mutex
		spans []int64
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"remote-test"`)
		rangeSpans, err := parseRangeSpans(r.Header.Get("Range"), int64(zipData.Len()))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if len(rangeSpans) > 0 {
			mu.Lock()
			spans = append(spans, rangeSpans...)
			mu.Unlock()
		}
		http.ServeContent(w, r, "payload.zip", time.Unix(0, 0), bytes.NewReader(zipData.Bytes()))
	}))
	defer server.Close()

	zr, err := NewRemoteZipReader(server.URL, &RemoteConfig{BlockSize: blockSize})
	if err != nil {
		t.Fatalf("NewRemoteZipReader: %v", err)
	}
	if len(zr.File) != 1 {
		t.Fatalf("zip file count = %d, want 1", len(zr.File))
	}
	rc, err := zr.File[0].Open()
	if err != nil {
		t.Fatalf("open zip member: %v", err)
	}
	defer rc.Close()
	if _, err := io.ReadAll(rc); err != nil {
		t.Fatalf("read zip member: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	return append([]int64(nil), spans...)
}

func hasBlockMultiple(spans []int64, blockSize int) bool {
	for _, span := range spans {
		if span >= int64(blockSize) && span%int64(blockSize) == 0 {
			return true
		}
	}
	return false
}

func parseRangeSpans(header string, length int64) ([]int64, error) {
	if header == "" {
		return nil, nil
	}
	value, ok := strings.CutPrefix(header, "bytes=")
	if !ok {
		return nil, fmt.Errorf("unsupported range %q", header)
	}
	parts := strings.Split(value, ",")
	spans := make([]int64, 0, len(parts))
	for _, part := range parts {
		start, end, err := parseRangeSpan(strings.TrimSpace(part), length)
		if err != nil {
			return nil, err
		}
		spans = append(spans, end-start+1)
	}
	return spans, nil
}

func parseRangeSpan(value string, length int64) (int64, int64, error) {
	startText, endText, ok := strings.Cut(value, "-")
	if !ok {
		return 0, 0, fmt.Errorf("bad range %q", value)
	}
	var start int64
	var err error
	if startText == "" {
		suffix, err := strconv.ParseInt(endText, 10, 64)
		if err != nil {
			return 0, 0, fmt.Errorf("bad suffix range: %w", err)
		}
		start = length - suffix
		endText = ""
	} else {
		start, err = strconv.ParseInt(startText, 10, 64)
		if err != nil {
			return 0, 0, fmt.Errorf("bad range start: %w", err)
		}
	}

	end := length - 1
	if endText != "" {
		end, err = strconv.ParseInt(endText, 10, 64)
		if err != nil {
			return 0, 0, fmt.Errorf("bad range end: %w", err)
		}
	}
	if end >= length {
		end = length - 1
	}
	if start < 0 || start > end {
		return 0, 0, fmt.Errorf("invalid range %q", value)
	}
	return start, end, nil
}
