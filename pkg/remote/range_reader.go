// Package remote reads the disk images of a remote IPSW through HTTP range
// requests, without downloading or mounting them.
package remote

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/utils"
	lru "github.com/hashicorp/golang-lru/v2"
)

// Config selects the HTTP client of a RangeReader.
type Config struct {
	Proxy    string
	Insecure bool
	// Client overrides Proxy/Insecure when set and is safe to share across
	// readers for connection reuse.
	Client *http.Client
}

// RangeReader is a bounded, immutable HTTP ReaderAt. Unlike the ZIP reader's
// sequential-download cache, it is intended for sparse filesystem access.
// A mutex serializes requests and protects the page LRU.
type RangeReader struct {
	mu                    sync.Mutex
	client                *http.Client
	url, agent            string
	size                  int64
	etag                  string
	cache                 *lru.Cache[int64, []byte] // page offset -> page
	requests, transferred int64
}

// rangeRetryDelay is scaled by the attempt number.
var rangeRetryDelay = 500 * time.Millisecond

const (
	rangePageSize   = 64 << 10
	rangeCacheSize  = 8 << 20
	rangeMaxRequest = 4 << 20 // keeps one request within rangeTimeout on slow links
	rangeTimeout    = 2 * time.Minute
	rangeAttempts   = 3
)

// NewRangeReader asks url for its size with a HEAD request. A nil config uses
// a default client.
func NewRangeReader(url string, config *Config) (*RangeReader, error) {
	if config == nil {
		config = &Config{}
	}
	client := config.Client
	if client == nil {
		client = download.NewRemoteHTTPClient(config.Proxy, config.Insecure)
	}
	req, err := http.NewRequest(http.MethodHead, url, nil)
	if err != nil {
		return nil, err
	}
	agent := utils.RandomAgent()
	req.Header.Set("User-Agent", agent)
	req.Header.Set("Accept-Encoding", "identity")
	// Keep the shared client's transport and redirect policy without changing it.
	bounded := *client
	bounded.Timeout = rangeTimeout
	resp, err := bounded.Do(req)
	if err != nil {
		if errors.Is(err, download.ErrDevPortalAuthRequired) {
			return nil, download.ErrDevPortalAuthRequired
		}
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.ContentLength <= 0 {
		return nil, fmt.Errorf("remote image size unavailable: %s", resp.Status)
	}
	etag := resp.Header.Get("ETag")
	if len(etag) > 2 && etag[:2] == "W/" {
		etag = ""
	}
	cache, err := lru.New[int64, []byte](rangeCacheSize / rangePageSize)
	if err != nil {
		return nil, err
	}
	return &RangeReader{client: &bounded, url: url, agent: agent, size: resp.ContentLength, etag: etag, cache: cache}, nil
}

// Size is the length of the remote file.
func (r *RangeReader) Size() int64 { return r.size }

// Stats reports the range requests made so far and the bytes they returned.
func (r *RangeReader) Stats() (requests, bytes int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.requests, r.transferred
}

// fetch fills dst with the bytes at offset. Transport failures and transient
// server errors are retried; a response that contradicts the request is not.
func (r *RangeReader) fetch(offset int64, dst []byte) error {
	for attempt := 1; ; attempt++ {
		retry, err := r.fetchOnce(offset, dst)
		if err == nil || !retry || attempt == rangeAttempts {
			return err
		}
		time.Sleep(time.Duration(attempt) * rangeRetryDelay)
	}
}

func (r *RangeReader) fetchOnce(offset int64, dst []byte) (retry bool, err error) {
	size := len(dst)
	req, err := http.NewRequest(http.MethodGet, r.url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("User-Agent", r.agent)
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", offset, offset+int64(size)-1))
	if r.etag != "" {
		req.Header.Set("If-Match", r.etag)
	}
	r.requests++
	resp, err := r.client.Do(req)
	if err != nil {
		return !errors.Is(err, download.ErrDevPortalAuthRequired), err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusRequestTimeout {
		return true, fmt.Errorf("HTTP range request failed: %s", resp.Status)
	}
	want := fmt.Sprintf("bytes %d-%d/%d", offset, offset+int64(size)-1, r.size)
	if resp.StatusCode != http.StatusPartialContent || resp.Header.Get("Content-Range") != want ||
		(resp.ContentLength >= 0 && resp.ContentLength != int64(size)) ||
		(r.etag != "" && resp.Header.Get("ETag") != "" && resp.Header.Get("ETag") != r.etag) ||
		(resp.Header.Get("Content-Encoding") != "" && resp.Header.Get("Content-Encoding") != "identity") {
		return false, fmt.Errorf("invalid HTTP range response: %s, Content-Range=%q, expected %q", resp.Status, resp.Header.Get("Content-Range"), want)
	}
	n, err := io.ReadFull(resp.Body, dst)
	r.transferred += int64(n)
	if err != nil {
		return true, fmt.Errorf("truncated range body: %d != %d: %v", n, size, err)
	}
	if extra, _ := resp.Body.Read(make([]byte, 1)); extra > 0 {
		r.transferred += int64(extra)
		return false, fmt.Errorf("oversized range body: expected %d bytes", size)
	}
	return false, nil
}
func (r *RangeReader) ReadAt(p []byte, off int64) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if off < 0 {
		return 0, fmt.Errorf("negative read offset: %d", off)
	}
	n := 0
	for n < len(p) && off < r.size {
		// Large reads are contiguous payload and bypass the metadata page cache.
		if len(p)-n > rangePageSize {
			size := int(min(int64(len(p)-n), r.size-off, rangeMaxRequest))
			if err := r.fetch(off, p[n:n+size]); err != nil {
				return n, err
			}
			off += int64(size)
			n += size
			continue
		}
		page := off / int64(rangePageSize) * int64(rangePageSize)
		data, ok := r.cache.Get(page)
		if !ok {
			data = make([]byte, min(int64(rangePageSize), r.size-page))
			if err := r.fetch(page, data); err != nil {
				return n, err
			}
			r.cache.Add(page, data)
		}
		count := copy(p[n:], data[off-page:])
		n += count
		off += int64(count)
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
