package ranger

import (
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

const httpMethodGet = "GET"
const httpHeaderAcceptRanges = "Accept-Ranges"
const httpHeaderContentType = "Content-Type"
const httpHeaderIfRange = "If-Range"
const httpHeaderLastModified = "Last-Modified"
const httpHeaderRange = "Range"
const mimeMultipartByteranges = "multipart/byteranges"

// HTTPClient is an interface describing the methods required from net/http.Client
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
	Get(string) (*http.Response, error)
	Head(string) (*http.Response, error)
}

// HTTPRanger is a RangeFetcher that uses the HTTP Range: header to fetch blocks.
//
// HTTPRanger first makes a HEAD request and then between 0 and Length()/BlockSize GET requests, attempting
// whenever possible to optimize for a lower number of requests.
//
// No network requests are made until the first I/O-related function call.
type HTTPRanger struct {
	URL    *url.URL
	Client HTTPClient

	validator string
	length    int64

	once sync.Once
}

func statusCodeError(status int) error {
	return fmt.Errorf("unexpected response (status %d)", status)
}

func statusIsAcceptable(status int) bool {
	return status >= 200 && status < 300
}

func validatorFromResponse(resp *http.Response) (string, error) {
	etag := resp.Header.Get("ETag")
	if etag != "" && etag[0] == '"' {
		return etag, nil
	}

	modtime := resp.Header.Get(httpHeaderLastModified)
	if modtime != "" {
		return modtime, nil
	}

	return "", errors.New("no applicable validator in response")
}

// init performs a HEAD request to determine whether the resource is rangeable.
func (r *HTTPRanger) init() error {
	var outerErr error
	r.once.Do(func() {
		if r.Client == nil {
			r.Client = &http.Client{}
		}

		resp, err := r.Client.Head(r.URL.String())
		if err != nil {
			outerErr = err
			return
		}

		if !statusIsAcceptable(resp.StatusCode) {
			outerErr = statusCodeError(resp.StatusCode)
			return
		}

		if !strings.Contains(resp.Header.Get(httpHeaderAcceptRanges), "bytes") {
			outerErr = errors.New(r.URL.String() + " does not support byte-ranged requests.")
			return
		}

		validator, err := validatorFromResponse(resp)
		if err != nil {
			outerErr = errors.New(r.URL.String() + " did not offer a strong-enough validator for subsequent requests")
			return
		}

		r.validator = validator
		r.length = resp.ContentLength
	})
	return outerErr
}

// ExpectedLength returns the length, in bytes, of the ranged-over file.
func (r *HTTPRanger) ExpectedLength() (int64, error) {
	err := r.init()
	return r.length, err
}

func makeByteRangeHeader(ranges []ByteRange) string {
	if len(ranges) > 0 {
		ranges = coalesceAdjacentRanges(ranges)
		rs := make([]string, len(ranges))
		for i, rng := range ranges {
			rs[i] = fmt.Sprintf("%d-%d", rng.Start, rng.End)
		}
		return "bytes=" + strings.Join(rs, ",")
	}
	return ""
}

func (r *HTTPRanger) validateResponse(resp *http.Response) error {
	switch resp.StatusCode {
	case http.StatusPreconditionFailed:
		return ErrResourceChanged
	case http.StatusNotFound:
		return ErrResourceNotFound
	}

	if !statusIsAcceptable(resp.StatusCode) {
		return statusCodeError(resp.StatusCode)
	}
	newValidator, err := validatorFromResponse(resp)
	if err != nil || newValidator != r.validator {
		return ErrResourceChanged
	}
	return nil
}

// FetchRanges requests ranges from the HTTP server.
func (r *HTTPRanger) FetchRanges(ranges []ByteRange) ([]Block, error) {
	if len(ranges) == 0 {
		return nil, nil
	}

	err := r.init()
	if err != nil {
		return nil, err
	}

	req := &http.Request{
		Method: httpMethodGet,
		URL:    r.URL,
		Header: http.Header{
			httpHeaderRange:   []string{makeByteRangeHeader(ranges)},
			httpHeaderIfRange: []string{r.validator},
		},
	}

	resp, err := r.Client.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() { _ = resp.Body.Close() }()

	err = r.validateResponse(resp)
	if err != nil {
		return nil, err
	}

	typ, params, err := mime.ParseMediaType(resp.Header.Get(httpHeaderContentType))
	if err != nil {
		return nil, err
	}

	blox := make([]Block, len(ranges))
	for i, v := range ranges {
		blox[i].Length = v.End - v.Start + 1
	}

	var n int
	if typ == mimeMultipartByteranges {
		multipart := multipart.NewReader(resp.Body, params["boundary"])
		n, err = fillBlocksFromMultipartReader(blox, multipart)
	} else {
		n, err = fillBlocksFromContiguousReader(blox, resp.Body)
	}

	if err != nil {
		return nil, err
	}

	if n != len(blox) {
		return nil, fmt.Errorf("http: expected to get %d content blocks back, but only got %d", len(blox), n)
	}

	return blox, nil
}

func fillBlocksFromMultipartReader(blox []Block, mp *multipart.Reader) (c int, err error) {
	for {
		var p *multipart.Part
		p, err = mp.NextPart()
		if err != nil {
			break
		}

		var n int
		n, err = fillBlocksFromContiguousReader(blox[c:], p)
		if err != nil {
			break
		}

		c += n
	}

	// EOFs bubble up as the number of blocks read being short, so we'll
	// never raise one from here.
	if err == io.EOF {
		err = nil
	}
	return
}

func readUntilErr(r io.Reader, p []byte) (c int, err error) {
	for len(p) > 0 {
		var n int
		n, err = r.Read(p)
		p = p[n:]
		c += n
		if err != nil {
			break
		}
	}
	return
}

func fillBlocksFromContiguousReader(blox []Block, r io.Reader) (c int, err error) {
	for i := range blox {
		block := &blox[i]
		l := block.Length
		data := make([]byte, l)

		var n int
		n, err = readUntilErr(r, data)
		if n > 0 {
			// Any data having been read dirties a block
			block.Data = data[:n]
			c++
		}

		if err != nil {
			break
		}
	}

	// EOFs bubble up as the number of blocks read being short, so we'll
	// never raise one from here.
	if err == io.EOF {
		err = nil
	}
	return
}
