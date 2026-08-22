package download

import (
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	godl "github.com/blacktop/go-download"
	"github.com/blacktop/ipsw/internal/utils"
	"golang.org/x/net/http/httpproxy"
)

const (
	// PartSuffix is go-download's staging-file suffix for in-flight downloads.
	PartSuffix = ".part"
	// StateSuffix is go-download's resume-sidecar suffix.
	StateSuffix = ".part.json"
	// legacySuffix is the partial-download suffix of the pre-go-download engine.
	legacySuffix = ".download"

	// engineParts is go-download's maximum parallel-connection count.
	engineParts = 8
	// engineMinParts deliberately equals the cap for Apple's per-flow-limited
	// hosts. go-download still sheds eager flows when a server returns HTTP 429.
	engineMinParts = engineParts
	// engineMinPartSize is the smallest range the scheduler will split out;
	// eager concurrency is clamped when an object cannot supply enough ranges.
	engineMinPartSize = 1 << 20
)

// Download drives github.com/blacktop/go-download (parallel parts, HTTP 429
// shedding, and automatic resume) with ipsw's CLI semantics.
type Download struct {
	URL      string
	Sha1     string
	DestName string
	Headers  map[string]string

	proxyFn    func(*http.Request) (*url.URL, error)
	insecure   bool
	skipAll    bool
	restartAll bool
	ignoreSha1 bool

	client *http.Client
	engine *godl.Downloader // lazily built on first Do; reused across a batch
}

// NewDownload creates a new downloader. Interrupted downloads always resume
// automatically, validated against the server's ETag/Last-Modified.
func NewDownload(proxy string, insecure, skipAll, restartAll, ignoreSha1 bool) *Download {
	return &Download{
		proxyFn:    GetProxy(proxy),
		insecure:   insecure,
		skipAll:    skipAll,
		restartAll: restartAll,
		ignoreSha1: ignoreSha1,
	}
}

// GetProxy takes either an input string or read the enviornment and returns a proxy function
func GetProxy(proxy string) func(*http.Request) (*url.URL, error) {
	if len(proxy) > 0 {
		proxyURL, err := url.Parse(proxy)
		if err != nil {
			log.WithError(err).Error("bad proxy url")
		}
		log.Debugf("proxy set to: %s", proxyURL)

		return http.ProxyURL(proxyURL)
	}

	conf := httpproxy.FromEnvironment()
	if len(conf.HTTPProxy) > 0 || len(conf.HTTPSProxy) > 0 {
		log.WithFields(log.Fields{
			"http_proxy":  conf.HTTPProxy,
			"https_proxy": conf.HTTPSProxy,
			"no_proxy":    conf.NoProxy,
		}).Debugf("proxy info from environment")
	}

	return http.ProxyFromEnvironment
}

// Status reports what a Do/DoContext call actually did. It is only
// meaningful when the returned error is nil.
type Status int

const (
	// Skipped means this invocation did NOT produce DestName: the staging
	// file is locked by another download process and --skip-all turned the
	// collision into a non-fatal skip. Callers must not install, patch,
	// checksum, or otherwise post-process DestName on this status.
	Skipped Status = iota
	// Downloaded means this invocation produced DestName.
	Downloaded
)

// Do downloads d.URL to d.DestName, resuming any interrupted download.
func (d *Download) Do() (Status, error) {
	return d.DoContext(context.Background())
}

// DoContext downloads d.URL to d.DestName and stops when ctx is cancelled.
func (d *Download) DoContext(ctx context.Context) (Status, error) {
	if ctx == nil {
		return Skipped, errors.New("download context is nil")
	}
	if d.skipAll && fileExists(d.DestName+PartSuffix) && !stagingLockSupported(filepath.Dir(d.DestName)) {
		// fail closed: this platform or filesystem cannot enforce the
		// staging lock, so any existing stage may be another process's
		// active download. Never let --restart-all discard an unprotected
		// stage because its ownership cannot be established.
		log.Infof("%s - SKIPPED", d.DestName)
		return Skipped, nil
	}
	if err := d.prepareStage(ctx); err != nil {
		if d.skipLocked(err) {
			return Skipped, nil
		}
		return Skipped, err
	}

	if d.engine == nil {
		dl, err := godl.New(d.options())
		if err != nil {
			return Skipped, fmt.Errorf("failed to create downloader for %s: %w", godl.RedactURL(d.URL), err)
		}
		d.engine = dl
	}

	req := &godl.Request{
		URL:          d.URL,
		Dest:         d.DestName,
		Reporter:     newProgressReporter(),
		ExpectedSHA1: d.expectedSHA1(),
	}
	res, err := d.engine.Do(ctx, req)
	if err != nil {
		if d.skipLocked(err) {
			return Skipped, nil
		}
		return Skipped, d.wrapError(err)
	}
	if res.Resumed {
		utils.Indent(log.WithField("file", d.DestName).Debug, 2)("Resumed a previous download")
	}
	if req.ExpectedSHA1 != "" {
		utils.Indent(log.Debug, 2)("sha1sum verified ✅")
	}
	return Downloaded, nil
}

// Close releases the cached engine's idle connections. Call it once after a
// batch of Do calls; a closed Download can still be reused (the next Do
// rebuilds the engine).
func (d *Download) Close() {
	if d.engine != nil {
		d.engine.CloseIdleConnections()
		d.engine = nil
	}
}

func (d *Download) prepareStage(ctx context.Context) error {
	legacyPath := d.DestName + legacySuffix
	if fileExists(legacyPath) {
		log.Warnf("found legacy partial download %s: the new engine cannot resume it and it may be incomplete; "+
			"if it is actually complete, rename it into place (mv '%s' '%s') — otherwise delete it", legacyPath, legacyPath, d.DestName)
	}
	if !d.restartAll {
		return nil
	}
	if fileExists(d.DestName + PartSuffix) {
		log.Infof("Downloading %s - RESTARTED", d.DestName)
	}
	if err := godl.Discard(ctx, d.DestName); err != nil {
		return fmt.Errorf("failed to restart download: %w", err)
	}
	if fileExists(legacyPath) {
		log.Infof("removing legacy partial download %s", legacyPath)
		if err := os.Remove(legacyPath); err != nil {
			return fmt.Errorf("failed to restart download, cannot remove %s: %w", legacyPath, err)
		}
	}
	return nil
}

func (d *Download) options() *godl.Options {
	headers := make(http.Header)
	for key, value := range d.Headers {
		headers.Set(key, value)
	}
	if headers.Get("User-Agent") == "" {
		headers.Set("User-Agent", utils.RandomAgent())
	}

	opts := &godl.Options{
		Parts:              engineParts,
		MinParts:           engineMinParts,
		MinPartSize:        engineMinPartSize,
		Headers:            headers,
		RejectContentTypes: []string{"text/html"},
		Overwrite:          true,
	}
	if d.insecure {
		opts.TLSConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- user opted in via --insecure
	}
	if transport := d.downloadTransport(); transport != nil {
		opts.Transport = transport
	} else {
		opts.Proxy = d.proxy()
	}
	if d.client != nil {
		opts.Jar = d.client.Jar
	}
	return opts
}

func (d *Download) expectedSHA1() string {
	sha := strings.ToLower(strings.TrimSpace(d.Sha1))
	if sha == "" {
		return ""
	}
	if d.ignoreSha1 {
		utils.Indent(log.Warn, 2)("SHA-1 verification disabled")
		return ""
	}
	if !ValidSHA1(sha) {
		// Scraped sources sometimes publish placeholders instead of hashes.
		log.Warnf("ignoring invalid published SHA-1 %q for %s: downloading without verification", d.Sha1, d.DestName)
		return ""
	}
	return sha
}

func (d *Download) wrapError(err error) error {
	if contentTypeErr, ok := errors.AsType[*godl.ContentTypeError](err); ok {
		return fmt.Errorf("failed to download %s to %s: server returned %q instead of the requested file: %w",
			godl.RedactURL(d.URL), d.DestName, contentTypeErr.ContentType, err)
	}
	if checksumErr, ok := errors.AsType[*godl.ChecksumError](err); ok {
		return fmt.Errorf("checksum mismatch for %s (downloaded bytes retained at %s): "+
			"rerun with --restart-all to re-download, or — only after independently validating the file — "+
			"with --ignore-sha1 to accept it (a complete resumable stage finalizes without re-downloading): %w",
			d.DestName, checksumErr.Path, err)
	}
	return fmt.Errorf("failed to download %s: %w", godl.RedactURL(d.URL), err)
}

func (d *Download) skipLocked(err error) bool {
	if !d.skipAll || !errors.Is(err, godl.ErrLocked) {
		return false
	}
	log.Infof("%s - SKIPPED", d.DestName)
	return true
}

// ValidSHA1 reports whether s is a well-formed hex SHA-1 digest.
func ValidSHA1(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) != sha1.Size*2 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// proxy returns d's proxy function, defaulting to the environment for
// zero-value Downloads that skipped NewDownload.
func (d *Download) proxy() func(*http.Request) (*url.URL, error) {
	if d.proxyFn != nil {
		return d.proxyFn
	}
	return http.ProxyFromEnvironment
}

// borrowedRoundTripper deliberately exposes only RoundTrip. That prevents
// go-download from closing a caller-owned custom transport through its
// optional CloseIdleConnections method.
type borrowedRoundTripper struct{ http.RoundTripper }

// downloadTransport clones standard authenticated transports so go-download
// can tune and close the clone. Opaque transports stay caller-owned.
func (d *Download) downloadTransport() http.RoundTripper {
	if d.client == nil || d.client.Transport == nil {
		return nil
	}
	if t, ok := d.client.Transport.(*http.Transport); ok {
		t = t.Clone()
		// HTTP/2 would multiplex every range onto a single TCP connection.
		var protocols http.Protocols
		protocols.SetHTTP1(true)
		t.Protocols = &protocols
		t.MaxIdleConnsPerHost = engineParts + 1
		return t
	}
	return borrowedRoundTripper{RoundTripper: d.client.Transport}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
