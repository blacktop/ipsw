package download

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
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
)

// Download drives github.com/blacktop/go-download (parallel parts, HTTP 429
// shedding, and automatic resume) with ipsw's CLI semantics. A Download is
// intended for sequential use by one goroutine; create one for each batch
// that may run concurrently.
type Download struct {
	URL      string
	Sha1     string
	DestName string
	Headers  map[string]string

	proxyFn    func(*http.Request) (*url.URL, error)
	userAgent  string // chosen once so every request follows one redirect chain
	insecure   bool
	skipAll    bool
	restartAll bool
	ignoreSha1 bool

	client *http.Client

	workloadProfile Profile
	// nodeSelection is the placement setting captured at construction:
	// EnableNodeSelection is fixed at engine construction (the tuple stays
	// live via Options.Policy), and the CLI installs overrides exactly once
	// before any Download exists.
	nodeSelection bool
	// engine is one long-lived go-download instance per transport/auth
	// context; per-resource tuples are applied by Options.Policy after the
	// engine's own election resolves the byte-serving URL.
	engine *godl.Downloader
}

// FileRequest is one artifact handled by a long-lived Download session.
// Headers and ResumeID are per file; transport, cookie jar, proxy, TLS, and
// concurrency policy stay on the Download.
type FileRequest struct {
	URL      string
	SHA1     string
	SHA256   string
	DestName string
	Headers  http.Header
	// ResumeID overrides the wrapper's default origin/path identity.
	// Empty derives that identity with defaultResumeID.
	ResumeID string
}

// NewDownload creates a new downloader. Interrupted downloads always resume
// automatically, validated against the server's ETag/Last-Modified.
func NewDownload(proxy string, insecure, skipAll, restartAll, ignoreSha1 bool) *Download {
	return NewDownloadWithProfile(GenericProfile, proxy, insecure, skipAll, restartAll, ignoreSha1)
}

// NewDownloadWithProfile creates a downloader for an explicit workload. The
// engine's final byte-serving hostname remains authoritative: a parseable
// non-Apple final hostname selects GenericProfile, while a URL without a
// parseable hostname retains the normalized workload.
func NewDownloadWithProfile(
	profile Profile, proxy string, insecure, skipAll, restartAll, ignoreSha1 bool,
) *Download {
	d := &Download{
		insecure:        insecure,
		skipAll:         skipAll,
		restartAll:      restartAll,
		ignoreSha1:      ignoreSha1,
		workloadProfile: profile,
		nodeSelection:   GetPolicyOverrides().EnableNodeSelection,
	}
	// Only an explicit --proxy becomes a caller-supplied proxy function.
	// go-download decides placement from the actual election route
	// (a proxied election disables it); a nil Proxy keeps the engine's own
	// per-URL environment-proxy evaluation.
	if proxy != "" {
		d.proxyFn = GetProxy(proxy)
	} else {
		logEnvProxy()
	}
	return d
}

// logEnvProxy surfaces environment proxy settings at debug level; the engine
// evaluates them per URL without logging.
func logEnvProxy() {
	conf := httpproxy.FromEnvironment()
	if len(conf.HTTPProxy) > 0 || len(conf.HTTPSProxy) > 0 {
		log.WithFields(log.Fields{
			"http_proxy":  conf.HTTPProxy,
			"https_proxy": conf.HTTPSProxy,
			"no_proxy":    conf.NoProxy,
		}).Debugf("proxy info from environment")
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

	logEnvProxy()

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
// It is the compatibility adapter for callers that still populate Download's
// public per-file fields.
func (d *Download) DoContext(ctx context.Context) (Status, error) {
	headers := make(http.Header, len(d.Headers))
	for key, value := range d.Headers {
		headers.Set(key, value)
	}
	return d.DoRequestContext(ctx, &FileRequest{
		URL: d.URL, SHA1: d.Sha1, DestName: d.DestName, Headers: headers,
	})
}

// DoRequestContext downloads one typed file request and stops when ctx is
// cancelled. The engine snapshots Headers at its Do boundary.
func (d *Download) DoRequestContext(ctx context.Context, req *FileRequest) (Status, error) {
	if ctx == nil {
		return Skipped, errors.New("download context is nil")
	}
	if req == nil {
		return Skipped, errors.New("download request is nil")
	}
	request := *req
	request.Headers = req.Headers.Clone()
	if d.skipAll && fileExists(request.DestName+PartSuffix) && !stagingLockSupported(filepath.Dir(request.DestName)) {
		// fail closed: this platform or filesystem cannot enforce the
		// staging lock, so any existing stage may be another process's
		// active download. Never let --restart-all discard an unprotected
		// stage because its ownership cannot be established.
		log.Infof("%s - SKIPPED", request.DestName)
		return Skipped, nil
	}
	if err := d.prepareStage(ctx, request.DestName); err != nil {
		if d.skipLocked(err, request.DestName) {
			return Skipped, nil
		}
		return Skipped, err
	}

	engine, err := d.downloadEngine()
	if err != nil {
		return Skipped, fmt.Errorf("failed to create downloader for %s: %w", godl.RedactURL(request.URL), err)
	}

	engineReq := &godl.Request{
		URL:            request.URL,
		Dest:           request.DestName,
		Reporter:       newProgressReporter(),
		ExpectedSHA1:   d.expectedDigest(request.SHA1, request.DestName, "SHA-1", sha1.Size),
		ExpectedSHA256: d.expectedDigest(request.SHA256, request.DestName, "SHA-256", sha256.Size),
		Headers:        request.Headers,
		ResumeID:       request.ResumeID,
	}
	if engineReq.ResumeID == "" {
		engineReq.ResumeID = defaultResumeID(request.URL)
	}
	res, err := engine.Do(ctx, engineReq)
	if err != nil {
		if d.skipLocked(err, request.DestName) {
			return Skipped, nil
		}
		return Skipped, d.wrapError(err, request.URL, request.DestName)
	}
	if res.Resumed {
		utils.Indent(log.WithField("file", request.DestName).Debug, 2)("Resumed a previous download")
	}
	if engineReq.ExpectedSHA1 != "" {
		utils.Indent(log.Debug, 2)("sha1sum verified ✅")
	}
	if engineReq.ExpectedSHA256 != "" {
		utils.Indent(log.Debug, 2)("sha256sum verified ✅")
	}
	return Downloaded, nil
}

// Close releases the engine's idle connections. Call it once after a batch
// of Do calls; a closed Download can still be reused (the next Do rebuilds
// the engine).
func (d *Download) Close() {
	if d.engine != nil {
		d.engine.CloseIdleConnections()
		d.engine = nil
	}
}

func (d *Download) prepareStage(ctx context.Context, destName string) error {
	legacyPath := destName + legacySuffix
	if fileExists(legacyPath) {
		log.Warnf("found legacy partial download %s: the new engine cannot resume it and it may be incomplete; "+
			"if it is actually complete, rename it into place (mv '%s' '%s') — otherwise delete it", legacyPath, legacyPath, destName)
	}
	if !d.restartAll {
		return nil
	}
	if fileExists(destName + PartSuffix) {
		log.Infof("Downloading %s - RESTARTED", destName)
	}
	if err := godl.Discard(ctx, destName); err != nil {
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

// downloadEngine lazily builds the Download's single engine. Per-resource
// concurrency is chosen by policyFor once the engine's election has followed
// redirects — no ipsw-side preflight request exists.
func (d *Download) downloadEngine() (*godl.Downloader, error) {
	if d.engine != nil {
		return d.engine, nil
	}
	engine, err := godl.New(d.options())
	if err != nil {
		return nil, err
	}
	d.engine = engine
	return engine, nil
}

// policyFor classifies the byte-serving (post-redirect) URL within the
// session's workload and returns the per-resource tuple.
func (d *Download) policyFor(finalURL string) godl.Concurrency {
	return ResolvePolicy(finalURL, d.workloadProfile)
}

func (d *Download) options() *godl.Options {
	// Policy owns the effective tuple per resource; the Generic base gives
	// godl.New a valid tuple before the final URL is known.
	base := resolveProfile(GenericProfile, GetPolicyOverrides())
	opts := &godl.Options{
		Parts:       base.Parts,
		MinParts:    base.MinParts,
		MinPartSize: base.MinPartSize,
		// Policy re-tunes the tuple per resource once the election has
		// resolved the byte-serving URL
		Policy: d.policyFor,
		// go-download itself keeps placement off for borrowed transports
		// (Options.Transport != nil): no ipsw-side mirror of that invariant
		EnableNodeSelection: d.nodeSelection,
		Headers:             d.requestHeaders(),
		RejectContentTypes:  []string{"text/html"},
		Overwrite:           true,
		// surface the engine's structured measurements (election, tuple,
		// retries, 429 shedding, placement, resume, integrity) at --verbose
		Logger: engineLog,
	}
	if d.client != nil {
		opts.Jar = d.client.Jar
	}
	d.applyTransport(opts)
	return opts
}

// expectedDigest normalizes a published hex digest for the engine. Empty
// digests, --ignore-sha1 (which disables all published-checksum
// verification), and malformed digests download unverified — scraped
// sources sometimes publish placeholders instead of hashes.
func (d *Download) expectedDigest(raw, destName, algo string, size int) string {
	sha := strings.ToLower(strings.TrimSpace(raw))
	if sha == "" {
		return ""
	}
	if d.ignoreSha1 {
		utils.Indent(log.Warn, 2)(algo + " verification disabled")
		return ""
	}
	if !validHexDigest(sha, size) {
		log.Warnf("ignoring invalid published %s %q for %s: downloading without verification", algo, raw, destName)
		return ""
	}
	return sha
}

func (d *Download) wrapError(err error, rawURL, destName string) error {
	if contentTypeErr, ok := errors.AsType[*godl.ContentTypeError](err); ok {
		return fmt.Errorf("failed to download %s to %s: server returned %q instead of the requested file: %w",
			godl.RedactURL(rawURL), destName, contentTypeErr.ContentType, err)
	}
	if checksumErr, ok := errors.AsType[*godl.ChecksumError](err); ok {
		return fmt.Errorf("checksum mismatch for %s (downloaded bytes retained at %s): "+
			"rerun with --restart-all to re-download, or — only after independently validating the file — "+
			"with --ignore-sha1 to accept it (a complete resumable stage finalizes without re-downloading): %w",
			destName, checksumErr.Path, err)
	}
	return fmt.Errorf("failed to download %s: %w", godl.RedactURL(rawURL), err)
}

func (d *Download) skipLocked(err error, destName string) bool {
	if !d.skipAll || !errors.Is(err, godl.ErrLocked) {
		return false
	}
	log.Infof("%s - SKIPPED", destName)
	return true
}

// ValidSHA1 reports whether s is a well-formed hex SHA-1 digest.
func ValidSHA1(s string) bool {
	return validHexDigest(strings.TrimSpace(s), sha1.Size)
}

// validHexDigest reports whether s is exactly size bytes of hex.
func validHexDigest(s string, size int) bool {
	if len(s) != size*2 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// borrowedRoundTripper deliberately exposes only RoundTrip. That prevents
// go-download from closing a caller-owned non-http custom transport through
// its optional CloseIdleConnections method.
type borrowedRoundTripper struct{ http.RoundTripper }

// requestHeaders builds the engine's session-level header set. Per-file
// headers are carried by FileRequest.
func (d *Download) requestHeaders() http.Header {
	headers := make(http.Header)
	// Origins can route or redirect on User-Agent: pick one agent per Download
	// so every request presents a single identity. A FileRequest may explicitly
	// replace it through go-download's canonical merge.
	if d.userAgent == "" {
		d.userAgent = utils.RandomAgent()
	}
	headers.Set("User-Agent", d.userAgent)
	return headers
}

// defaultResumeID derives the fallback identity used when FileRequest.ResumeID
// is empty. Query and fragment are excluded so rotating URL credentials do not
// change identity; validators, expected size, and the per-destination sidecar
// still gate partial-data reuse. An explicit default port is normalized away
// while a non-default port remains part of the origin.
func defaultResumeID(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Opaque != "" {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	host := godl.NormalizeHost(u.Hostname())
	if scheme == "" || host == "" {
		return ""
	}
	port := u.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	authority := host
	if port != "" {
		authority = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		authority = "[" + host + "]"
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return scheme + "://" + authority + path
}

// insecureTLS returns a clone of c (or a fresh config) with certificate
// verification disabled.
func insecureTLS(c *tls.Config) *tls.Config {
	if c == nil {
		c = &tls.Config{}
	} else {
		c = c.Clone()
	}
	c.InsecureSkipVerify = true // #nosec G402 -- user opted in via --insecure
	return c
}

// applyTransport hands recognized standard Apple transport configuration to
// go-download so it owns dialing and can place connections. Opaque transports
// remain borrowed and affirmatively disable placement.
func (d *Download) applyTransport(opts *godl.Options) {
	if d.client == nil || d.client.Transport == nil {
		opts.Proxy = d.proxyFn // nil: engine evaluates env proxy per URL
		if d.insecure {
			opts.TLSConfig = insecureTLS(nil)
		}
		return
	}
	transport, ok := d.client.Transport.(*http.Transport)
	if !ok {
		opts.Transport = borrowedRoundTripper{RoundTripper: d.client.Transport}
		return
	}
	if decomposableTransport(transport) {
		// the session transport's Proxy came from the same proxy setting
		// this Download was constructed with; hand the engine the explicit
		// form (nil when unset) and let it judge placement from the actual
		// election route
		opts.Proxy = d.proxyFn
		if transport.TLSClientConfig != nil {
			opts.TLSConfig = transport.TLSClientConfig.Clone()
		}
		if d.insecure {
			opts.TLSConfig = insecureTLS(opts.TLSConfig)
		}
		return
	}
	clone := transport.Clone()
	// HTTP/2 would multiplex every range onto one TCP connection. Preserve
	// the prior ipsw behavior for opaque standard transports while keeping
	// their custom dialing, timeout, and buffer policy intact.
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	clone.Protocols = &protocols
	clone.ForceAttemptHTTP2 = false
	// Policy can retune Parts per resource after the election: size the idle
	// pool from the cap so a larger tuple does not evict useful connections.
	clone.MaxIdleConnsPerHost = MaxParts + 1
	if d.insecure {
		clone.TLSClientConfig = insecureTLS(clone.TLSClientConfig)
	}
	opts.Transport = clone
}

func decomposableTransport(transport *http.Transport) bool {
	return transport != nil && transport.Dial == nil && transport.DialContext == nil &&
		transport.DialTLS == nil && transport.DialTLSContext == nil &&
		transport.ProxyConnectHeader == nil && transport.GetProxyConnectHeader == nil &&
		transport.OnProxyConnectResponse == nil &&
		transport.TLSHandshakeTimeout == 0 && !transport.DisableKeepAlives &&
		!transport.DisableCompression && transport.MaxIdleConns == 0 &&
		transport.MaxIdleConnsPerHost == 0 && transport.MaxConnsPerHost == 0 &&
		transport.IdleConnTimeout == 0 && transport.ResponseHeaderTimeout == 0 &&
		transport.ExpectContinueTimeout == 0 && transport.TLSNextProto == nil &&
		transport.MaxResponseHeaderBytes == 0 && transport.WriteBufferSize == 0 &&
		transport.ReadBufferSize == 0 && !transport.ForceAttemptHTTP2 &&
		transport.HTTP2 == nil && transport.Protocols == nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
