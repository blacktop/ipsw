package download

import (
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

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
// intended for sequential use by one goroutine; create one per concurrent
// batch.
type Download struct {
	URL      string
	Sha1     string
	DestName string
	Headers  map[string]string

	proxyFn    func(*http.Request) (*url.URL, error)
	userAgent  string // chosen once so preflight and transfer follow one redirect chain
	insecure   bool
	skipAll    bool
	restartAll bool
	ignoreSha1 bool

	client *http.Client

	fallbackProfile Profile
	engines         map[EnginePolicy]*godl.Downloader // lazily built and reused by resolved tuple
	preflight       *http.Client                      // lazy redirect resolver; closed by Close
	// resolveFinalURL overrides redirect resolution in tests; nil uses the
	// ranged-request preflight.
	resolveFinalURL func(context.Context, string) (string, error)
}

// NewDownload creates a new downloader. Interrupted downloads always resume
// automatically, validated against the server's ETag/Last-Modified.
func NewDownload(proxy string, insecure, skipAll, restartAll, ignoreSha1 bool) *Download {
	return NewDownloadWithProfile(GenericProfile, proxy, insecure, skipAll, restartAll, ignoreSha1)
}

// NewDownloadWithProfile creates a downloader with an explicit fallback for
// URLs that cannot be classified. A valid URL always selects by hostname.
func NewDownloadWithProfile(
	profile Profile, proxy string, insecure, skipAll, restartAll, ignoreSha1 bool,
) *Download {
	d := &Download{
		insecure:        insecure,
		skipAll:         skipAll,
		restartAll:      restartAll,
		ignoreSha1:      ignoreSha1,
		fallbackProfile: profile,
	}
	// Only an explicit --proxy becomes a caller-supplied proxy function:
	// go-download treats every non-nil callback as opaque and disables node
	// placement, while a nil Proxy keeps its own per-URL environment-proxy
	// evaluation (and placement eligibility) intact.
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

	engine, err := d.engineForURL(ctx)
	if err != nil {
		return Skipped, fmt.Errorf("failed to create downloader for %s: %w", godl.RedactURL(d.URL), err)
	}

	req := &godl.Request{
		URL:          d.URL,
		Dest:         d.DestName,
		Reporter:     newProgressReporter(),
		ExpectedSHA1: d.expectedSHA1(),
	}
	res, err := engine.Do(ctx, req)
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

// Close releases every cached engine's idle connections. Call it once after a
// batch of Do calls; a closed Download can still be reused.
func (d *Download) Close() {
	for _, engine := range d.engines {
		engine.CloseIdleConnections()
	}
	d.engines = nil
	if d.preflight != nil {
		if transport, ok := d.preflight.Transport.(*http.Transport); ok {
			transport.CloseIdleConnections()
		}
		d.preflight = nil
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

func (d *Download) engineForURL(ctx context.Context) (*godl.Downloader, error) {
	target := d.URL
	// The profile contract classifies the byte-serving hostname, so resolve
	// redirects before choosing the tuple regardless of the source hostname —
	// unless the overrides pin both profiles to one tuple, in which case the
	// answer cannot matter and the extra request is skipped.
	resolve := d.resolveFinalURL
	if resolve == nil {
		resolve = d.resolveByteServingURL
	}
	if profilesConverge() {
		resolve = nil
	}
	if resolve != nil {
		if final, err := resolve(ctx, target); err == nil {
			target = final
		} else {
			log.Debugf("could not resolve byte-serving URL for %s: %s",
				godl.RedactURL(target), redactedError(err))
		}
	}
	policy, err := ResolvePolicy(target, d.fallbackProfile)
	if err != nil {
		return nil, err
	}
	if engine := d.engines[policy]; engine != nil {
		return engine, nil
	}
	opts := d.options(policy)
	engine, err := godl.New(opts)
	if err != nil {
		return nil, err
	}
	if d.engines == nil {
		d.engines = make(map[EnginePolicy]*godl.Downloader)
	}
	d.engines[policy] = engine
	return engine, nil
}

func (d *Download) options(policy EnginePolicy) *godl.Options {
	opts := &godl.Options{
		Parts:       policy.Parts,
		MinParts:    policy.MinParts,
		MinPartSize: policy.MinPartSize,
		// go-download itself keeps placement off for borrowed transports
		// (Options.Transport != nil): no ipsw-side mirror of that invariant
		EnableNodeSelection: policy.EnableNodeSelection,
		Headers:             d.requestHeaders(),
		RejectContentTypes:  []string{"text/html"},
		Overwrite:           true,
	}
	if d.client != nil {
		opts.Jar = d.client.Jar
	}
	d.applyTransport(opts)
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

// borrowedRoundTripper deliberately exposes only RoundTrip. That prevents
// go-download from closing a caller-owned non-http custom transport through
// its optional CloseIdleConnections method.
type borrowedRoundTripper struct{ http.RoundTripper }

// requestHeaders builds the header set shared by the engine options and the
// redirect preflight, so both follow the same redirect chain (hosts can gate
// on User-Agent).
func (d *Download) requestHeaders() http.Header {
	headers := make(http.Header)
	for key, value := range d.Headers {
		headers.Set(key, value)
	}
	if headers.Get("User-Agent") == "" {
		// origins can route or redirect on User-Agent: pick one agent per
		// Download so classification and transfer see the same chain
		if d.userAgent == "" {
			d.userAgent = utils.RandomAgent()
		}
		headers.Set("User-Agent", d.userAgent)
	}
	return headers
}

// resolveByteServingURL follows redirects with a one-byte ranged request and
// returns the final URL that will actually serve the download's bytes.
func (d *Download) resolveByteServingURL(ctx context.Context, rawURL string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	client := d.client
	if client == nil {
		if d.preflight == nil {
			proxy := d.proxyFn
			if proxy == nil {
				proxy = http.ProxyFromEnvironment
			}
			transport := &http.Transport{Proxy: proxy}
			if d.insecure {
				transport.TLSClientConfig = insecureTLS(nil)
			}
			d.preflight = &http.Client{Transport: transport}
		}
		client = d.preflight
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	for key, values := range d.requestHeaders() {
		req.Header[key] = values
	}
	req.Header.Set("Range", "bytes=0-0")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	// drain the single byte of a 206 so the connection is reusable; a
	// Range-ignoring 200 is closed with its body unread (no reuse)
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 2))
	resp.Body.Close()
	// an error page's final URL must not classify the download: fail the
	// preflight so the caller falls back to the source hostname
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("preflight for %s returned %s", godl.RedactURL(rawURL), resp.Status)
	}
	return resp.Request.URL.String(), nil
}

// redactedError renders err for logging with any embedded request URL
// redacted (url.Error strings carry the full signed query).
// urlPattern matches URL text embedded in error strings (nested url.Errors,
// redirect messages) so signed query credentials never reach logs.
var urlPattern = regexp.MustCompile(`https?://[^\s"']+`)

func redactedError(err error) string {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return fmt.Sprintf("%s %s: %s", urlErr.Op, godl.RedactURL(urlErr.URL), redactedError(urlErr.Err))
	}
	return urlPattern.ReplaceAllStringFunc(err.Error(), godl.RedactURL)
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
		// form (nil when unset) so placement stays eligible on direct routes
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
	clone.MaxIdleConnsPerHost = opts.Parts + 1
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
