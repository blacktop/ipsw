package download

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestOptionsProxyNilWithoutExplicitProxy pins the node-selection contract:
// go-download treats every non-nil Proxy callback as opaque and disables
// placement, so only an explicit --proxy may reach Options.Proxy.
func TestOptionsProxyNilWithoutExplicitProxy(t *testing.T) {
	policy := EnginePolicy{Parts: 1, MinParts: 1}

	d := NewDownload("", false, false, false, false)
	if opts := d.options(policy); opts.Proxy != nil {
		t.Fatal("Options.Proxy must be nil without an explicit --proxy (placement would be disabled)")
	}

	d = NewDownload("http://proxy.example:3128", false, false, false, false)
	if opts := d.options(policy); opts.Proxy == nil {
		t.Fatal("Options.Proxy must carry an explicit --proxy")
	}

	// decomposed standard session transports must not reintroduce a stub
	d = NewDownload("", false, false, false, false)
	d.client = &http.Client{Transport: &http.Transport{}}
	if opts := d.options(policy); opts.Proxy != nil {
		t.Fatal("decomposed session transport must leave Options.Proxy nil without an explicit --proxy")
	}
}

// TestResolveByteServingURLFollowsRedirects pins profile classification to
// the byte-serving hostname rather than the redirecting source.
func TestResolveByteServingURLFollowsRedirects(t *testing.T) {
	payload := []byte("synthetic firmware payload")
	var mu sync.Mutex
	agents := make(map[string]struct{})
	recordAgent := func(r *http.Request) {
		mu.Lock()
		agents[r.Header.Get("User-Agent")] = struct{}{}
		mu.Unlock()
	}
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recordAgent(r)
		http.ServeContent(w, r, "test.ipsw", time.Time{}, bytes.NewReader(payload))
	}))
	t.Cleanup(final.Close)
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recordAgent(r)
		http.Redirect(w, r, final.URL+"/test.ipsw", http.StatusFound)
	}))
	t.Cleanup(source.Close)

	d := &Download{URL: source.URL + "/start", DestName: filepath.Join(t.TempDir(), "test.ipsw")}
	got, err := d.resolveByteServingURL(t.Context(), d.URL)
	if err != nil {
		t.Fatal(err)
	}
	if want := final.URL + "/test.ipsw"; got != want {
		t.Fatalf("resolved byte-serving URL = %q, want %q", got, want)
	}

	// and the full download still works through the redirect chain
	if _, err := d.DoContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(d.DestName)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, payload) {
		t.Fatal("downloaded bytes differ from source")
	}
	// origins can route on User-Agent: the preflight and the transfer must
	// present one identity or they may classify different redirect chains
	if len(agents) != 1 {
		t.Fatalf("requests used %d distinct User-Agents, want 1: %v", len(agents), agents)
	}
}

// TestResolveByteServingURLRejectsErrorStatus pins the fallback contract: an
// error page's final URL must not classify the download; the caller keeps the
// source hostname instead.
func TestResolveByteServingURLRejectsErrorStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "denied", http.StatusForbidden)
	}))
	t.Cleanup(server.Close)

	d := &Download{URL: server.URL + "/file"}
	t.Cleanup(d.Close)
	if got, err := d.resolveByteServingURL(t.Context(), d.URL); err == nil {
		t.Fatalf("resolveByteServingURL on a 403 returned %q, want error", got)
	}
}

func TestRedactedErrorStripsSignedURL(t *testing.T) {
	err := &url.Error{
		Op:  "Get",
		URL: "https://cdn.invalid/file.ipsw?accessKey=synthetic-secret",
		Err: errors.New("connection refused"),
	}
	got := redactedError(err)
	if strings.Contains(got, "synthetic-secret") {
		t.Fatalf("redactedError leaks signed query values: %s", got)
	}
	if !strings.Contains(got, "cdn.invalid") || !strings.Contains(got, "connection refused") {
		t.Fatalf("redactedError dropped useful context: %s", got)
	}

	// nested causes and free-text URLs must be scrubbed too
	nested := &url.Error{
		Op:  "Get",
		URL: "https://outer.invalid/start?sig=outer-secret",
		Err: &url.Error{
			Op:  "Get",
			URL: "https://inner.invalid/hop?sig=inner-secret",
			Err: errors.New(`redirect to "https://free.invalid/x?sig=text-secret" blocked`),
		},
	}
	got = redactedError(nested)
	for _, secret := range []string{"outer-secret", "inner-secret", "text-secret"} {
		if strings.Contains(got, secret) {
			t.Fatalf("redactedError leaks %s: %s", secret, got)
		}
	}
}

func TestEngineProfileUsesResolvedByteServingURL(t *testing.T) {
	preservePolicyOverrides(t)
	d := NewDownload("", false, false, false, false)
	t.Cleanup(d.Close)

	finalURLs := map[string]string{
		"https://updates.cdn-apple.com/from-apple":   "https://example.net/final",
		"https://example.net/direct-generic":         "https://example.net/final",
		"https://example.net/from-generic":           "https://updates.cdn-apple.com/final",
		"https://updates.cdn-apple.com/direct-apple": "https://updates.cdn-apple.com/final",
	}
	resolved := make(map[string]int)
	d.resolveFinalURL = func(_ context.Context, rawURL string) (string, error) {
		resolved[rawURL]++
		return finalURLs[rawURL], nil
	}

	d.URL = "https://updates.cdn-apple.com/from-apple"
	appleToGeneric, err := d.engineForURL(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	d.URL = "https://example.net/direct-generic"
	directGeneric, err := d.engineForURL(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	d.URL = "https://example.net/from-generic"
	genericToApple, err := d.engineForURL(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	d.URL = "https://updates.cdn-apple.com/direct-apple"
	directApple, err := d.engineForURL(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	if appleToGeneric != directGeneric {
		t.Fatal("Apple source redirecting to a generic host did not use the generic profile")
	}
	if genericToApple != directApple {
		t.Fatal("generic source redirecting to an Apple host did not use the Apple profile")
	}
	if directGeneric == directApple {
		t.Fatal("generic and Apple final hosts reused the same engine profile")
	}
	for rawURL := range finalURLs {
		if resolved[rawURL] != 1 {
			t.Fatalf("redirect resolution calls for %q = %d, want 1", rawURL, resolved[rawURL])
		}
	}
}
