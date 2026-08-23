package download

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestOptionsProxyNilWithoutExplicitProxy pins the proxy contract: only an
// explicit --proxy reaches Options.Proxy; nil keeps the engine's own per-URL
// environment-proxy evaluation, and v0.2.4 judges placement from the actual
// election route.
func TestOptionsProxyNilWithoutExplicitProxy(t *testing.T) {
	preservePolicyOverrides(t)

	d := NewDownload("", false, false, false, false)
	if opts := d.options(); opts.Proxy != nil {
		t.Fatal("Options.Proxy must be nil without an explicit --proxy (placement would be disabled)")
	}

	d = NewDownload("http://proxy.example:3128", false, false, false, false)
	if opts := d.options(); opts.Proxy == nil {
		t.Fatal("Options.Proxy must carry an explicit --proxy")
	}

	// decomposed standard session transports must not reintroduce a stub
	d = NewDownload("", false, false, false, false)
	d.client = &http.Client{Transport: &http.Transport{}}
	if opts := d.options(); opts.Proxy != nil {
		t.Fatal("decomposed session transport must leave Options.Proxy nil without an explicit --proxy")
	}
}

// TestDownloadClassifiesFinalHostWithoutPreflight proves profile selection
// happens through Options.Policy on the final redirected URL, with the
// engine's own election as the only request that touches the redirecting
// source — no ipsw-side preflight exists before range work begins.
func TestDownloadClassifiesFinalHostWithoutPreflight(t *testing.T) {
	preservePolicyOverrides(t)
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

	var sourceHits atomic.Int32
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recordAgent(r)
		sourceHits.Add(1)
		http.Redirect(w, r, final.URL+"/test.ipsw", http.StatusFound)
	}))
	t.Cleanup(source.Close)

	// stage 1: the plain wrapper path downloads through the redirect with
	// exactly one source request (the election)
	d := &Download{URL: source.URL + "/start", DestName: filepath.Join(t.TempDir(), "test.ipsw")}
	t.Cleanup(d.Close)
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
	if got := sourceHits.Load(); got != 1 {
		t.Fatalf("redirecting source served %d requests, want exactly 1 (election only)", got)
	}
	if len(agents) != 1 {
		// origins can route on User-Agent: every request presents one identity
		t.Fatalf("requests used %d distinct User-Agents, want 1: %v", len(agents), agents)
	}

	// the only ipsw-side Policy invariant: the callback is installed.
	// "called once with the final URL" is go-download's own contract,
	// tested upstream.
	if opts := d.options(); opts.Policy == nil {
		t.Fatal("engine options carry no Policy callback")
	}
}
