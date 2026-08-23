package download

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"testing"
	"time"
)

func preservePolicyOverrides(t *testing.T) {
	t.Helper()
	previous := GetPolicyOverrides()
	t.Cleanup(func() {
		if err := SetPolicyOverrides(previous); err != nil {
			t.Fatal(err)
		}
	})
	if err := SetPolicyOverrides(PolicyOverrides{}); err != nil {
		t.Fatal(err)
	}
}

func TestURLProfileClassification(t *testing.T) {
	preservePolicyOverrides(t)
	tests := []struct {
		name     string
		url      string
		fallback Profile
		want     EnginePolicy
	}{
		{
			name: "apple exact", url: "https://apple.com/file",
			want: EnginePolicy{Parts: 8, MinParts: 8, MinPartSize: 8 << 20},
		},
		{
			name: "apple subdomain", url: "https://updates.cdn-apple.com/file",
			want: EnginePolicy{Parts: 8, MinParts: 8, MinPartSize: 8 << 20},
		},
		{
			name: "aaplimg boundary", url: "https://A.B.AAPLIMG.COM./file",
			want: EnginePolicy{Parts: 8, MinParts: 8, MinPartSize: 8 << 20},
		},
		{
			name: "apple with port", url: "https://apple.com:8443/file",
			want: EnginePolicy{Parts: 8, MinParts: 8, MinPartSize: 8 << 20},
		},
		{
			name: "mzstatic subdomain", url: "https://iosapps-ssl.mzstatic.com/file",
			want: EnginePolicy{Parts: 8, MinParts: 8, MinPartSize: 8 << 20},
		},
		{
			name: "apple with userinfo", url: "https://user:pass@apple.com/file",
			want: EnginePolicy{Parts: 8, MinParts: 8, MinPartSize: 8 << 20},
		},
		{
			name: "lookalike", url: "https://notapple.com/file",
			want: EnginePolicy{Parts: 8, MinParts: 4, MinPartSize: 16 << 20},
		},
		{
			name: "suffix lookalike", url: "https://apple.com.invalid/file",
			want: EnginePolicy{Parts: 8, MinParts: 4, MinPartSize: 16 << 20},
		},
		{
			name: "userinfo spoof", url: "https://apple.com@evil.example/file",
			want: EnginePolicy{Parts: 8, MinParts: 4, MinPartSize: 16 << 20},
		},
		{
			name: "literal IPv4", url: "https://192.0.2.1/file",
			want: EnginePolicy{Parts: 8, MinParts: 4, MinPartSize: 16 << 20},
		},
		{
			name: "literal IPv6", url: "https://[2001:db8::1]/file",
			want: EnginePolicy{Parts: 8, MinParts: 4, MinPartSize: 16 << 20},
		},
		{
			name: "punycode", url: "https://xn--pple-43d.com/file",
			want: EnginePolicy{Parts: 8, MinParts: 4, MinPartSize: 16 << 20},
		},
		{
			name: "github", url: "https://github.com/apple/repo",
			want: EnginePolicy{Parts: 8, MinParts: 4, MinPartSize: 16 << 20},
		},
		{
			name: "malformed apple fallback", url: "::", fallback: AppleCDNProfile,
			want: EnginePolicy{Parts: 8, MinParts: 8, MinPartSize: 8 << 20},
		},
		{
			name: "malformed generic fallback", url: "::", fallback: GenericProfile,
			want: EnginePolicy{Parts: 8, MinParts: 4, MinPartSize: 16 << 20},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := ResolvePolicy(test.url, test.fallback)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("ResolvePolicy(%q) = %+v, want %+v", test.url, got, test.want)
			}
		})
	}
}

func TestPolicyOverrideResolution(t *testing.T) {
	preservePolicyOverrides(t)
	if err := SetPolicyOverrides(PolicyOverrides{Parts: 3}); err != nil {
		t.Fatal(err)
	}
	for _, fallback := range []Profile{GenericProfile, AppleCDNProfile} {
		got, err := ResolvePolicy("::", fallback)
		if err != nil {
			t.Fatal(err)
		}
		if got.Parts != 3 || got.MinParts != 3 {
			t.Fatalf("profile %d reduced-parts policy = %+v, want 3/3", fallback, got)
		}
	}
	if err := SetPolicyOverrides(PolicyOverrides{Parts: 3, MinParts: 4}); err == nil {
		t.Fatal("explicit inconsistent min-parts was accepted")
	}
	if err := SetPolicyOverrides(PolicyOverrides{
		MinPartSize: 2 << 20, EnableNodeSelection: true,
	}); err != nil {
		t.Fatal(err)
	}
	got, err := ResolvePolicy("https://updates.cdn-apple.com/file", GenericProfile)
	if err != nil {
		t.Fatal(err)
	}
	if got.MinPartSize != 2<<20 || !got.EnableNodeSelection {
		t.Fatalf("explicit policy overrides = %+v", got)
	}
}

func TestSingleStreamOverrideResolvesToOneOfOne(t *testing.T) {
	preservePolicyOverrides(t)
	const selectedMinPartSize = 3 << 20
	if err := SetPolicyOverrides(PolicyOverrides{
		Parts: 1, MinPartSize: selectedMinPartSize,
	}); err != nil {
		t.Fatal(err)
	}
	for _, rawURL := range []string{
		"https://updates.cdn-apple.com/file",
		"https://example.net/file",
	} {
		policy, err := ResolvePolicy(rawURL, GenericProfile)
		if err != nil {
			t.Fatal(err)
		}
		if policy.Parts != 1 || policy.MinParts != 1 ||
			policy.MinPartSize != selectedMinPartSize {
			t.Fatalf("single-stream policy for %q = %+v", rawURL, policy)
		}
	}
}

func TestResolvedPolicyReachesEngineOptions(t *testing.T) {
	preservePolicyOverrides(t)
	want := PolicyOverrides{
		Parts: 6, MinParts: 3, MinPartSize: 5 << 20, EnableNodeSelection: true,
	}
	if err := SetPolicyOverrides(want); err != nil {
		t.Fatal(err)
	}
	d := NewDownload("", false, false, false, false)
	policy, err := ResolvePolicy("https://example.net/file", GenericProfile)
	if err != nil {
		t.Fatal(err)
	}
	opts := d.options(policy)
	if opts.Parts != policy.Parts || opts.MinParts != policy.MinParts ||
		opts.MinPartSize != policy.MinPartSize || !opts.EnableNodeSelection {
		t.Fatalf("engine options = %d/%d/%d, resolved policy = %+v",
			opts.Parts, opts.MinParts, opts.MinPartSize, policy)
	}
}

func TestEngineCacheUsesOneEnginePerResolvedTuple(t *testing.T) {
	preservePolicyOverrides(t)
	d := NewDownloadWithProfile(AppleCDNProfile, "", false, false, false, false)
	d.resolveFinalURL = func(_ context.Context, u string) (string, error) { return u, nil }
	d.URL = "https://updates.cdn-apple.com/first"
	appleFirst, err := d.engineForURL(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	d.URL = "https://example.net/generic"
	generic, err := d.engineForURL(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	d.URL = "https://apple.com/second"
	appleSecond, err := d.engineForURL(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if appleFirst != appleSecond || appleFirst == generic || len(d.engines) != 2 {
		t.Fatalf("engine cache: apple reused=%v distinct generic=%v count=%d",
			appleFirst == appleSecond, appleFirst != generic, len(d.engines))
	}
	if err := SetPolicyOverrides(PolicyOverrides{EnableNodeSelection: true}); err != nil {
		t.Fatal(err)
	}
	d.URL = "https://apple.com/placed"
	applePlaced, err := d.engineForURL(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if applePlaced == appleFirst || len(d.engines) != 3 {
		t.Fatalf("engine cache did not separate placement tuple: distinct=%v count=%d",
			applePlaced != appleFirst, len(d.engines))
	}
	if err := SetPolicyOverrides(PolicyOverrides{}); err != nil {
		t.Fatal(err)
	}
	d.URL = "https://apple.com/unplaced"
	appleThird, err := d.engineForURL(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if appleThird != appleFirst || len(d.engines) != 3 {
		t.Fatalf("engine cache did not reuse original tuple: reused=%v count=%d",
			appleThird == appleFirst, len(d.engines))
	}
	d.Close()
	if d.engines != nil {
		t.Fatalf("Close left cached engines: %v", d.engines)
	}
}

func TestAuthenticatedTransportOwnershipPolicy(t *testing.T) {
	preservePolicyOverrides(t)
	proxy := func(*http.Request) (*url.URL, error) { return nil, nil }
	standard := &http.Transport{
		Proxy: proxy, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	d := NewDownloadWithProfile(AppleCDNProfile, "", false, false, false, false)
	d.client = &http.Client{Transport: standard, Jar: jar}
	policy, err := ResolvePolicy("https://updates.cdn-apple.com/file", d.fallbackProfile)
	if err != nil {
		t.Fatal(err)
	}
	policy.EnableNodeSelection = true
	opts := d.options(policy)
	// Proxy must stay nil without an explicit --proxy: go-download treats a
	// non-nil caller callback as opaque and disables node placement.
	if opts.Transport != nil || opts.Proxy != nil || opts.Jar != jar ||
		opts.TLSConfig == standard.TLSClientConfig ||
		!opts.EnableNodeSelection {
		t.Fatalf("standard authenticated transport was not decomposed: %+v", opts)
	}

	customDial := func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("unused")
	}
	d.client = &http.Client{Transport: &http.Transport{DialContext: customDial}}
	opts = d.options(policy)
	// go-download keeps placement off whenever Options.Transport is set;
	// ipsw no longer mirrors that invariant into EnableNodeSelection
	if opts.Transport == nil {
		t.Fatalf("opaque authenticated transport was not borrowed: %+v", opts)
	}
	clone, ok := opts.Transport.(*http.Transport)
	if !ok || clone == d.client.Transport || clone.Protocols == nil ||
		!clone.Protocols.HTTP1() || clone.Protocols.HTTP2() ||
		clone.MaxIdleConnsPerHost != policy.Parts+1 {
		t.Fatalf("opaque standard transport clone not HTTP/1 tuned: %+v", opts.Transport)
	}

	customTimeout := 7 * time.Second
	original := &http.Transport{ResponseHeaderTimeout: customTimeout, ReadBufferSize: 32 << 10}
	d.client = &http.Client{Transport: original}
	opts = d.options(policy)
	clone, ok = opts.Transport.(*http.Transport)
	if !ok || clone == original || clone.ResponseHeaderTimeout != customTimeout ||
		clone.ReadBufferSize != original.ReadBufferSize {
		t.Fatalf("opaque transport policy was not preserved: %+v", opts)
	}

	d.client = &http.Client{Transport: failingTransport{}}
	opts = d.options(policy)
	// placement stays engine-disabled via Options.Transport != nil
	if _, ok := opts.Transport.(borrowedRoundTripper); !ok {
		t.Fatalf("non-http transport was not borrowed: %+v", opts)
	}
}
