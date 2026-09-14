//go:build !ios

package download

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestDevPortalCookieScopes(t *testing.T) {
	dp := testDevPortalWithSession(t)
	idmsa := &url.URL{Scheme: "https", Host: "idmsa.apple.com", Path: "/appleauth/auth/signin"}
	asc := &url.URL{Scheme: "https", Host: "appstoreconnect.apple.com", Path: "/olympus/v1/session"}
	dp.Client.Jar.SetCookies(idmsa, []*http.Cookie{
		{Name: "shared", Value: "synthetic", Domain: ".apple.com", Path: "/", Secure: true},
		{Name: "idmsa-only", Value: "synthetic", Path: "/appleauth", Secure: true},
		{Name: "default-path", Value: "synthetic", Secure: true},
		{Name: "deleted", Value: "synthetic", Domain: ".apple.com", Path: "/"},
		{Name: "expired", Value: "synthetic", Path: "/", Expires: time.Now().Add(-time.Hour)},
		{Name: "relative", Value: "synthetic", MaxAge: 60, Path: "/"},
	})
	dp.Client.Jar.SetCookies(asc, []*http.Cookie{
		{Name: "asc-path", Value: "synthetic", Path: "/olympus", Secure: true},
		{Name: "deleted", Domain: ".apple.com", Path: "/", MaxAge: -1},
		{Name: "shared", Value: "invalid-domain", Domain: "example.invalid", Path: "/"},
	})
	if err := dp.storeSession(); err != nil {
		t.Fatal(err)
	}
	jar, err := newDevPortalCookieJar()
	if err != nil {
		t.Fatal(err)
	}
	item, err := dp.Vault.Get(VaultName)
	if err != nil {
		t.Fatal(err)
	}
	var account AppleAccountAuth
	if err := json.Unmarshal(item.Data, &account); err != nil {
		t.Fatal(err)
	}
	records := account.DevPortalSession.CookieRecords
	for _, record := range records {
		if record.Cookie.Name == "relative" && (record.Cookie.MaxAge != 0 || record.Cookie.Expires.IsZero()) {
			t.Error("relative lifetime was not frozen")
		}
		u, err := url.Parse(record.URL)
		if err != nil {
			t.Fatal(err)
		}
		jar.SetCookies(u, []*http.Cookie{&record.Cookie})
	}
	for _, raw := range []string{
		"https://idmsa.apple.com/", "https://idmsa.apple.com/appleauth/auth/signin",
		"https://idmsa.apple.com/appleauth/auth/2sv/trust", "http://idmsa.apple.com/appleauth/auth/signin",
		"https://appstoreconnect.apple.com/", "https://appstoreconnect.apple.com/olympus/v1/session",
		"https://developer.apple.com/services-account/QH65B2/downloadws/listDownloads.action",
		"https://developerservices2.apple.com/services/download", "https://unrelated.invalid/",
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := jar.Cookies(u), dp.Client.Jar.Cookies(u); !reflect.DeepEqual(got, want) {
			t.Errorf("cookie scope differs at %s: got %v, want %v", raw, got, want)
		}
	}
	// Repeated updates retain one scoped record and the latest value, even when
	// the shared domain cookie comes from a different Apple host.
	before := len(jar.snapshot())
	jar.SetCookies(asc, []*http.Cookie{{Name: "shared", Value: "updated", Domain: ".apple.com", Path: "/", Secure: true}})
	if len(jar.snapshot()) != before {
		t.Error("duplicate shared-domain record")
	}
	jar.SetCookies(idmsa, []*http.Cookie{{Name: "shared", Domain: ".apple.com", Path: "/", MaxAge: -1}})
	if len(jar.snapshot()) != before-1 {
		t.Error("domain deletion not retained")
	}
}

func TestDevPortalCookieExpiryOrder(t *testing.T) {
	jar, err := newDevPortalCookieJar()
	if err != nil {
		t.Fatal(err)
	}
	u := &url.URL{Scheme: "https", Host: "idmsa.apple.com", Path: "/"}
	jar.SetCookies(u, []*http.Cookie{{Name: "session", Value: "old-domain", Domain: ".apple.com", Path: "/"}, {Name: "session", Value: "host-only", Path: "/"}})
	// Simulate expiry of the domain cookie in both the live jar and its record.
	expired := jar.records[0].Cookie
	expired.Expires = time.Now().Add(-time.Hour)
	jar.records[0].Cookie = expired
	jar.Jar.SetCookies(u, []*http.Cookie{&expired})
	jar.SetCookies(u, []*http.Cookie{{Name: "session", Value: "new-domain", Domain: ".apple.com", Path: "/"}})
	restored, err := newDevPortalCookieJar()
	if err != nil {
		t.Fatal(err)
	}
	for _, record := range jar.snapshot() {
		origin, err := url.Parse(record.URL)
		if err != nil {
			t.Fatal(err)
		}
		restored.SetCookies(origin, []*http.Cookie{&record.Cookie})
	}
	if got, want := restored.Cookies(u), jar.Cookies(u); !reflect.DeepEqual(got, want) {
		t.Fatalf("cookie order changed: got %v, want %v", got, want)
	}
}

func TestDevPortalCookieJarConcurrentSnapshots(t *testing.T) {
	jar, err := newDevPortalCookieJar()
	if err != nil {
		t.Fatal(err)
	}
	u := &url.URL{Scheme: "https", Host: "idmsa.apple.com", Path: "/"}
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			for range 20 {
				jar.SetCookies(u, []*http.Cookie{{Name: "session", Value: "synthetic", Path: "/"}})
				jar.Cookies(u)
				jar.snapshot()
			}
		})
	}
	group.Wait()
	if len(jar.snapshot()) != 1 {
		t.Fatal("repeated updates grew cookie records")
	}
}

// Compare with an independent standard jar so a bug shared by the live wrapper
// and its restored copy cannot make the round-trip assertions pass.
func TestDevPortalCookieJarMatchesStandardJar(t *testing.T) {
	jar, err := newDevPortalCookieJar()
	if err != nil {
		t.Fatal(err)
	}
	standard, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		origin  string
		cookies []*http.Cookie
	}{
		{"https://idmsa.apple.com/appleauth/auth/signin", []*http.Cookie{
			{Name: "session", Value: "domain", Domain: ".apple.com", Path: "/", Secure: true},
			{Name: "session", Value: "host", Path: "/"},
			{Name: "path", Value: "default"},
			{Name: "relative", Value: "live", MaxAge: 60, Expires: time.Now().Add(-time.Hour)},
		}},
		{"https://appstoreconnect.apple.com/olympus/v1/session", []*http.Cookie{
			{Name: "session", Value: "updated-domain", Domain: "apple.com", Path: "/", Secure: true},
			{Name: "session", Value: "asc-path", Path: "/olympus"},
			{Name: "session", Value: "invalid", Domain: "idmsa.apple.com", Path: "/"},
		}},
		{"https://IDMSA.APPLE.COM./appleauth/auth/signin", []*http.Cookie{
			{Name: "session", Value: "updated-host", Path: "/"},
			{Name: "path", Value: "deleted", MaxAge: -1},
		}},
		{"http://idmsa.apple.com/", []*http.Cookie{
			{Name: "secure-http", Value: "secure", Secure: true, Path: "/"},
			{Name: "session", Value: "invalid-domain", Domain: "..apple.com", Path: "/"},
		}},
		{"https://developer.apple.com/account/", []*http.Cookie{
			{Name: "session", Domain: ".apple.com", Path: "/", MaxAge: -1},
		}},
	} {
		origin, err := url.Parse(step.origin)
		if err != nil {
			t.Fatal(err)
		}
		jar.SetCookies(origin, step.cookies)
		standard.SetCookies(origin, step.cookies)
		restored, err := newDevPortalCookieJar()
		if err != nil {
			t.Fatal(err)
		}
		for _, record := range jar.snapshot() {
			origin, err := url.Parse(record.URL)
			if err != nil {
				t.Fatal(err)
			}
			restored.SetCookies(origin, []*http.Cookie{&record.Cookie})
		}
		for _, raw := range []string{
			"https://idmsa.apple.com/", "http://idmsa.apple.com/",
			"https://idmsa.apple.com/appleauth/auth/signin",
			"https://appstoreconnect.apple.com/olympus/v1/session",
			"https://developerservices2.apple.com/services/download",
			"https://unrelated.invalid/",
		} {
			target, err := url.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			want := standard.Cookies(target)
			if got := jar.Cookies(target); !reflect.DeepEqual(got, want) {
				t.Errorf("live jar after %s at %s: got %v, want %v", step.origin, raw, got, want)
			}
			if got := restored.Cookies(target); !reflect.DeepEqual(got, want) {
				t.Errorf("restored jar after %s at %s: got %v, want %v", step.origin, raw, got, want)
			}
		}
	}
}
