//go:build !ios

package download

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/99designs/keyring"
)

const syntheticAppStoreLogin = `<plist version="1.0"><dict><key>dsPersonId</key><string>12345</string><key>passwordToken</key><string>synthetic-token</string></dict></plist>`

func newTestAppStore(t *testing.T, roundTrip func(*http.Request) (*http.Response, error)) *AppStore {
	t.Helper()
	stored, err := json.Marshal(AppleAccountAuth{
		Credentials: credentials{Username: "synthetic@example.invalid", Password: "synthetic-password"},
	})
	if err != nil {
		t.Fatal(err)
	}
	as := NewAppStore(&AppStoreConfig{Context: t.Context()})
	as.Client.Transport = adcRoundTripFunc(roundTrip)
	as.Vault = keyring.NewArrayKeyring([]keyring.Item{{Key: VaultName, Data: stored}})
	t.Cleanup(as.Close)
	return as
}

func appStoreTestResponse(req *http.Request, status int, contentType, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Header:     http.Header{"Content-Type": {contentType}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
}

func TestAppStoreLoginRedirect(t *testing.T) {
	for _, status := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		for _, location := range []string{"/auth/v1/native/finish", "https://p42-buy.itunes.apple.com" + appStoreAuthPath} {
			t.Run(fmt.Sprintf("%d/%s", status, location), func(t *testing.T) {
				calls := 0
				as := newTestAppStore(t, func(req *http.Request) (*http.Response, error) {
					calls++
					if req.Method != http.MethodPost {
						t.Errorf("method = %s, want POST", req.Method)
					}
					body, err := io.ReadAll(req.Body)
					if err != nil {
						return nil, err
					}
					var login loginRequest
					if err := decodePlistResponse(body, &login); err != nil {
						return nil, err
					}
					if login.Password != "synthetic-password123456" || login.Attempt != fmt.Sprint(calls) {
						t.Errorf("redirect did not preserve credentials and increment the attempt")
					}
					if calls == 1 {
						res := appStoreTestResponse(req, status, "text/html", "<html>redirect</html>")
						res.Header.Set("Location", location)
						res.Header.Set("pod", "42")
						res.Header.Set("X-Set-Apple-Store-Front", "123456-1,1")
						return res, nil
					}
					want := location
					if strings.HasPrefix(want, "/") {
						want = appStoreURL(appStoreAuthHost, want)
					}
					if req.URL.String() != want {
						t.Errorf("redirect endpoint = %s, want %s", req.URL, want)
					}
					return appStoreTestResponse(req, http.StatusOK, "text/xml", syntheticAppStoreLogin), nil
				})
				if err := as.signInWithEndpoint("synthetic@example.invalid", "synthetic-password", "123 456", 1, "", appStoreURL(appStoreAuthHost, appStoreAuthNativePath), false); err != nil {
					t.Fatal(err)
				}
				if calls != 2 || as.pod != "42" || as.storeFront != "123456-1,1" || as.token != "synthetic-token" {
					t.Errorf("login did not retain redirect routing and session state (calls=%d)", calls)
				}
			})
		}
	}
}

func TestAppStoreLoginLegacyFallback(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusNotFound, http.StatusMovedPermanently} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			posts, bags := 0, 0
			as := newTestAppStore(t, func(req *http.Request) (*http.Response, error) {
				if req.Method == http.MethodGet {
					bags++
					return appStoreTestResponse(req, http.StatusOK, "text/xml", `<plist version="1.0"><dict><key>authenticateAccount</key><string>`+appStoreURL(appStoreBuyHost, appStoreAuthPath)+`</string></dict></plist>`), nil
				}
				posts++
				if posts == 1 {
					if req.URL.String() != appStoreURL(appStoreBuyHost, appStoreAuthPath) {
						t.Errorf("initial endpoint = %s", req.URL)
					}
					return appStoreTestResponse(req, status, "text/html", "<html>missing endpoint</html>"), nil
				}
				if req.URL.String() != appStoreURL(appStoreAuthHost, appStoreAuthNativePath) {
					t.Errorf("fallback endpoint = %s", req.URL)
				}
				return appStoreTestResponse(req, http.StatusOK, "text/xml", syntheticAppStoreLogin), nil
			})
			if err := as.signIn("synthetic@example.invalid", "synthetic-password", "", 1, ""); err != nil {
				t.Fatal(err)
			}
			if posts != 2 || bags != 1 || as.token != "synthetic-token" {
				t.Errorf("fallback posts=%d bags=%d; want one bag and two login requests", posts, bags)
			}
		})
	}
}

func TestAppStoreLoginHTTPError(t *testing.T) {
	for _, status := range []int{http.StatusMovedPermanently, http.StatusForbidden, http.StatusNotFound, http.StatusOK} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			calls := 0
			as := newTestAppStore(t, func(req *http.Request) (*http.Response, error) {
				calls++
				return appStoreTestResponse(req, status, "text/html", "<html>synthetic-private-response</html>"), nil
			})
			err := as.signInWithEndpoint("synthetic@example.invalid", "synthetic-password", "", 1, "", appStoreURL(appStoreAuthHost, appStoreAuthNativePath), false)
			if err == nil || !strings.Contains(err.Error(), fmt.Sprint(status)) || !strings.Contains(err.Error(), "text/html") || strings.Contains(err.Error(), "synthetic-private-response") {
				t.Errorf("error = %v, want HTTP metadata without response data", err)
			}
			if calls != 1 {
				t.Errorf("requests = %d, want 1", calls)
			}
		})
	}
}

func TestAppStoreLogin404Challenge(t *testing.T) {
	endpoint := appStoreURL(appStoreBuyHost, appStoreAuthPath)
	calls := 0
	as := newTestAppStore(t, func(req *http.Request) (*http.Response, error) {
		calls++
		if req.URL.String() != endpoint {
			t.Errorf("2FA endpoint changed to %s", req.URL)
		}
		if calls == 1 {
			return appStoreTestResponse(req, http.StatusNotFound, "text/xml", `<plist version="1.0"><dict><key>customerMessage</key><string>`+ErrLoginRequires2fa+`</string></dict></plist>`), nil
		}
		return appStoreTestResponse(req, http.StatusOK, "text/xml", syntheticAppStoreLogin), nil
	})
	if err := as.signInWithEndpoint("synthetic@example.invalid", "synthetic-password", "123456", 1, "", endpoint, false); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || as.token != "synthetic-token" {
		t.Errorf("2FA challenge made %d requests, want 2 and a saved session", calls)
	}
}

func TestAppStoreLoginRedirectLimit(t *testing.T) {
	calls := 0
	as := newTestAppStore(t, func(req *http.Request) (*http.Response, error) {
		calls++
		res := appStoreTestResponse(req, http.StatusMovedPermanently, "text/html", "<html>redirect</html>")
		res.Header.Set("Location", appStoreAuthNativePath)
		return res, nil
	})
	err := as.signInWithEndpoint("synthetic@example.invalid", "synthetic-password", "", 1, "", appStoreURL(appStoreAuthHost, appStoreAuthNativePath), false)
	if err == nil || err.Error() != "too many authentication attempts" || calls != 4 {
		t.Errorf("redirect loop made %d requests and returned %v", calls, err)
	}
}

func TestAppStoreLoginRejectsUnsafeRedirect(t *testing.T) {
	for _, location := range []string{
		"http://auth.itunes.apple.com/auth/v1/native/fast/",
		"https://auth.itunes.apple.com.example.invalid/",
		"https://auth.itunes.apple.com@other.example.invalid/",
		"https://auth.itunes.apple.com:8443/",
		"https://p42-buy.itunes.apple.com.example.invalid/",
	} {
		t.Run(location, func(t *testing.T) {
			calls := 0
			as := newTestAppStore(t, func(req *http.Request) (*http.Response, error) {
				calls++
				res := appStoreTestResponse(req, http.StatusTemporaryRedirect, "text/html", "<html>redirect</html>")
				res.Header.Set("Location", location)
				return res, nil
			})
			if err := as.signInWithEndpoint("synthetic@example.invalid", "synthetic-password", "", 1, "", appStoreURL(appStoreAuthHost, appStoreAuthNativePath), false); err == nil {
				t.Error("unsafe redirect succeeded")
			}
			if calls != 1 {
				t.Errorf("requests = %d, want 1", calls)
			}
		})
	}
}

func TestNormalizeAuthEndpoint(t *testing.T) {
	for _, tc := range []struct{ endpoint, want string }{
		{"https://auth.itunes.apple.com/auth/v1/native", appStoreURL(appStoreAuthHost, appStoreAuthNativePath)},
		{"https://auth.itunes.apple.com/auth/v1/native/", appStoreURL(appStoreAuthHost, appStoreAuthNativePath)},
		{"https://auth.itunes.apple.com/auth/v1/native/fast?source=synthetic", appStoreURL(appStoreAuthHost, appStoreAuthNativePath) + "?source=synthetic"},
		{"https://auth.itunes.apple.com/auth/v1/native/finish", "https://auth.itunes.apple.com/auth/v1/native/finish"},
		{"https://other.example.invalid/auth.itunes.apple.com", "https://other.example.invalid/auth.itunes.apple.com"},
		{appStoreURL(appStoreBuyHost, appStoreAuthPath), appStoreURL(appStoreBuyHost, appStoreAuthPath)},
	} {
		if got := normalizeAuthEndpoint(tc.endpoint); got != tc.want {
			t.Errorf("normalizeAuthEndpoint(%q) = %q, want %q", tc.endpoint, got, tc.want)
		}
	}
}
