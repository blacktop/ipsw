//go:build !ios

package download

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/99designs/keyring"
	"github.com/blacktop/ipsw/internal/srp"
)

// syntheticSRPInit is a well-formed SRP init body; the values are arbitrary
// but B must be non-zero so the client accepts it.
func syntheticSRPInit(t *testing.T) string {
	t.Helper()
	body, err := json.Marshal(srpInitResponse{
		Iteration: 1000,
		Salt:      base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32)),
		Protocol:  string(srp.ProtocolS2K),
		B:         base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 256)),
		C:         "synthetic-c",
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func testDevPortalWithSession(t *testing.T) *DevPortal {
	t.Helper()
	data, err := json.Marshal(AppleAccountAuth{Credentials: credentials{Username: "synthetic@example.invalid", Password: "synthetic-password"}, DevPortalSession: session{WidgetKey: "old", SessionID: "stale-session", SCNT: "stale-scnt", HashCash: "stale-hash"}})
	if err != nil {
		t.Fatal(err)
	}
	dp := NewDevPortal(&DevConfig{Context: t.Context()})
	dp.Vault = keyring.NewArrayKeyring([]keyring.Item{{Key: VaultName, Data: data}})
	return dp
}

func TestDevPortalSessionCookiesRoundTrip(t *testing.T) {
	dp := testDevPortalWithSession(t)
	idmsa := &url.URL{Scheme: "https", Host: "idmsa.apple.com"}
	asc := &url.URL{Scheme: "https", Host: "appstoreconnect.apple.com"}
	dp.Client.Jar.SetCookies(idmsa, []*http.Cookie{{Name: "shared", Value: "synthetic-shared", Domain: ".apple.com", Path: "/", Secure: true}, {Name: "idmsa-only", Value: "synthetic-idmsa", Path: "/", Secure: true}})
	dp.Client.Jar.SetCookies(asc, []*http.Cookie{{Name: "asc-only", Value: "synthetic-asc", Path: "/", Secure: true}})
	if err := dp.storeSession(); err != nil {
		t.Fatal(err)
	}
	restored := NewDevPortal(&DevConfig{Context: t.Context()})
	restored.Vault = dp.Vault
	restored.Client.Transport = adcRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != olympusSessionURL {
			return nil, errors.New("unexpected sign-in request")
		}
		for _, name := range []string{"shared", "asc-only"} {
			if _, err := req.Cookie(name); err != nil {
				t.Errorf("missing %s cookie", name)
			}
		}
		if _, err := req.Cookie("idmsa-only"); err == nil {
			t.Error("host-only cookie leaked to ASC")
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	})
	if err := restored.Login("", ""); err != nil {
		t.Fatal(err)
	}
}

func TestDevPortalSessionFailureDoesNotReauthenticate(t *testing.T) {
	transportErr := errors.New("synthetic network error")
	for _, tc := range []struct {
		name, body string
		status     int
		err        error
	}{
		{name: "network", err: transportErr}, {name: "server", status: 503, body: "<html>unavailable</html>"}, {name: "malformed", status: 200, body: "<html>bad response</html>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, refresh := range []bool{false, true} {
				dp := testDevPortalWithSession(t)
				calls := 0
				dp.Client.Transport = adcRoundTripFunc(func(req *http.Request) (*http.Response, error) {
					calls++
					if req.URL.String() != olympusSessionURL {
						return nil, errors.New("unexpected sign-in request")
					}
					if tc.err != nil {
						return nil, tc.err
					}
					return &http.Response{StatusCode: tc.status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(tc.body))}, nil
				})
				var err error
				if refresh {
					err = dp.refreshSession()
				} else {
					err = dp.Login("", "")
				}
				if err == nil {
					t.Error("session failure ignored")
				}
				if tc.err != nil && !errors.Is(err, tc.err) {
					t.Errorf("lost transport error: %v", err)
				}
				if calls != 1 {
					t.Errorf("refresh=%v requests=%d, want 1", refresh, calls)
				}
			}
		})
	}
}

func TestDevPortalRejectedSessionStartsClean(t *testing.T) {
	for _, refresh := range []bool{false, true} {
		dp := testDevPortalWithSession(t)
		dp.config.HashCashBits = "1"
		dp.config.HashCashChallenge = "stale-challenge"
		dp.Client.Jar.SetCookies(&url.URL{Scheme: "https", Host: "idmsa.apple.com"}, []*http.Cookie{{Name: "stale", Value: "synthetic", Path: "/"}})
		checks, signins := 0, 0
		dp.Client.Transport = adcRoundTripFunc(func(req *http.Request) (*http.Response, error) {
			status, body := 200, `{}`
			switch req.Method + " " + req.URL.String() {
			case "GET " + olympusSessionURL:
				checks++
				status = 401
			case "GET " + loginURL:
				if len(req.Cookies()) != 0 {
					t.Error("stale cookies sent")
				}
				if dp.config.SessionID != "" || dp.config.SCNT != "" || dp.config.HashCash != "" || dp.config.HashCashBits != "" || dp.config.HashCashChallenge != "" {
					t.Error("stale auth state retained")
				}
			case "POST " + initURL:
				if req.Header.Get(hashcashHeader) != "" {
					t.Error("stale hashcash sent")
				}
				body = syntheticSRPInit(t)
			case "POST " + completeURL:
				signins++
			default:
				return nil, errors.New("unexpected request")
			}
			return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
		})
		var err error
		if refresh {
			err = dp.refreshSession()
		} else {
			err = dp.Login("", "")
		}
		if err != nil {
			t.Fatal(err)
		}
		if checks != 1 || signins != 1 {
			t.Errorf("refresh=%v checks=%d signins=%d", refresh, checks, signins)
		}
	}
}

type countingDevVault struct {
	keyring.Keyring
	reads   int
	readErr error
}

func (v *countingDevVault) Get(key string) (keyring.Item, error) {
	v.reads++
	if v.readErr != nil {
		return keyring.Item{}, v.readErr
	}
	return v.Keyring.Get(key)
}

func TestDevPortalVaultReadFailures(t *testing.T) {
	failure := errors.New("synthetic locked vault")
	for _, tc := range []struct {
		name    string
		data    []byte
		readErr error
	}{
		{name: "locked", readErr: failure}, {name: "malformed", data: []byte("invalid JSON")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dp := NewDevPortal(&DevConfig{Context: t.Context()})
			dp.Vault = &countingDevVault{Keyring: keyring.NewArrayKeyring([]keyring.Item{{Key: VaultName, Data: tc.data}}), readErr: tc.readErr}
			dp.Client.Transport = adcRoundTripFunc(func(*http.Request) (*http.Response, error) {
				t.Error("network request after vault failure")
				return nil, errors.New("unexpected request")
			})
			err := dp.Login("synthetic@example.invalid", "synthetic-password")
			if err == nil {
				t.Fatal("vault failure ignored")
			}
			if tc.readErr != nil && !errors.Is(err, tc.readErr) {
				t.Errorf("lost vault error: %v", err)
			}
		})
	}
}

func TestDevPortalVaultReadsAndNewAccount(t *testing.T) {
	for _, mode := range []string{"valid", "expired", "new"} {
		t.Run(mode, func(t *testing.T) {
			dp := testDevPortalWithSession(t)
			if mode == "new" {
				dp.Vault = keyring.NewArrayKeyring(nil)
			}
			vault := &countingDevVault{Keyring: dp.Vault}
			dp.Vault = vault
			dp.Client.Transport = adcRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				status, body := 200, `{}`
				switch req.URL.String() {
				case olympusSessionURL:
					if mode == "new" {
						t.Error("checked nonexistent session")
					}
					if mode == "expired" {
						status = 401
					}
				case initURL:
					body = syntheticSRPInit(t)
				}
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
			})
			if err := dp.Login("synthetic@example.invalid", "synthetic-password"); err != nil {
				t.Fatal(err)
			}
			wantReads := 2
			if mode == "valid" {
				wantReads = 1
			}
			if vault.reads != wantReads {
				t.Errorf("vault reads=%d, want %d", vault.reads, wantReads)
			}
			item, err := vault.Keyring.Get(VaultName)
			if err != nil {
				t.Fatal(err)
			}
			var stored AppleAccountAuth
			if err := json.Unmarshal(item.Data, &stored); err != nil {
				t.Fatal(err)
			}
			if stored.Credentials.Username != "synthetic@example.invalid" || stored.Credentials.Password != "synthetic-password" {
				t.Error("credentials not preserved")
			}
			if mode != "valid" && len(stored.DevPortalSession.Cookies) != 0 {
				t.Error("legacy cookies retained after renewal")
			}
		})
	}
}
