//go:build !ios

package download

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/99designs/keyring"
)

func TestDevPortalLoginServiceKey(t *testing.T) {
	const publicKey = "e0b80c3bf78523bfe80974d320935bfa30add02e1bff88ec2166c6bd5a706c42"
	stopAtSRP := errors.New("synthetic stop after SRP init request")
	for _, tc := range []struct {
		name         string
		storedKey    string
		sessionValid bool
		completeSRP  bool
	}{
		{name: "first login"},
		{name: "expired session", storedKey: "synthetic-old-key"},
		{name: "expired session signs in", storedKey: "synthetic-old-key", completeSRP: true},
		{name: "valid session", storedKey: "synthetic-cached-key", sessionValid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stored, err := json.Marshal(AppleAccountAuth{
				Credentials:      credentials{Username: "synthetic@example.invalid", Password: "synthetic-password"},
				DevPortalSession: session{WidgetKey: tc.storedKey},
			})
			if err != nil {
				t.Fatal(err)
			}
			vault := keyring.NewArrayKeyring([]keyring.Item{{Key: VaultName, Data: stored}})
			jar, err := newDevPortalCookieJar()
			if err != nil {
				t.Fatal(err)
			}
			var requests []string
			dp := &DevPortal{
				Vault:  vault,
				config: &DevConfig{Context: t.Context()},
				Client: &http.Client{Jar: jar, Transport: adcRoundTripFunc(func(req *http.Request) (*http.Response, error) {
					request := req.Method + " " + req.URL.String()
					requests = append(requests, request)
					status, body := http.StatusOK, `{}`
					switch request {
					case "GET " + olympusSessionURL:
						if !tc.sessionValid {
							status = http.StatusUnauthorized
						}
					case "GET https://appstoreconnect.apple.com/olympus/v1/app/config?hostname=itunesconnect.apple.com":
						status, body = http.StatusNotFound, "<html>Not Found</html>"
					case "GET " + loginURL:
					case "POST " + initURL:
						if got := req.Header.Get("X-Apple-Widget-Key"); got != publicKey {
							t.Errorf("SRP init widget key = %q, want current public key", got)
						}
						if !tc.completeSRP {
							return nil, stopAtSRP
						}
						body = syntheticSRPInit(t)
					case "POST " + completeURL:
					default:
						return nil, fmt.Errorf("unexpected request: %s %s", req.Method, req.URL)
					}
					return &http.Response{
						StatusCode: status,
						Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
						Header:     make(http.Header),
						Body:       io.NopCloser(strings.NewReader(body)),
					}, nil
				})},
			}
			var wantErr error
			if !tc.sessionValid && !tc.completeSRP {
				wantErr = stopAtSRP
			}
			if err := dp.Login("", ""); !errors.Is(err, wantErr) {
				t.Fatalf("Login() error = %v, want %v", err, wantErr)
			}
			wantRequests := []string{"GET " + olympusSessionURL}
			wantKey := tc.storedKey // Failed authentication must not save a new session.
			if !tc.sessionValid {
				wantRequests = append(wantRequests, "GET "+loginURL, "POST "+initURL)
			}
			if tc.completeSRP {
				wantRequests = append(wantRequests, "POST "+completeURL)
				wantKey = publicKey // A completed sign-in persists the refreshed service key.
			}
			if !slices.Equal(requests, wantRequests) {
				t.Errorf("requests = %v, want %v", requests, wantRequests)
			}
			item, err := vault.Get(VaultName)
			if err != nil {
				t.Fatal(err)
			}
			var saved AppleAccountAuth
			if err := json.Unmarshal(item.Data, &saved); err != nil {
				t.Fatal(err)
			}
			if saved.DevPortalSession.WidgetKey != wantKey {
				t.Errorf("saved widget key = %q, want %q", saved.DevPortalSession.WidgetKey, wantKey)
			}
		})
	}
}

func TestDevPortalLoginSRPRejectedHint(t *testing.T) {
	const hint = "stored in the \"" + VaultName + "\" entry"
	const rejection = `{"serviceErrors":[{"code":"-20101","message":"synthetic bad password"}]}`
	for _, tc := range []struct {
		name               string
		savedAccount       bool
		username, password string
		rejectAtInit       bool
		initOutage         bool
		wantHint           bool
	}{
		{name: "vault credentials", savedAccount: true, wantHint: true},
		{name: "explicit credentials with saved account", savedAccount: true, username: "other@example.invalid", password: "typed-password"},
		{name: "first run discards rejected credentials", username: "synthetic@example.invalid", password: "typed-password"},
		{name: "first run discards credentials on outage", username: "synthetic@example.invalid", password: "typed-password", initOutage: true},
		{name: "rejected at init", savedAccount: true, rejectAtInit: true, wantHint: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var items []keyring.Item
			if tc.savedAccount {
				stored, err := json.Marshal(AppleAccountAuth{Credentials: credentials{Username: "synthetic@example.invalid", Password: "synthetic-password"}})
				if err != nil {
					t.Fatal(err)
				}
				items = append(items, keyring.Item{Key: VaultName, Data: stored})
			}
			jar, err := newDevPortalCookieJar()
			if err != nil {
				t.Fatal(err)
			}
			dp := &DevPortal{
				Vault:  keyring.NewArrayKeyring(items),
				config: &DevConfig{Context: t.Context()},
				Client: &http.Client{Jar: jar, Transport: adcRoundTripFunc(func(req *http.Request) (*http.Response, error) {
					status, body := http.StatusOK, `{}`
					switch req.Method + " " + req.URL.String() {
					case "GET " + olympusSessionURL:
						status = http.StatusUnauthorized
					case "GET " + loginURL:
					case "POST " + initURL:
						body = syntheticSRPInit(t)
						if tc.rejectAtInit {
							status, body = http.StatusUnauthorized, rejection
						}
						if tc.initOutage {
							status, body = http.StatusServiceUnavailable, "<html>maintenance</html>"
						}
					case "POST " + completeURL:
						status, body = http.StatusUnauthorized, rejection
					default:
						return nil, fmt.Errorf("unexpected request: %s %s", req.Method, req.URL)
					}
					return &http.Response{
						StatusCode: status,
						Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
						Header:     make(http.Header),
						Body:       io.NopCloser(strings.NewReader(body)),
					}, nil
				})},
			}
			err = dp.Login(tc.username, tc.password)
			if err == nil {
				t.Fatal("Login() succeeded, want failure")
			}
			if !tc.initOutage && !errors.Is(err, errSRPRejected) {
				t.Fatalf("Login() error = %v, want errSRPRejected", err)
			}
			if tc.initOutage && errors.Is(err, errSRPRejected) {
				t.Fatalf("Login() error = %v classified as rejection, want plain failure", err)
			}
			if got := strings.Contains(err.Error(), hint); got != tc.wantHint {
				t.Errorf("hint present = %v, want %v: %v", got, tc.wantHint, err)
			}
			_, vaultErr := dp.Vault.Get(VaultName)
			if tc.savedAccount && vaultErr != nil {
				t.Errorf("saved account removed: %v", vaultErr)
			}
			if !tc.savedAccount && !errors.Is(vaultErr, keyring.ErrKeyNotFound) {
				t.Errorf("rejected first-run credentials kept in vault (err=%v)", vaultErr)
			}
		})
	}
}
