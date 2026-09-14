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
		srp          bool
	}{
		{name: "first login"},
		{name: "expired session", storedKey: "synthetic-old-key"},
		{name: "expired session SRP", storedKey: "synthetic-old-key", srp: true},
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
					case "POST " + loginURL:
						if got := req.Header.Get("X-Apple-Widget-Key"); got != publicKey {
							t.Errorf("sign-in widget key = %q, want current public key", got)
						}
						if tc.srp {
							status = http.StatusServiceUnavailable
						}
					case "POST " + initURL:
						if got := req.Header.Get("X-Apple-Widget-Key"); got != publicKey {
							t.Errorf("SRP init widget key = %q, want current public key", got)
						}
						return nil, stopAtSRP
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
			if tc.srp {
				wantErr = stopAtSRP
			}
			if err := dp.Login("", ""); !errors.Is(err, wantErr) {
				t.Fatalf("Login() error = %v, want %v", err, wantErr)
			}
			wantRequests := []string{"GET " + olympusSessionURL}
			wantKey := tc.storedKey
			if !tc.sessionValid {
				wantRequests = append(wantRequests, "GET "+loginURL, "POST "+loginURL)
				wantKey = publicKey
			}
			if tc.srp {
				wantRequests = append(wantRequests, "POST "+initURL)
				wantKey = tc.storedKey // Failed authentication must not save a new session.
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
