//go:build !ios

package download

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestDevPortalHashcashResponse(t *testing.T) {
	for _, tc := range []struct {
		name, bits, challenge, wantErr string
		status                         int
	}{
		{name: "absent", status: 200},
		{name: "complete", bits: "1", challenge: "synthetic-challenge", status: 200},
		{name: "challenge only", challenge: "synthetic-challenge", status: 200, wantErr: "incomplete hashcash"},
		{name: "bits only", bits: "1", status: 200, wantErr: "incomplete hashcash"},
		{name: "impossible bits", bits: "33", challenge: "synthetic-challenge", status: 200, wantErr: "hashcash bits"},
		{name: "invalid bits", bits: "-1", challenge: "synthetic-challenge", status: 200, wantErr: "hashcash bits"},
		{name: "HTTP error", status: 503, wantErr: "hashcash headers: HTTP 503"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := &trackedADCBody{Reader: strings.NewReader("synthetic page")}
			dp := NewDevPortal(&DevConfig{Context: t.Context(), HashCash: "stale"})
			dp.Client.Transport = adcRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				h := make(http.Header)
				h.Set(hashcashBitsHeader, tc.bits)
				h.Set(hashcashCallengeHeader, tc.challenge)
				return &http.Response{StatusCode: tc.status, Header: h, Body: body}, nil
			})
			err := dp.getHashcachHeaders()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error = %v, want %q", err, tc.wantErr)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if !body.closed.Load() {
				t.Error("response body not closed")
			}
			remaining, _ := io.ReadAll(body)
			if len(remaining) != 0 {
				t.Error("response body not drained")
			}
			if tc.name == "absent" && dp.config.HashCash != "" {
				t.Error("stale hashcash retained")
			}
			if tc.name == "complete" && !strings.Contains(dp.config.HashCash, ":synthetic-challenge::") {
				t.Error("challenge not used")
			}
		})
	}
}

func TestDevPortalSRPInitErrors(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
		status           int
	}{
		{"HTML error", "<html>synthetic-private</html>", "SRP init: HTTP 503", 503},
		{"empty body", "", "SRP init", 200},
		{"empty object", "{}", "incomplete SRP init", 200},
		{"missing salt", `{"iteration":1,"b":"Ag==","c":"synthetic"}`, "incomplete SRP init", 200},
		{"invalid iteration", `{"iteration":-1,"salt":"AQ==","b":"Ag==","c":"synthetic"}`, "incomplete SRP init", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			body := &trackedADCBody{Reader: strings.NewReader(tc.body)}
			dp := NewDevPortal(&DevConfig{Context: t.Context()})
			dp.Client.Transport = adcRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				if req.URL.String() != initURL {
					return nil, errors.New("unexpected request")
				}
				return &http.Response{StatusCode: tc.status, Header: make(http.Header), Body: body}, nil
			})
			_, err := dp.generateSRP("synthetic@example.invalid", "synthetic-password")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want %q", err, tc.want)
			}
			if err != nil && strings.Contains(err.Error(), "synthetic-private") {
				t.Error("response body leaked")
			}
			if calls != 1 {
				t.Errorf("requests = %d, want 1", calls)
			}
			if !body.closed.Load() {
				t.Error("response body not closed")
			}
		})
	}
}

func TestDevPortalHashcashCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	dp := NewDevPortal(&DevConfig{Context: ctx, HashCashBits: "32", HashCashChallenge: "synthetic"})
	if _, err := dp.generateHashCash(); !errors.Is(err, context.Canceled) {
		t.Fatalf("generateHashCash() error=%v", err)
	}
	dp.Client.Transport = adcRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Context() != ctx {
			t.Error("request lost caller context")
		}
		return nil, req.Context().Err()
	})
	if err := dp.getHashcachHeaders(); !errors.Is(err, context.Canceled) {
		t.Fatalf("getHashcachHeaders() error=%v", err)
	}
}
