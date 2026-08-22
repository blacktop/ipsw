//go:build !ios

package download

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type adcRoundTripFunc func(*http.Request) (*http.Response, error)

func (f adcRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type trackedADCBody struct {
	io.Reader
	closed atomic.Bool
}

func (b *trackedADCBody) Close() error {
	b.closed.Store(true)
	return nil
}

func TestGetADCDownloadAuthClosesResponseBody(t *testing.T) {
	body := &trackedADCBody{Reader: strings.NewReader("ignored")}
	dp := &DevPortal{
		Client: &http.Client{Transport: adcRoundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Set-Cookie": {"ADCDownloadAuth=synthetic-token"}},
				Body:       body,
			}, nil
		})},
		config: &DevConfig{Context: context.Background()},
	}

	auth, err := dp.getADCDownloadAuth("https://download.developer.apple.com/file.dmg")
	if err != nil {
		t.Fatal(err)
	}
	if auth != "synthetic-token" {
		t.Fatalf("auth = %q, want synthetic-token", auth)
	}
	if !body.closed.Load() {
		t.Fatal("ADC authentication response body was not closed")
	}
}

func TestGetADCDownloadAuthRejectsNonSuccessStatus(t *testing.T) {
	dp := &DevPortal{
		Client: &http.Client{Transport: adcRoundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusForbidden,
				Status:     "403 Forbidden",
				Header:     http.Header{},
				Body:       io.NopCloser(strings.NewReader("<html>denied</html>")),
			}, nil
		})},
		config: &DevConfig{Context: context.Background()},
	}
	_, err := dp.getADCDownloadAuth("https://download.developer.apple.com/file.dmg?accessKey=synthetic-secret")
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("getADCDownloadAuth() error = %v, want status failure naming 403", err)
	}
	if strings.Contains(err.Error(), "synthetic-secret") {
		t.Fatalf("getADCDownloadAuth() error leaks signed URL credentials: %v", err)
	}
}

func TestGetADCDownloadAuthRejectsMissingCookie(t *testing.T) {
	for name, header := range map[string]http.Header{
		"no set-cookie": {},
		"empty value":   {"Set-Cookie": {"ADCDownloadAuth="}},
		"other cookie":  {"Set-Cookie": {"session=abc"}},
	} {
		t.Run(name, func(t *testing.T) {
			dp := &DevPortal{
				Client: &http.Client{Transport: adcRoundTripFunc(func(*http.Request) (*http.Response, error) {
					return &http.Response{
						StatusCode: http.StatusOK,
						Header:     header,
						Body:       io.NopCloser(strings.NewReader("ok")),
					}, nil
				})},
				config: &DevConfig{Context: context.Background()},
			}
			_, err := dp.getADCDownloadAuth("https://download.developer.apple.com/file.dmg")
			if err == nil || !strings.Contains(err.Error(), "ADCDownloadAuth") {
				t.Fatalf("getADCDownloadAuth() error = %v, want missing-cookie failure", err)
			}
		})
	}
}

func TestGetADCDownloadAuthRedactsInvalidURL(t *testing.T) {
	dp := &DevPortal{config: &DevConfig{Context: context.Background()}}
	_, err := dp.getADCDownloadAuth("https://download.invalid/%zz?accessKey=synthetic-secret")
	if err == nil {
		t.Fatal("getADCDownloadAuth() error = nil, want malformed URL error")
	}
	if strings.Contains(err.Error(), "synthetic-secret") {
		t.Fatalf("getADCDownloadAuth() error leaks signed URL credentials: %v", err)
	}
}

func TestWaitForContextCancelsPromptly(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := waitForContext(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatalf("waitForContext() error = %v, want context.Canceled", err)
	}
}
