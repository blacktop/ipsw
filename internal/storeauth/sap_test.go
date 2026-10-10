package storeauth

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/blacktop/go-plist"
)

type syntheticSAP struct {
	step   int
	closed int
	fail   int
}

func (s *syntheticSAP) handshake(data []byte) ([]byte, error) {
	if s.step != 0 || string(data) != "synthetic certificate" || s.fail == 1 {
		return nil, errors.New("synthetic handshake failure")
	}
	s.step++
	return []byte("synthetic request"), nil
}

func (s *syntheticSAP) complete(data []byte) error {
	if s.step != 1 || string(data) != "synthetic reply" || s.fail == 2 {
		return errors.New("synthetic completion failure")
	}
	s.step++
	return nil
}

func (s *syntheticSAP) sign(data []byte) ([]byte, error) {
	if s.step < 2 || s.closed != 0 {
		return nil, errors.New("synthetic signer is not ready")
	}
	s.step++
	return append([]byte("synthetic signature:"), data...), nil
}

func (s *syntheticSAP) close() { s.closed++ }

type sapRoundTrip func(*http.Request) (*http.Response, error)

func (f sapRoundTrip) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func syntheticSAPResponse(t *testing.T, req *http.Request, key, value string) *http.Response {
	t.Helper()
	data, err := plist.Marshal(map[string]any{key: []byte(value)}, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(data)), Request: req}
}

func sapTestClient(t *testing.T, calls *int) *http.Client {
	t.Helper()
	return &http.Client{Transport: sapRoundTrip(func(req *http.Request) (*http.Response, error) {
		*calls++
		if deadline, ok := req.Context().Deadline(); !ok || time.Until(deadline) > 30*time.Second {
			t.Error("SAP request has no bounded deadline")
		}
		switch req.URL.String() {
		case sapCertificateURL:
			if req.Method != http.MethodGet {
				t.Error("certificate method is not GET")
			}
			return syntheticSAPResponse(t, req, "sign-sap-setup-cert", "synthetic certificate"), nil
		case sapSetupURL:
			if req.Method != http.MethodPost || req.Header.Get("Content-Type") != "application/x-plist" {
				t.Error("setup request profile changed")
			}
			data, err := io.ReadAll(req.Body)
			if err != nil {
				return nil, err
			}
			var values map[string]any
			if _, err := plist.Unmarshal(data, &values); err != nil || len(values) != 1 || !bytes.Equal(values["sign-sap-setup-buffer"].([]byte), []byte("synthetic request")) {
				t.Fatal("setup body did not contain the native exchange output")
			}
			return syntheticSAPResponse(t, req, "sign-sap-setup-buffer", "synthetic reply"), nil
		default:
			t.Fatalf("unexpected SAP destination: %s", req.URL)
			return nil, nil
		}
	})}
}

func TestSAPSession(t *testing.T) {
	var requests int
	native := &syntheticSAP{}
	session, err := setupSAPSession(t.Context(), sapTestClient(t, &requests), native)
	if err != nil {
		t.Fatal(err)
	}
	for _, message := range []string{"one", "two"} {
		signature, err := session.Sign(t.Context(), []byte(message))
		if err != nil || string(signature) != "synthetic signature:"+message {
			t.Fatalf("incorrect signed message: %v", err)
		}
	}
	session.Close()
	session.Close()
	if _, err := session.Sign(t.Context(), []byte("closed")); err == nil {
		t.Error("closed session signed a request")
	}
	if requests != 2 || native.step != 4 || native.closed != 1 {
		t.Errorf("requests=%d native step=%d closes=%d", requests, native.step, native.closed)
	}
}

func TestSAPSetupFailureClosesSession(t *testing.T) {
	for _, stage := range []int{1, 2} {
		var requests int
		native := &syntheticSAP{fail: stage}
		if _, err := setupSAPSession(t.Context(), sapTestClient(t, &requests), native); err == nil {
			t.Fatal("failed native exchange accepted")
		}
		if requests != stage || native.closed != 1 {
			t.Errorf("stage=%d requests=%d closes=%d", stage, requests, native.closed)
		}
	}
}

func TestSAPRequestBounds(t *testing.T) {
	for _, body := range []string{"", "<html>synthetic private response</html>", strings.Repeat("x", maxSAPResponse+1)} {
		client := &http.Client{Transport: sapRoundTrip(func(req *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
		})}
		_, err := sapRequest(t.Context(), client, sapCertificateURL, nil, "sign-sap-setup-cert")
		if err == nil || strings.Contains(err.Error(), "synthetic private") {
			t.Errorf("invalid response error=%v", err)
		}
	}
	requests := 0
	client := &http.Client{Transport: sapRoundTrip(func(req *http.Request) (*http.Response, error) {
		requests++
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": {"https://example.invalid/"}}, Body: http.NoBody, Request: req}, nil
	})}
	if _, err := sapRequest(t.Context(), client, sapCertificateURL, nil, "sign-sap-setup-cert"); err == nil || requests != 1 {
		t.Errorf("redirect requests=%d error=%v", requests, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := NewSAPSession(ctx, client); !errors.Is(err, context.Canceled) || requests != 1 {
		t.Errorf("canceled setup requests=%d error=%v", requests, err)
	}
}
