package storeauth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/blacktop/go-plist"
)

const (
	sapCertificateURL = "https://s.mzstatic.com/sap/setupCert.plist"
	sapSetupURL       = "https://fpinit.itunes.apple.com/v1/signSapSetup/legacy"
	sapUserAgent      = "Configurator/2.18 (Macintosh; OS X 15.4.1; 24E263) AppleWebKit/0621.1.15.11.10"
	maxSAPResponse    = 1 << 20
)

type sapNative interface {
	handshake([]byte) ([]byte, error)
	complete([]byte) error
	sign([]byte) ([]byte, error)
	close()
}

// SAPSession owns a native SAP 200 session. Close it after the authentication
// attempt, including all redirects and verification-code submissions.
type SAPSession struct {
	mu     sync.Mutex
	native sapNative
}

// NewSAPSession provisions the local macOS Osprey signer using Apple's public
// SAP endpoints. All network requests use the caller's transport and cookie jar.
// Unsupported platforms return ErrNativeUnavailable before making a request.
func NewSAPSession(ctx context.Context, client *http.Client) (*SAPSession, error) {
	if err := nativeContextError(ctx); err != nil {
		return nil, err
	}
	if client == nil {
		return nil, errors.New("SAP setup requires an HTTP client")
	}
	native, err := openNativeSAP()
	if err != nil {
		return nil, err
	}
	return setupSAPSession(ctx, client, native)
}

func setupSAPSession(ctx context.Context, client *http.Client, native sapNative) (_ *SAPSession, err error) {
	defer func() {
		if err != nil {
			native.close()
		}
	}()
	certificate, err := sapRequest(ctx, client, sapCertificateURL, nil, "sign-sap-setup-cert")
	if err != nil {
		return nil, fmt.Errorf("get SAP certificate: %w", err)
	}
	outgoing, err := native.handshake(certificate)
	if err != nil {
		return nil, fmt.Errorf("begin native SAP handshake: %w", err)
	}
	if len(outgoing) == 0 || len(outgoing) > maxSAPResponse {
		return nil, errors.New("native SAP handshake returned an invalid request")
	}
	body, err := plist.Marshal(map[string]any{"sign-sap-setup-buffer": outgoing}, plist.XMLFormat)
	if err != nil {
		return nil, errors.New("encode SAP setup request")
	}
	incoming, err := sapRequest(ctx, client, sapSetupURL, body, "sign-sap-setup-buffer")
	if err != nil {
		return nil, fmt.Errorf("exchange SAP setup: %w", err)
	}
	if err := native.complete(incoming); err != nil {
		return nil, fmt.Errorf("complete native SAP handshake: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &SAPSession{native: native}, nil
}

func sapRequest(ctx context.Context, source *http.Client, endpoint string, body []byte, key string) ([]byte, error) {
	method := http.MethodGet
	if body != nil {
		method = http.MethodPost
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("create SAP request")
	}
	req.Header.Set("User-Agent", sapUserAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/x-plist")
	}
	client := *source
	if client.Timeout <= 0 || client.Timeout > 30*time.Second {
		client.Timeout = 30 * time.Second
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", res.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, maxSAPResponse+1))
	if err != nil {
		return nil, errors.New("read SAP response")
	}
	if len(data) == 0 || len(data) > maxSAPResponse {
		return nil, errors.New("invalid SAP response size")
	}
	values, err := decodeGrandSlamPlist(data)
	if err != nil {
		return nil, errors.New("invalid SAP response plist")
	}
	value, ok := values[key].([]byte)
	if !ok || len(value) == 0 || len(value) > maxSAPResponse {
		return nil, errors.New("SAP response has no setup data")
	}
	return value, nil
}

// Sign signs the exact encoded request body. The session is serialized because
// Apple's signer maintains state across calls.
func (s *SAPSession) Sign(ctx context.Context, body []byte) ([]byte, error) {
	if err := nativeContextError(ctx); err != nil {
		return nil, err
	}
	if len(body) > maxNativeSigningBody {
		return nil, errors.New("SAP signing body exceeds the size limit")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.native == nil {
		return nil, errors.New("SAP signing session is closed")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	signature, err := s.native.sign(body)
	if contextErr := ctx.Err(); contextErr != nil {
		return nil, contextErr
	}
	if err != nil {
		return nil, err
	}
	if len(signature) == 0 || len(signature) > maxNativeSignatureBytes {
		return nil, errors.New("native SAP returned an invalid signature")
	}
	return signature, nil
}

// Close releases the native session. It is safe to call more than once.
func (s *SAPSession) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.native != nil {
		s.native.close()
		s.native = nil
	}
}
